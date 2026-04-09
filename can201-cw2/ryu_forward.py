from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types


class RyuForward(app_manager.RyuApp):
    # Use OPenFlow 1.3
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Initialize MAC-to-port mapping table
    def __init__(self, *args, **kwargs):
        super(RyuForward, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # Handle switch feature event by installing table-miss flow entry
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Construct and send flow mod message to datapath (switch)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, timeout=False):
        # print(f'data path={datapath}, priority={priority}, match={match}, action={actions}, buffer_id={buffer_id}')
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Install a flow to the flow table
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=inst, idle_timeout=5 if timeout else 0)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                    idle_timeout=5 if timeout else 0)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg

        datapath = msg.datapath
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # Ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        self.logger.info(f'packet in: dpid={dpid}  src={src}  dst={dst}  in_port={in_port}')

        # Learn the source MAC address to the port it came from
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            # Send packet out the known port if destination MAC is known
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Flood packet out all ports if destination unknown
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            # Add flow entry to switch to avoid future packet-in events for this flow
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id, True)
                return
            else:
                self.add_flow(datapath, 1, match, actions, None, True)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # Include packet data in packet-out message if no buffer ID
            data = msg.data

        # Send packet-out message to forward the packet accordingly
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                  data=data)
        self.logger.info(f'packet out: dpid={dpid}  action={actions}  buffer_id={msg.buffer_id} in_port={in_port}')

        datapath.send_msg(out)
