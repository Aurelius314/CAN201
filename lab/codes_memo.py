# Lab 1
# Linux for networking, VM, Mininet (a virtual testbed used for testing network tools and protocols, easy for topology)

# Lab 2
# Wireshark (Packet Sniffer, protocol analyzer), tcpdump (capture packet as .pcap)

# Lab 3 python basis
# Dict
tel = {'jack': 4098, 'sape': 4139}
tel['guido'] = 4127
# 通过网络发送 dict，需要先转换为字符串（通常为 JSON），再转为二进制传输 (string -> byte)
# struct module used for binary data stored in files or from network connection
# int, float -> using struct
import struct

# 假设我们有一个整数和一个浮点数
num = 42
pi = 3.14

# 打包：将整数和浮点数分别按照 'i'（int）和 'f'（float）格式打包成二进制数据
binary_data = struct.pack('if', num, pi)
print(binary_data)  # 输出类似：b'*\x00\x00\x00\xc3\xf5H@'

# 解包：从二进制数据还原出原始的整数和浮点数
unpacked_data = struct.unpack('if', binary_data)
print(unpacked_data)  # 输出：(42, 3.140000104904175)

# ========== Lab 4 ==========
# uncertain number of arguments (*args return tuple / *kwargs return dict)
def func(a, *args):
    print('a is', a)
    print('Others are', args)

func(10, 20, 30) # a is 10, Others are (20, 30)

def func2(**kwargs):
    print(kwargs)

func2(x=1, y=2) # {'x': 1, 'y': 2}


# Small anonymous (map, filter) func define: lambada expression 
f = lambda a, b: a + b
result = f(2, 3) # 输出: 5

# Recommended python programming style
import argparse
def _argparse():
    parser = argparse.ArgumentParser(description="This is description!")
    parser.add_argument('--input', action='store', required=True,
      dest='path', help='The path of input file')
    parser.add_argument('--server', action='store', required=True,
      dest='server', help='The hostname of server')
    parser.add_argument('--port', action='store', required=True,
      dest='port', help='The port of server')
    return parser.parse_args()

def main():
    parser = _argparse()
    print(parser)
    print('Input file:', parser.path)
    print('Server:', parser.server)
    print('Port:', parser.port)

if __name__ == '__main__':
    main()

# ================= Lab 5 =================
# Socket(套接字) programming(IP address a. 127.0.0.1 -> localhost b. 192.168.xxx.xxx -> local network IP c. Internet IP address, Port number: 0~65535)

# UDP Socket programming
# 1) server side
from socket import *
server_port = 12000
server_socket = socket(AF_INET, SOCK_DGRAM)# 创建UDP套接字
server_socket.bind(('', server_port))      # 绑定端口
print('The server is ready to receive.')
while True:
    message, client_address = server_socket.recvfrom(20480)     # 接收客户端消息及地址
    print(message, client_address)
    modified_message = message.decode().upper()        # 将消息内容转为大写
    server_socket.sendto(modified_message.encode(), client_address)  # 回复客户端

# client side
from socket import *
server_hostname = '127.0.0.1' # 服务器IP（本地测试用）
server_port = 12000
client_socket = socket(AF_INET, SOCK_DGRAM)# 创建UDP套接字
message = input('Input a sentence:')       # 用户输入消息
client_socket.sendto(message.encode(), (server_hostname, server_port))    # 发送消息
modified_message, server_address = client_socket.recvfrom(20480) # 收到服务器回复
print(modified_message.decode(), server_address)
client_socket.close()

# TCP Socket programming
# server side
from socket import *

server_port = 12000
server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind(('', server_port))
server_socket.listen(10) # 最多10个连接

print('The server is ready to receive')
while True:
    connection_socket, addr = server_socket.accept()
    sentence = connection_socket.recv(20480).decode()
    capitalized_sentence = sentence.upper()
    connection_socket.send(capitalized_sentence.encode())
    connection_socket.close()

# client side
from socket import *

server_hostname = '127.0.0.1'
server_port = 12000
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_hostname, server_port))

sentence = input('Input a sentence:')
client_socket.send(sentence.encode())
modified_message = client_socket.recv(20480)
print('Received from server:', modified_message.decode())
client_socket.close()

# ================= Lab 6 =================
# monitor udp/tcp via wireshark
# File operation f = open(file='filename.xxx', mode='r')


# ================= Lab 6 =================
# parallel computing (multiprocessing module, threading module)
# Using threading to support multi-clients for TCP (sample code)
# tcp_client1.py
from socket import *

server_hostname = '127.0.0.1'
server_port = 12002
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_hostname, server_port))

while True:
    sentence = input('Input a sentence')
    if sentence == '':
        break
    client_socket.send(sentence.encode())
    modified_message = client_socket.recv(20480)
    print(modified_message.decode())
client_socket.close()

# tcp_client2.py
from socket import *

server_hostname = '127.0.0.1'
server_port = 12002
client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((server_hostname, server_port))

while True:
    sentence = input('Input a sentence')
    if sentence == '':
        break
    client_socket.send(sentence.encode())
    modified_message = client_socket.recv(20480)
    print(modified_message.decode())
client_socket.close()

# tcp_server_for_multi_clients.py
from socket import *
import threading

server_port = 12002
server_socket = socket(AF_INET, SOCK_STREAM)

server_socket.bind(('', server_port))
server_socket.listen(10)

print('TCP server is listening!')

records = []  # A global list to store all the records!!!

def TCP_processor(connection_socket, address):
    global records
    print(address, ' connected')
    while True:
        try:
            sentence = connection_socket.recv(20480).decode()
            if sentence == '':
                break
            print(address, ' said ', sentence)
            records.append([address, sentence])
            print(records)
            modified_message = sentence.upper()
            connection_socket.send(modified_message.encode())
        except Exception as ex:
            break
    print(address, ' disconnected')
    connection_socket.close()


while True:
    try:
        connection_socket, address = server_socket.accept()
        th = threading.Thread(target=TCP_processor, args=(connection_socket, address))
        th.start()
    except Exception as ex:
        print(ex)

# =============================== Lab 7 ===============================
# Building Network Topology with Mininet
# display the available nodes: mininet> nodes
# display the available links: mininet> net
# specify the device + command
# e.g. turn on a terminal of a node: xterm h1, clean up config: $sudo mn -c, start the network: $sudo mn -x 
# myTopo(): empty network where we add hosts, switches etc.
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Host
from mininet.node import OVSKernelSwitch
from mininet.log import setLogLevel, info

def MyTopo():
    net = Mininet(topo=None, autoSetMacs=True, build = False, ipBase='10.0.1.0/24')

    # Add hosts
    h1 = net.addHost('h1', cls=Host, defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, defaultRoute=None)

    # Switch 2 hosts
    h4 = net.addHost('h4', cls=Host, defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, defaultRoute=None)

    # Add switches
    s1 = net.addSwitch('s1',cls=OVSKernelSwitch, failMode='standalone')
    s2 = net.addSwitch('s2',cls=OVSKernelSwitch, failMode='standalone')

    # Add links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s2)
    net.addLink(h5, s2)
    net.addLink(h6, s2)

    # connect the two switches
    net.addLink(s1, s2)

    # assign ip address to host
    h1.setIP(intf='h1-eth0', ip='10.0.1.2/24')
    h2.setIP(intf='h2-eth0', ip='10.0.1.3/24')
    h3.setIP(intf='h3-eth0', ip='10.0.1.4/24')

    # IPs for s2’s side
    h4.setIP(intf='h4-eth0', ip='10.0.1.5/24')
    h5.setIP(intf='h5-eth0', ip='10.0.1.6/24')
    h6.setIP(intf='h6-eth0', ip='10.0.1.7/24')

    info('*** Starting network\n')
    net.build()
    net.start()

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    MyTopo()

# =================== Lab 8 ====================
# TCP Connection Analysis
# transfer the file to a Web server using the HTTP POST method, handshake, source/destination address
# TCP 层详细信息(packet details pane), window size (发送方允许接收方未被确认的数据最大字节数)
# flow control: window size 越大，网络传输越畅通，拥堵或接收端繁忙时窗口值会变小。