from socket import *
import json
import argparse
import struct
import hashlib
import os
from tqdm import tqdm
import threading
import time

MAX_PACKET_SIZE = 20480

OP_SAVE = "SAVE"
OP_UPLOAD = "UPLOAD"
OP_DELETE = "DELETE"
TYPE_FILE = "FILE"
FIELD_TOKEN = "token"
FIELD_KEY = "key"
FIELD_SIZE = "size"
FIELD_BLOCK_INDEX = "block_index"
FIELD_TOTAL_BLOCK = "total_block"
FIELD_BLOCK_SIZE = "block_size"
FIELD_MD5 = "md5"
FIELD_USERNAME = "username"
FIELD_STATUS = "status"
FIELD_STATUS_MSG = "status_msg"
DIR_REQUEST = 'REQUEST'
MAX_THREAD = 4

# User database path constant
USER_DB_PATH = os.path.abspath(os.path.expanduser("./users.json"))


def make_packet(json_data, bin_data=None):
    """Construct a data packet"""
    j = json.dumps(dict(json_data), ensure_ascii=False)
    j_len = len(j)
    if bin_data is None:
        return struct.pack('!II', j_len, 0) + j.encode()
    else:
        return struct.pack('!II', j_len, len(bin_data)) + j.encode() + bin_data


def receive_packet(client_socket):
    """Receive and parse data packets"""
    response_header = b""
    while len(response_header) < 8:
        chunk = client_socket.recv(8 - len(response_header))
        if not chunk:
            print("Connection closed while receiving header")
            return None, None, None
        response_header += chunk

    j_len, b_len = struct.unpack("!II", response_header)

    j_data = b""
    while len(j_data) < j_len:
        chunk = client_socket.recv(j_len - len(j_data))
        if not chunk:
            print("Connection closed while receiving JSON data")
            return None, None, None
        j_data += chunk

    try:
        decode_data = json.loads(j_data.decode())
    except Exception as e:
        print(f"Failed to decode JSON data: {str(e)}")
        return None, None, None

    b_data = b""
    while len(b_data) < b_len:
        chunk = client_socket.recv(b_len - len(b_data))
        if not chunk:
            print("Connection closed while receiving binary data")
            return None, None, None
        b_data += chunk

    return decode_data, b_data, (j_len, b_len)


def _argparse():
    parser = argparse.ArgumentParser("STEP client")
    parser.add_argument('--port', default=1379, type=int, required=False, help='default port number')
    parser.add_argument('--server_ip', dest='ip', required=False, help='server ip')
    parser.add_argument('--out', default='login_info.txt', required=False,
                        help='path to write the upload stub file (e.g., ./login_info.txt)')
    parser.add_argument('--f', dest='upload', default='file_info.txt', help='path to the file to upload')
    parser.add_argument('--id', dest='user_id', required=False, help='user id for non-interactive login')
    parser.add_argument('--measure', action='store_true', help='measure upload time and per-block latency')
    return parser.parse_args()


def create_upload_stub_file(out_path, token, username, server_ip, server_port):
    """Generate user information and save it to login_info"""
    lines = [
        "username: " + username,
        "token: " + token,
        "server ip: " + str(server_ip) + " server port: " + str(server_port)
    ]
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))

def md5_username(name: str):
    return hashlib.md5(name.encode('utf-8')).hexdigest()

def load_user_db():
    if not os.path.exists(USER_DB_PATH):
        return {}
    try:
        with open(USER_DB_PATH, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_user_db(data: dict):
    folder = os.path.dirname(USER_DB_PATH)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)
    with open(USER_DB_PATH, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def is_valid_username(name: str):
    """Verify the validity of the username"""
    if not name or len(name) > 64:
        return False
    for ch in name:
        if ch.isspace():
            return False
    return True


def create_account_interactive():
    """Interactive creation/reconstruction of accounts"""
    db = load_user_db()
    while True:
        username = input("Create username (no whitespace): ").strip()
        if not is_valid_username(username):
            print("Invalid username, retry.")
            continue
        if username in db:
            ans = input(f'Username "{username}" exists. Overwrite? (y/n): ').strip().lower()
            if ans not in ('y', 'yes'):
                continue
        pw1 = input("Password: ")
        pw2 = input("Confirm password: ")
        if pw1 != pw2:
            print("Passwords do not match. Retry.")
            continue
        if len(pw1) == 0:
            print("Password cannot be empty.")
            continue
        db[username] = {"password": pw1}
        save_user_db(db)
        print(f'Account "{username}" created/updated.')
        return username


def local_login_or_create():
    """return (username, plain_password)；
       return (None, None) if fail
    """
    db = load_user_db()

    # Create local account if user do not have
    if not db:
        print("No local accounts found. Creating one...")
        username = create_account_interactive()
        db = load_user_db()
        return username, db[username]["password"]

    choice = input("Do you have an account? (y/n): ").strip().lower()

    if choice in ('n', 'no'):
        # Create new account
        username = create_account_interactive()
        db = load_user_db()
        return username, db[username]["password"]

    if choice in ('y', 'yes'):
        # Already have an account, doing login verification.
        username = input("Please enter username: ").strip()
        if username not in db:
            print("Username not found.")
            return None, None
        pw = input("Please enter password: ")
        if pw != db[username].get("password"):
            print("Password incorrect.")
            return None, None
        print("Local authentication success.")
        return username, pw

    print("Invalid selection.")
    return None, None


def login(server_ip, server_port, out_path, user_id = None):
    """Log in to the system,
       integrate local account management and server verification
    """
    if user_id:
        username = user_id.strip()
        if not username:
            print('No id is provided')
            return None
        user_password = None # Don't use interactive login
    else:
        username, user_password = local_login_or_create()
        if not username:
            print("Local authentication failed or canceled.")
            return None

    validate_token = md5_username(username)

    # Build login request
    login_request = {
        'type': 'AUTH',
        'operation': 'LOGIN',
        'direction': 'REQUEST',
        'username': username,
        'password': validate_token
    }

    # Connect server
    client_socket = socket(AF_INET, SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        print(f'Connect to server {server_ip}')
    except Exception as e:
        print(f"Connection to server failed: {e}")
        client_socket.close()
        return (None, username, user_password)

    try:
        packet = make_packet(login_request)
        client_socket.send(packet)
        print('Requesting to log in...')

        response_data, _, _ = receive_packet(client_socket)
        if response_data is None:
            print('Can not get response from server')
            client_socket.close()
            return (None, username, user_password)

        print(f'Successfully get response from server:{response_data}')

        if response_data.get('status') == 200:
            print('Successfully login!')
            token = response_data.get('token')
            client_socket.close()

            # Save login information
            create_upload_stub_file(out_path, token, username, server_ip, server_port)
            return token, username, user_password
        else:
            error_status = response_data.get('status')
            print(f'Login failed with status: {error_status}')
            client_socket.close()
            return None, username, user_password
    except Exception as e:
        print(f'Error during login: {e}')
        client_socket.close()
        return None, username, user_password


def calculate_file_md5(file_path):
    """Calculate the MD5 of the local file"""
    md5_obj = hashlib.md5()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            md5_obj.update(chunk)
    return md5_obj.hexdigest()


def get_upload_plan(client_socket, token, username, file_path):
    """Obtain the upload plan"""
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print(f"File not found or invalid: {file_path}")
        return None
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)

    save_request = {
        "type": TYPE_FILE,
        "operation": OP_SAVE,
        "direction": "REQUEST",
        "status": 200,
        FIELD_TOKEN: token,
        FIELD_USERNAME: username,
        FIELD_SIZE: file_size,
        FIELD_KEY: file_name
    }

    try:
        client_socket.send(make_packet(save_request))
        print(f"Requesting upload plan for file: {os.path.basename(file_path)} (size: {file_size} bytes)")

        response_data, _, _ = receive_packet(client_socket)
        if response_data is None:
            print("No valid response from server for upload plan")
            return None

        if response_data.get("status") == 200:
            required_fields = [FIELD_KEY, FIELD_BLOCK_SIZE, FIELD_TOTAL_BLOCK]
            if all(field in response_data for field in required_fields):
                upload_plan = {
                    FIELD_KEY: response_data[FIELD_KEY],
                    FIELD_BLOCK_SIZE: response_data[FIELD_BLOCK_SIZE],
                    FIELD_TOTAL_BLOCK: response_data[FIELD_TOTAL_BLOCK]
                }
                print(f"Upload plan obtained:")
                print(f"Key: {upload_plan[FIELD_KEY]}")
                print(f"Block size: {upload_plan[FIELD_BLOCK_SIZE]} bytes")
                print(f"Total blocks: {upload_plan[FIELD_TOTAL_BLOCK]}")
                return upload_plan
            else:
                print(f"Upload plan missing required fields: {required_fields}")
                return None
        else:
            error_code = response_data.get("status", "Unknown")
            error_msg = response_data.get("status_msg", "No error message")
            print(f"Failed to get upload plan (status: {error_code}): {error_msg}")
            return None
    except Exception as e:
        print(f"Error getting upload plan: {str(e)}")
        return None


def upload_file_blocks(client_socket, token, username, file_path, upload_plan, measure=False):
    """Upload files in blocks according to the upload plan (single thread), and record the time statistics when measure=True"""
    file_key = upload_plan[FIELD_KEY]
    block_size = upload_plan[FIELD_BLOCK_SIZE]
    total_blocks = upload_plan[FIELD_TOTAL_BLOCK]
    local_md5 = calculate_file_md5(file_path)
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    progress_bar = tqdm(
        total=total_blocks,
        desc=f"Uploading {file_name} (key: {file_key})",
        unit="block",
        ncols=100
    )

    block_latencies = []  # Block delay（s）
    start_time = time.time() if measure else None

    try:
        with open(file_path, 'rb') as file:
            for block_index in range(total_blocks):
                block_data = file.read(block_size)

                upload_request = {
                    "type": TYPE_FILE,
                    "operation": OP_UPLOAD,
                    "direction": "REQUEST",
                    "status": 200,
                    FIELD_TOKEN: token,
                    FIELD_USERNAME: username,
                    FIELD_KEY: file_name,
                    FIELD_BLOCK_INDEX: block_index
                }

                if measure:
                    t0 = time.time()

                client_socket.send(make_packet(upload_request, block_data))

                response_data, _, _ = receive_packet(client_socket)
                if response_data is None:
                    raise Exception(f"Block {block_index} upload failed (no response)")

                if response_data.get("status") != 200:
                    error_msg = response_data.get("status_msg", "No error message")
                    raise Exception(f"Block {block_index} failed: {error_msg}")

                if measure:
                    t1 = time.time()
                    block_latencies.append(t1 - t0)

                progress_bar.update(1)

        # Statistics and Verification
        if FIELD_MD5 in response_data:
            server_md5 = response_data[FIELD_MD5]
            if server_md5 == local_md5:
                if measure:
                    end_time = time.time()
                    elapsed = end_time - start_time
                    throughput = (file_size / 1024 / 1024) / elapsed if elapsed > 0 else 0.0
                    avg_block = sum(block_latencies) / len(block_latencies) if block_latencies else 0.0
                    block_latencies_sorted = sorted(block_latencies)
                    median = block_latencies_sorted[len(block_latencies_sorted)//2] if block_latencies_sorted else 0.0
                    print("\n=== Upload stats ===")
                    print(f"Total time: {elapsed:.3f} s")
                    print(f"Throughput: {throughput:.3f} MB/s")
                    print(f"Avg block latency: {avg_block:.4f} s  Median: {median:.4f} s  Min: {min(block_latencies):.4f} s  Max: {max(block_latencies):.4f} s")
                print(f'\n File upload completed successfully! MD5 check passed.')
                print(f'   Local MD5: {local_md5}')
                print(f'   Server MD5: {server_md5}')
                return True
            else:
                raise Exception(f"MD5 check failed! Local: {local_md5} | Server: {server_md5}")
        else:
            raise Exception(f"Server did not return MD5 (cannot verify integrity)")

    except Exception as e:
        print(f"\n File upload failed: {str(e)}")
        return False
    finally:
        progress_bar.close()


MAX_RETRIES = 3  #The maximum number of retries per block

def upload_worker(
    worker_id,
    server_address,
    token,
    username,
    file_key,
    file_path,
    block_size,
    total_blocks,
    shared_state
):
    """
    Each thread: upload blocks with retry mechanism and record per-block latency (only when measure enabled)
    """
    next_block_lock = shared_state["next_block_lock"]
    errors = shared_state["errors"]
    progress_bar = shared_state["progress_bar"]
    md5_lock = shared_state["md5_lock"]
    md5_result = shared_state["md5_result"]
    block_times_lock = shared_state["block_times_lock"]
    block_times = shared_state["block_times"]
    measure = shared_state.get("measure", False)
    file_name = os.path.basename(file_path)

    try:
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect(server_address)

        with open(file_path, 'rb') as f:
            while True:
                with next_block_lock:
                    if shared_state["next_block_index"] >= total_blocks:
                        break
                    block_index = shared_state["next_block_index"]
                    shared_state["next_block_index"] += 1

                offset = block_index * block_size
                f.seek(offset)
                block_data = f.read(block_size)
                if not block_data:
                    continue

                attempt = 0
                while attempt < MAX_RETRIES:
                    attempt += 1
                    upload_request = {
                        "type": TYPE_FILE,
                        "operation": OP_UPLOAD,
                        "direction": "REQUEST",
                        "status": 200,
                        FIELD_TOKEN: token,
                        FIELD_USERNAME: username,
                        FIELD_KEY: file_name,
                        FIELD_BLOCK_INDEX: block_index,
                    }

                    t0 = time.time()
                    sock.sendall(make_packet(upload_request, block_data))
                    response_data, _, _ = receive_packet(sock)
                    t1 = time.time()
                    latency = t1 - t0

                    if response_data is None:
                        errors.append(f"[Thread {worker_id}] Block {block_index} no response, attempt {attempt}")
                        time.sleep(0.5)
                        continue

                    if response_data.get("status") != 200:
                        err_msg = response_data.get("status_msg", "No error message")
                        errors.append(f"[Thread {worker_id}] Block {block_index} failed: {err_msg}, attempt {attempt}")
                        time.sleep(0.5)
                        continue

                    if measure:
                        with block_times_lock:
                            block_times.append(latency)

                    progress_bar.update(1)

                    if FIELD_MD5 in response_data:
                        with md5_lock:
                            md5_result["server_md5"] = response_data[FIELD_MD5]
                    break
                else:
                    errors.append(f"[Thread {worker_id}] Block {block_index} failed after {MAX_RETRIES} attempts")

        sock.close()

    except Exception as e:
        with next_block_lock:
            errors.append(f"[Thread {worker_id}] Exception: {e}")


def upload_file_multi(client_socket, token, username, file_path, upload_plan, num_threads=MAX_THREAD, measure=False):
    file_key = upload_plan[FIELD_KEY]
    block_size = upload_plan[FIELD_BLOCK_SIZE]
    total_blocks = upload_plan[FIELD_TOTAL_BLOCK]
    local_md5 = calculate_file_md5(file_path)
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    progress_bar = tqdm(
        total=total_blocks,
        desc=f"Uploading {file_name} (key: {file_key})",
        unit="block",
        ncols=100
    )
    server_address = client_socket.getpeername()

    shared_state = {
        "next_block_index": 0,
        "next_block_lock": threading.Lock(),
        "errors": [],
        "progress_bar": progress_bar,
        "md5_lock": threading.Lock(),
        "md5_result": {"server_md5": None},
        "block_times": [],               # only filled if measure True
        "block_times_lock": threading.Lock(),
        "retry_counts": {},
        "measure": measure
    }

    start_time = time.time() if measure else None
    threads = []
    for i in range(num_threads):
        thread = threading.Thread(
            target=upload_worker,
            args=(i,
                  server_address,
                  token,
                  username,
                  file_key,
                  file_path,
                  block_size,
                  total_blocks,
                  shared_state
                  )
        )
        thread.daemon = True
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end_time = time.time() if measure else None
    elapsed = (end_time - start_time) if (measure and start_time is not None) else None
    progress_bar.close()

    if shared_state['errors']:
        print("\nErrors:")
        for error in shared_state['errors']:
            print(f"{error}")
        return False

    server_md5 = shared_state["md5_result"]["server_md5"]
    block_times = shared_state["block_times"]

    if measure and block_times:
        avg_block = sum(block_times)/len(block_times)
        block_times_sorted = sorted(block_times)
        median = block_times_sorted[len(block_times_sorted)//2]
        throughput = (file_size / 1024 / 1024) / elapsed if elapsed and elapsed > 0 else 0.0
        print("\n=== Upload stats (multi-thread) ===")
        print(f"Total time: {elapsed:.3f} s")
        print(f"Throughput: {throughput:.3f} MB/s")
        print(f"Avg block latency: {avg_block:.4f} s  Median: {median:.4f} s  Min: {min(block_times):.4f} s  Max: {max(block_times):.4f} s")
    elif measure:
        if elapsed:
            throughput = (file_size / 1024 / 1024) / elapsed if elapsed > 0 else 0.0
            print("\n=== Upload stats (multi-thread) ===")
            print(f"Total time: {elapsed:.3f} s")
            print(f"Throughput: {throughput:.3f} MB/s")

    if server_md5 is not None:
        if server_md5 == local_md5:
            print("\nFile upload completed successfully")
            print(f"Local MD5 : {local_md5}")
            print(f"Server MD5: {server_md5}")
            return True
        else:
            print("\nMD5 mismatch!")
            print(f"Local MD5 : {local_md5}")
            print(f"Server MD5: {server_md5}")
            return False
    else:
        return True


def upload_file_main(client_socket, token, username, file_path, measure=False):
    """Main entry point for file uploads"""
    upload_plan = get_upload_plan(client_socket, token, username, file_path)
    if not upload_plan:
        print("Abort upload: failed to get upload plan")
        return False

    total_blocks = upload_plan[FIELD_TOTAL_BLOCK]
    file_size = os.path.getsize(file_path)

    big_file = 1024 * 1024 * 1024 # file size greater than 1024MB is considered as big file
    blocks = 8 # blocks > 8 is considered to use multithread

    if file_size >= big_file and total_blocks >= blocks:
        return upload_file_multi(client_socket, token, username, file_path, upload_plan, num_threads=MAX_THREAD, measure=measure)
    else:
        return upload_file_blocks(client_socket, token, username, file_path, upload_plan, measure=measure)


# Interactive file upload
def ask_upload_path(default_path: str):
    """
    Manually enter the file name to be uploaded：
    Enter non-empty path: Use the path input by the user
    Press Enter：user default_path
    """
    default_path = os.path.abspath(os.path.expanduser(default_path))

    while True:
        user_input = input(f'Please enter the file path(Press Enter if you want use default path：{default_path}):\n').strip()

        if user_input:
            path = os.path.abspath(os.path.expanduser(user_input))
        else:
            path = default_path

        if os.path.isfile(path):
            print(f'Upload file：{path}')
            return path

        print(f'File not found: {path}')

def delete_uploaded_file(server_ip, server_port, token, username, file_key):
    """
    Delete the given file by user
    :param file_key: The name of the file to be deleted
    :return:
    """
    client_socket = socket(AF_INET, SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        print(f"Connected to server {server_ip}:{server_port} for delete operation")

        delete_request = {
            'type': TYPE_FILE,
            'operation': OP_DELETE,
            'direction': DIR_REQUEST,
            FIELD_STATUS: 200,
            FIELD_TOKEN: token,
            FIELD_USERNAME: username,
            FIELD_KEY: file_key
        }

        client_socket.sendall(make_packet(delete_request))
        print(f"Requesting to delete file with key: {file_key}")

        response_data, _, _ = receive_packet(client_socket)
        if response_data is None:
            print("No valid response from server for delete operation")
            return False

        status = response_data.get(FIELD_STATUS)
        status_msg = response_data.get(FIELD_STATUS_MSG, "")

        if status == 200:
            print(f"Delete success: file_key={file_key}")
            return True
        else:
            print(f"Delete failed (status={status}): {status_msg}")
            return False

    except Exception as e:
        print(f"Error during delete operation: {e}")
        return False
    finally:
        client_socket.close()
        print("Disconnected from server")


def main():
    args = _argparse()
    server_ip = args.ip or '127.0.0.1'
    server_port = args.port
    out_path = os.path.abspath(os.path.expanduser(args.out))
    upload_path = args.upload
    user_id = args.user_id


    result = login(server_ip, server_port, out_path, user_id)

    if result is not None:
        token, username, _ = result
        if token:
            print(f'Token: {token}')

            # Re-establish the TCP connection
            client_socket = socket(AF_INET, SOCK_STREAM)
            try:
                client_socket.connect((server_ip, server_port))
                print(f'Reconnected to server for upload')

                if user_id:
                    file_to_upload = os.path.abspath(os.path.expanduser(upload_path))
                    if not os.path.isfile(file_to_upload):
                        print(f'File not found: {file_to_upload}')
                        return
                else:
                    default_file = upload_path
                    file_to_upload = ask_upload_path(default_file)

                # Call the main function for uploading
                upload_success = upload_file_main(client_socket, token, username, file_to_upload, measure=args.measure)
                if upload_success:
                    print("File upload task finished!")
                else:
                    print("File upload task failed!")
            finally:
                client_socket.close()
                print("Disconnected from server")
        else:
            print("Local login successful, but server authentication failed")
    else:
        print('Login failed')

    # Option: delete file
    # file_key_to_delete = "picture.png"
    # delete_uploaded_file(server_ip, server_port, token, username, file_key_to_delete)


if __name__ == "__main__":
    main()