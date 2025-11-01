from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import socket

DH_PRIME = int(
    '303924648605087443190644558570'
    '504392733172715178873590971773'
    '731728393720706025766237125383'
    '171102913738443406893788274018'
    '411161679478885352257588080114'
    '383908225010175450016186122826'
    '649331166301291232488460976679'
    '093470710059786827893465870502'
    '710994231289859318742620181718'
    '970379922008912637123679469717'
    '599094282534249750738686785153'
    '966530882857077585552509690472'
    '125721830315907486169025020822'
    '441456157542335303758320738847'
    '291583802553084101705739218300'
    '958697745200962035906356556075'
    '324571786177845080989457440994'
    '536431600645589813513529199863'
    '949325127457431221246973503882'
    '395648283909057418551162361746'
    '28886807231292669'
)

DH_GENERATOR = 2
DH_KEY_BYTECOUNT = 256
DH_KEY_BITCOUNT = DH_KEY_BYTECOUNT * 8

def is_valid_ipv4(hostname):
    is_valid = True

    try:
        socket.getaddrinfo(hostname, None, family=socket.AF_INET)
    except socket.gaierror:
        is_valid = False

    return is_valid

def is_valid_port(port):
    if type(port) is str:
        if port.isascii() and port.isdigit():
            port = int(port)

    if type(port) is int:
        return 0 <= port <= 65535
    
    is_valid = True
    
    try:
        socket.getaddrinfo(None, port, family=socket.AF_INET)
    except socket.gaierror:
        is_valid = False

    return is_valid

def get_numeric_ipv4(hostname):
    if not is_valid_ipv4(hostname):
        raise ValueError('invalid socket ipv4 hostname')

    return socket.gethostbyname(hostname)

def get_numeric_port(port):
    if not is_valid_port(port):
        raise ValueError('invalid socket port')

    if type(port) is int:
        return port
    
    if port.isascii() and port.isdigit():
        return int(port)
    
    return socket.getservbyname(port)

def create_socket(address=None, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)

    if address is not None:
        sock.bind(address)

    return sock

def recv_all(sock, nbytes):
    data = bytearray()

    while len(data) < nbytes:
        received = sock.recv(nbytes - len(data))

        if not received:
            raise socket.error('socket connection broken')

        data.extend(received)

    return bytes(data)

def receive_encrypted(sock, nbytes, aes_key):
    nonce = recv_all(sock, 12)
    data = recv_all(sock, nbytes)
    tag = recv_all(sock, 16)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(data, tag)

    return plaintext

def send_encrypted(sock, data, aes_key):
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)

    ciphertext, tag = cipher.encrypt_and_digest(data)
    sock.sendall(nonce)
    sock.sendall(ciphertext)
    sock.sendall(tag)

def dh_server(sock, private_int):
    server_pubkey = dh_key(DH_GENERATOR, private_int, DH_PRIME) 

    # Send server public key
    sock.sendall(server_pubkey)

    # Receive client public key
    buffer = recv_all(sock, DH_KEY_BYTECOUNT)
    client_pubkey = int.from_bytes(buffer)

    session_key = dh_key(client_pubkey, private_int, DH_PRIME)

    return session_key

def dh_client(sock, private_int):
    # Receive server public key
    buffer = recv_all(sock, DH_KEY_BYTECOUNT)
    server_pubkey = int.from_bytes(buffer)

    client_pubkey = dh_key(DH_GENERATOR, private_int, DH_PRIME)

    # Send client public key
    sock.sendall(client_pubkey)

    session_key = dh_key(server_pubkey, private_int, DH_PRIME)

    return session_key

def dh_key(base, exp, prime):
    key = pow(base, exp, prime)

    return key.to_bytes(DH_KEY_BYTECOUNT)