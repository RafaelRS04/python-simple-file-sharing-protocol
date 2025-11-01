from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import netutils
import config
import protocol
import sys

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('usage: server_ipv4 server_port filename')

    conf = config.get_client_conf()

    server_ip = netutils.get_numeric_ipv4(sys.argv[1])
    server_port = netutils.get_numeric_port(sys.argv[2])

    sock = netutils.create_socket((conf['ipv4_address'], conf['port_address']))
    sock.connect((server_ip, server_port))

    receiver = protocol.Transmitter(0xBEBACAFEBEBACAFEBEBACAFEBEBACAFE)
    status_code = receiver.send_file(sock, sys.argv[3])
    
    if status_code == protocol.STATUS_SUCCESS:
        print('Successful upload')
    elif status_code == protocol.STATUS_ERROR:
        print('Error on upload')