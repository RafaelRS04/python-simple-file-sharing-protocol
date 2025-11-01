from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
import whitelist
import netutils
import config
import sigmanager
import protocol

def get_trusted_hosts():
    try:
        trusted_hosts = whitelist.load_trusted_hosts()
    except FileNotFoundError:
        # TODO: LOG
        raise SystemExit('Not Found')
    except ValueError:
        # TODO: LOG
        raise SystemExit('Invalid File')

    if len(trusted_hosts) < 1:
        # TODO: LOG
        raise SystemExit('Too few hosts')
    
    return trusted_hosts

def get_trusted_mimetypes():
    try:
        trusted_mimetypes = whitelist.load_trusted_mimetypes()
    except FileNotFoundError:
        # TODO: LOG
        raise SystemExit('Not Found')
    except ValueError:
        # TODO: LOG
        raise SystemExit('Invalid File')

    if len(trusted_mimetypes) < 1:
        # TODO: LOG
        raise SystemExit('Too few MIME types')
    
    return trusted_mimetypes

if __name__ == '__main__':
    print('Press CTRL-C to exit')
    termination = sigmanager.Termination(['SIGINT', 'SIGBREAK', 'SIGTERM'])

    conf = config.get_server_conf()
    trusted_mimetypes = None

    if conf['check_mimetypes']:
        trusted_mimetypes = get_trusted_mimetypes()

    sock = netutils.create_socket((conf['ipv4_address'], conf['port_address']))
    sock.listen()

    receiver = protocol.Receiver(0xBEBACAFEBEBACAFEBEBACAFEBEBACAFE, conf, trusted_mimetypes)

    while not termination.requested():
        try:
            client, _ = sock.accept()
            receiver.receive_file(client)
        except TimeoutError:
            pass

    print('Server exited...')