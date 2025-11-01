from Crypto.Random import random
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

import pathvalidate
import mimetypes
import whitelist
import netutils
import pathlib
import struct
import size
import os

_HEADER_FORMAT = '!16sL100s'
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
MAX_FILE_SIZE = 4 * size.GiB

# ===================================== PROTOCOL FORMAT =====================================
# 
# - Request
# |-----------------------------HEADER------------------------------|--PAYLOAD--|
# | HEXPASS (16 bytes) | FILE SIZE (4 bytes) | FILENAME (100 bytes) |   FILE    |
# |-----------------------------------------------------------------|-----------|
#
# - Response
# |--------PAYLOAD--------|
# | STATUS CODE (4 bytes) |
# |-----------------------|
#
# - Diffie-Helman key exchange and AES GCM encryption is used
#
# ===========================================================================================

STATUS_SUCCESS = 0
STATUS_ERROR = 1

# TODO: Map edge cases
# TODO: Improve request processing
class Receiver:
    def __init__(self, hexpass, conf, trusted_mimetypes=None):
        self.__hexpass = hexpass
        self.__conf = conf
        self.__trusted_mimetypes = trusted_mimetypes

    def receive_file(self, client):
        # Diffie-Helman key exchange and key derivation
        private_int = random.getrandbits(netutils.DH_KEY_BITCOUNT)
        session_key = netutils.dh_server(client, private_int)
        aes_key = HKDF(session_key, 16, b'RAFAEL', SHA256, 1)

        # TODO: LOG
        # Temporary prints about encryption
        pubkey = netutils.dh_key(netutils.DH_GENERATOR, private_int, netutils.DH_PRIME) 
        print('Server Private Integer:', private_int)
        print('Server Public Key:', int.from_bytes(pubkey))
        print('Session Key:', int.from_bytes(session_key))
        print('AES Key (Derived using HKDF):', int.from_bytes(aes_key))

        data = netutils.receive_encrypted(client, _HEADER_SIZE, aes_key)
        hexpass, file_size, filename = struct.unpack(_HEADER_FORMAT, data) 

        hexpass = int.from_bytes(hexpass)
        filename = filename.decode('utf-8').rstrip('\0')

        try:
            if hexpass != self.__hexpass:
                raise ValueError('invalid hexpass received')
            
            if file_size > self.__conf['max_file_size']:
                raise ValueError('invalid file size')

            pathvalidate.validate_filename(filename)
        except (pathvalidate.ValidationError, ValueError) as e:
            print(f'ERROR: {e}')
            netutils.send_encrypted(client, STATUS_ERROR.to_bytes(4), aes_key)
            return

        content = netutils.receive_encrypted(client, file_size, aes_key)

        if not os.path.exists(self.__conf['files_path']):
            os.mkdir(self.__conf['files_path'])

        path = pathlib.Path(self.__conf['files_path']).joinpath(filename)

        with open(path, 'wb') as file:
            file.write(content)

        if self.__trusted_mimetypes is not None:
            mimetype, _ = mimetypes.guess_type(path)

            if mimetype is None or not whitelist.is_trusted_mimetype(mimetype, self.__trusted_mimetypes):
                print(f'ERROR: {filename} have an untrusted mimetype \'{mimetype}\'')
                netutils.send_encrypted(client, STATUS_ERROR.to_bytes(4), aes_key)        
                os.remove(path)
                return
        
        netutils.send_encrypted(client, STATUS_SUCCESS.to_bytes(4), aes_key)        

# TODO: Map edge cases
class Transmitter:
    def __init__(self, hexpass):
        self.__hexpass = hexpass

    def send_file(self, sock, filename:str):
        # TODO: Chunked loading (Low RAM usage)
        with open(filename, 'rb') as file:
            content = file.read()

        # Diffie-Helman key exchange and key derivation
        private_int = random.getrandbits(netutils.DH_KEY_BITCOUNT)
        session_key = netutils.dh_client(sock, private_int)
        aes_key = HKDF(session_key, 16, b'RAFAEL', SHA256, 1)

        # TODO: LOG
        # Temporary prints about encryption
        pubkey = netutils.dh_key(netutils.DH_GENERATOR, private_int, netutils.DH_PRIME) 
        print('Client Private Integer:', private_int)
        print('Client Public Key:', int.from_bytes(pubkey))
        print('Session Key:', int.from_bytes(session_key))
        print('AES Key (Derived using HKDF):', int.from_bytes(aes_key))

        # Header fields
        hexpass = self.__hexpass.to_bytes(16)
        filename = filename.encode('utf-8')
        file_size = len(content)

        header = struct.pack(
            _HEADER_FORMAT,
            hexpass,
            file_size,
            filename
        )

        netutils.send_encrypted(sock, header, aes_key)

        try:
            netutils.send_encrypted(sock, content, aes_key)
        except TimeoutError:
            pass

        status_code = netutils.receive_encrypted(sock, 4, aes_key)
        status_code = int.from_bytes(status_code)

        return status_code

