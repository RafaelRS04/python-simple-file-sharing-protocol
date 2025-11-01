import pathlib
import json
import size

_SERVER_CONF_DEFAULT_DICT = {
    'files_path': 'files',
    'max_file_size': 2 * size.KiB,
    'check_trusted_hosts': False,
    'check_mimetypes': True,
    'ipv4_address': 'localhost',
    'port_address': 8086,
    'max_connections': None,
    'show_crypto_info': True
}

_CLIENT_CONF_DEFAULT_DICT = {
    'ipv4_address': 'localhost',
    'port_address': 6502,
    'show_crypto_info': True
}

CONF_PATH = pathlib.Path('config')
SERVER_CONF_NAME = 'server-conf.json'
CLIENT_CONF_NAME = 'client-conf.json'

def get_server_conf():
    try:
        with open(CONF_PATH.joinpath(SERVER_CONF_NAME), 'r', encoding='utf-8') as file:            
            config = json.load(file)

            if not isinstance(config, dict):
                # TODO: LOG
                print(f'WARNING: {SERVER_CONF_NAME} needs to be Object JSON, default options used')
                return _SERVER_CONF_DEFAULT_DICT
            
            if set(config.keys()) != set(_SERVER_CONF_DEFAULT_DICT.keys()):
                # TODO: LOG
                print(f'WARNING: {SERVER_CONF_NAME} invalid properties, default options used')
                return _SERVER_CONF_DEFAULT_DICT

            # TODO: VALIDATION

            return config

    except json.JSONDecodeError:
        # TODO: LOG
        print(f'WARNING: {SERVER_CONF_NAME} decode error, default options used')
        return _SERVER_CONF_DEFAULT_DICT

    except FileNotFoundError:
        # TODO: LOG
        print(f'WARNING: {SERVER_CONF_NAME} not found, default options used')
        return _SERVER_CONF_DEFAULT_DICT

def get_client_conf():
    try:
        with open(CONF_PATH.joinpath(CLIENT_CONF_NAME), 'r', encoding='utf-8') as file:            
            config = json.load(file)

            if not isinstance(config, dict):
                # TODO: LOG
                print(f'WARNING: {CLIENT_CONF_NAME} needs to be Object JSON, default options used')
                return _CLIENT_CONF_DEFAULT_DICT
            
            if set(config.keys()) != set(_CLIENT_CONF_DEFAULT_DICT.keys()):
                # TODO: LOG
                print(f'WARNING: {CLIENT_CONF_NAME} invalid properties, default options used')
                return _CLIENT_CONF_DEFAULT_DICT

            # TODO: VALIDATION

            return config

    except json.JSONDecodeError:
        # TODO: LOG
        print(f'WARNING: {CLIENT_CONF_NAME} decode error, default options used')
        return _CLIENT_CONF_DEFAULT_DICT

    except FileNotFoundError:
        # TODO: LOG
        print(f'WARNING: {CLIENT_CONF_NAME} not found, default options used')
        return _CLIENT_CONF_DEFAULT_DICT