import netutils
import mimetypes
import pathlib

_VALID_MIMETYPES = set(
    map(
        lambda s: s.split('/').pop(0),
        mimetypes.types_map.values(),
    )
).union(
    map(
        lambda s: s.split('/').pop(0),
        mimetypes.common_types.values(),
    )
).union(
    mimetypes.types_map.values()
).union(
    mimetypes.common_types.values()
)

WHITELIST_PATH = pathlib.Path('whitelist')
HOSTS_FILENAME = 'trusted-hosts.whitelist'
MIMETYPES_FILENAME = 'trusted-mimetypes.whitelist'

def _parse_trusted_hosts_line(line, trusted_hosts):
    line = line.strip()

    if line and not line.startswith('#'):
        hostname, port = line.split(':')

        ipv4 = netutils.get_numeric_ipv4(hostname)

        if port != 'any':
            port = netutils.get_numeric_port(port)

        if ipv4 not in trusted_hosts:
            trusted_hosts[ipv4] = []

        trusted_hosts[ipv4].append(port)

def load_trusted_hosts():
    trusted_hosts = {}

    with open(WHITELIST_PATH.joinpath(HOSTS_FILENAME), 'r', encoding='utf-8') as file:
        for line in file.readlines():
            _parse_trusted_hosts_line(line, trusted_hosts)

    # Redundant declarations check
    for ipv4 in trusted_hosts.keys():
        ports = trusted_hosts[ipv4]
        ports_set = set(ports)

        if 'any' in ports and len(ports) > 1:
            trusted_hosts[ipv4] = ['any']
            # TODO: LOG
            print(f'WARNING: Redundant ports on whitelist for {ipv4}, used \'any\'')
        elif len(ports) != len(ports_set):
            trusted_hosts[ipv4] = list(ports_set)
            # TODO: LOG
            print(f'WARNING: Redundant ports on whitelist for {ipv4}, copies discarded')

    return trusted_hosts
                
def is_trusted_host(address, trusted_hosts):
    hostname, port = address

    ipv4 = netutils.get_numeric_ipv4(hostname)
    port = netutils.get_numeric_port(port)
    
    if ipv4 not in trusted_hosts:
        return False
    
    if 'any' in trusted_hosts[ipv4]:
        return True
    
    if port in trusted_hosts[ipv4]:
        return True
    
    return False

def _parse_trusted_mimetypes_line(line, trusted_mimetypes):
    line = line.strip()

    if line and not line.startswith('#'):
        if line in _VALID_MIMETYPES:
            trusted_mimetypes.append(line)
        else:
            raise ValueError(f'Invalid \'{line}\' MIME type')

def load_trusted_mimetypes():
    trusted_mimetypes = []

    with open(WHITELIST_PATH.joinpath(MIMETYPES_FILENAME), 'r', encoding='utf-8') as file:
        for line in file.readlines():
            _parse_trusted_mimetypes_line(line, trusted_mimetypes)
    
    return trusted_mimetypes

def is_trusted_mimetype(mimetype, trusted_mimetypes):
    return (mimetype.split('/').pop(0) in trusted_mimetypes
            or mimetype in trusted_mimetypes)