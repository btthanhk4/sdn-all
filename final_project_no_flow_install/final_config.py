# final_config.py
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ipv4 import ipv4

# Protocol constants
IP_PROTO_TCP = ipv4.TCP_PROTOCOL
IP_PROTO_UDP = ipv4.UDP_PROTOCOL
IP_PROTO_ICMP = ipv4.ICMP_PROTOCOL

# Gateway IPs for each subnet
GATEWAY_IPS = {
    1: IPAddr("10.0.1.1"),
    2: IPAddr("10.0.2.1"),
    3: IPAddr("10.0.3.1")
}

# MAC addresses for each switch port
INTERFACES = {
    1: {
        1: {'mac': EthAddr('00:00:00:00:01:01')},
        2: {'mac': EthAddr('00:00:00:00:01:02')},
        3: {'mac': EthAddr('00:00:00:00:01:03')}
    },
    2: {
        1: {'mac': EthAddr('00:00:00:00:02:01')},
        2: {'mac': EthAddr('00:00:00:00:02:02')},
        3: {'mac': EthAddr('00:00:00:00:02:03')},
        4: {'mac': EthAddr('00:00:00:00:02:04')}
    },
    3: {
        1: {'mac': EthAddr('00:00:00:00:03:01')},
        2: {'mac': EthAddr('00:00:00:00:03:02')},
        3: {'mac': EthAddr('00:00:00:00:03:03')}
    }
}

# Next-hop MAC addresses for inter-switch routing
BACKBONE_LINKS = {
    1: {3: {'dst_mac': INTERFACES[2][3]['mac']}},
    2: {3: {'dst_mac': INTERFACES[1][3]['mac']},
        4: {'dst_mac': INTERFACES[3][3]['mac']}},
    3: {3: {'dst_mac': INTERFACES[2][4]['mac']}}
}

# Firewall ACL rules
# Format: (Direction, Protocol, Port, Action)
FIREWALL_RULES = [
    ("INBOUND",  IP_PROTO_TCP, 22, "DENY"),
    ("INBOUND",  IP_PROTO_TCP, 80, "DENY"),
    ("OUTBOUND", IP_PROTO_UDP, 53, "ALLOW"),
]