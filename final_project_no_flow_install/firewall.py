# firewall.py
from pox.core import core
from final_config import FIREWALL_RULES, IP_PROTO_TCP, IP_PROTO_UDP

log = core.getLogger("firewall")

class Firewall:
    def __init__(self):
        log.info("Firewall initialized with %d rules", len(FIREWALL_RULES))
        self._log_rules()
    
    def _log_rules(self):
        log.info("=" * 60)
        log.info("FIREWALL RULES:")
        for i, (direction, proto, port, action) in enumerate(FIREWALL_RULES, 1):
            proto_name = "TCP" if proto == IP_PROTO_TCP else \
                        "UDP" if proto == IP_PROTO_UDP else str(proto)
            log.info("  [%d] %-8s %-4s:%-5d -> %s", 
                     i, direction, proto_name, port, action)
        log.info("=" * 60)
    
    def check_packet(self, dpid, packet, in_port, src_subnet_dpid, dst_subnet_dpid):
        """
        Check if packet should be dropped by firewall
        Returns: (should_drop, protocol, dst_port)
        """
        # Only check inter-subnet traffic
        if src_subnet_dpid == dst_subnet_dpid:
            return (False, None, None)
        
        ip_pkt = packet.find('ipv4')
        if not ip_pkt: 
            return (False, None, None)

        # Extract protocol and port
        tcp_pkt = packet.find('tcp')
        udp_pkt = packet.find('udp')

        proto_val = None
        dst_port = None
        proto_str = None

        if tcp_pkt:
            proto_val = IP_PROTO_TCP
            proto_str = "TCP"
            dst_port = tcp_pkt.dstport
        elif udp_pkt:
            proto_val = IP_PROTO_UDP
            proto_str = "UDP"
            dst_port = udp_pkt.dstport

        if dst_port is None:
            return (False, None, None)

        # Determine traffic direction
        is_inbound = (dst_subnet_dpid == dpid)
        is_outbound = (src_subnet_dpid == dpid)

        # Check ACL rules
        for (rule_direction, rule_proto, rule_port, action) in FIREWALL_RULES:
            # Match direction
            if rule_direction == "INBOUND" and not is_inbound:
                continue
            if rule_direction == "OUTBOUND" and not is_outbound:
                continue
            
            # Match protocol and port
            if rule_proto == proto_val and rule_port == dst_port:
                if action == "DENY":
                    log.warning("FIREWALL BLOCKED [%s]: %s:%d on s%s", 
                                rule_direction, proto_str, dst_port, dpid)
                    return (True, proto_val, dst_port)
                elif action == "ALLOW":
                    log.info("FIREWALL ALLOWED [%s]: %s:%d on s%s", 
                             rule_direction, proto_str, dst_port, dpid)
                    return (False, None, None)

        return (False, None, None)