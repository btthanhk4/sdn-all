# flow_installer.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger("flow")

class FlowInstaller:
    def __init__(self, debug=True):
        self.debug = debug
        log.info("Flow Installer initialized")
    
    def install_l3_flow(self, connection, ip_src, ip_dst, src_mac, dst_mac, 
                        out_port, protocol=None):
        """Install forward flow for inter-subnet traffic"""
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 120
        msg.hard_timeout = 300
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE,
            nw_src=ip_src, 
            nw_dst=ip_dst
        )
        
        if protocol is not None:
            msg.match.nw_proto = protocol
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        connection.send(msg)
        if self.debug:
            log.info("Installed FORWARD flow on s%s: %s -> %s via port %s", 
                     connection.dpid, ip_src, ip_dst, out_port)

    def install_reverse_flow(self, connection, ip_src, ip_dst, 
                             rev_src_mac, rev_dst_mac, rev_out_port, protocol=None):
        """Install reverse flow for return traffic"""
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 120
        msg.hard_timeout = 300
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE,
            nw_src=ip_dst,
            nw_dst=ip_src
        )
        
        if protocol is not None:
            msg.match.nw_proto = protocol
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(rev_src_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(rev_dst_mac))
        msg.actions.append(of.ofp_action_output(port=rev_out_port))
        
        connection.send(msg)
        if self.debug:
            log.info("Installed REVERSE flow on s%s: %s -> %s via port %s", 
                     connection.dpid, ip_dst, ip_src, rev_out_port)

    def install_local_flow(self, connection, ip_src, ip_dst, 
                           src_mac, dst_mac, out_port, protocol=None):
        """Install flow for same-subnet traffic"""
        msg = of.ofp_flow_mod()
        msg.priority = 100
        msg.idle_timeout = 120
        msg.hard_timeout = 300
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE,
            nw_src=ip_src,
            nw_dst=ip_dst
        )
        
        if protocol is not None:
            msg.match.nw_proto = protocol
        
        msg.actions.append(of.ofp_action_dl_addr.set_src(src_mac))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        msg.actions.append(of.ofp_action_output(port=out_port))
        
        connection.send(msg)
        if self.debug:
            log.info("Installed LOCAL flow on s%s: %s -> %s via port %s", 
                     connection.dpid, ip_src, ip_dst, out_port)

    def install_drop_flow(self, connection, ip_src, ip_dst, protocol, dst_port):
        """Install DROP flow for firewall-blocked traffic"""
        msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.idle_timeout = 0
        msg.hard_timeout = 0
        
        msg.match = of.ofp_match(
            dl_type=ethernet.IP_TYPE,
            nw_proto=protocol,
            nw_dst=ip_dst,
            tp_dst=dst_port
        )
        
        connection.send(msg)
        
        proto_name = "TCP" if protocol == ipv4.TCP_PROTOCOL else \
                     "UDP" if protocol == ipv4.UDP_PROTOCOL else str(protocol)
        log.warning("Installed DROP flow on s%s: proto=%s dst=%s port=%s", 
                    connection.dpid, proto_name, ip_dst, dst_port)