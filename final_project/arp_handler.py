# arp_handler.py
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of
from final_config import INTERFACES, GATEWAY_IPS

log = core.getLogger("arp_handler")

class ARPHandler:
    def __init__(self, debug=True):
        self.arp_cache = {}
        self.packet_queues = {}
        self.debug = debug
        log.info("ARP Handler initialized")

    def handle_arp(self, connection, packet, in_port, controller):
        """Process ARP requests and replies"""
        arp_pkt = packet.payload
        dpid = connection.dpid
        
        # Learn source MAC
        self.arp_cache[arp_pkt.protosrc] = arp_pkt.hwsrc

        if arp_pkt.opcode == arp.REQUEST:
            gw_ip = GATEWAY_IPS.get(dpid)
            if gw_ip and arp_pkt.protodst == gw_ip:
                # Proxy ARP for gateway
                if in_port in INTERFACES[dpid]:
                    my_mac = INTERFACES[dpid][in_port]['mac']
                    if self.debug:
                        log.info("ARP: Gateway reply %s -> %s (MAC: %s)", 
                                 arp_pkt.protosrc, gw_ip, my_mac)
                    self.send_arp_reply(connection, arp_pkt, my_mac, in_port)
                return True
            else:
                self.flood(connection, packet, in_port)
                return True

        elif arp_pkt.opcode == arp.REPLY:
            # Process queued packets waiting for this ARP reply
            if arp_pkt.protosrc in self.packet_queues:
                if self.debug:
                    log.info("ARP: Reply for %s, flushing queue", arp_pkt.protosrc)
                self.process_queue(controller, arp_pkt.protosrc)
            
            self.flood(connection, packet, in_port)
            return True

        return False

    def send_arp_reply(self, connection, req_pkt, mac_src, out_port):
        """Send ARP reply packet"""
        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwdst = req_pkt.hwsrc
        reply.protodst = req_pkt.protosrc
        reply.hwsrc = mac_src
        reply.protosrc = req_pkt.protodst
        
        e = ethernet(type=ethernet.ARP_TYPE, src=mac_src, dst=req_pkt.hwsrc)
        e.payload = reply
        
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = of.OFPP_NONE
        connection.send(msg)

    def send_arp_request(self, connection, ip_dst, dpid):
        """Send ARP request to discover MAC address"""
        for port in [1, 2]:
            if port in INTERFACES[dpid]:
                src_mac = INTERFACES[dpid][port]['mac']
                src_ip = GATEWAY_IPS[dpid]
                
                req = arp()
                req.opcode = arp.REQUEST
                req.hwsrc = src_mac
                req.protosrc = src_ip
                req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")
                req.protodst = ip_dst
                
                e = ethernet(type=ethernet.ARP_TYPE, src=src_mac, 
                           dst=EthAddr("ff:ff:ff:ff:ff:ff"))
                e.payload = req
                
                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port=port))
                msg.in_port = of.OFPP_NONE
                connection.send(msg)

    def process_queue(self, controller, ip_dst):
        """Process packets queued waiting for ARP resolution"""
        if ip_dst in self.packet_queues:
            queue = self.packet_queues.pop(ip_dst)
            for (packet, in_dpid, in_port) in queue:
                conn = controller.connections.get(in_dpid)
                if conn:
                    controller.ip_handler.handle_ip(conn, packet, in_port, controller)

    def flood(self, connection, packet, in_port):
        """Flood packet to all ports"""
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.data = packet.pack()
        msg.in_port = in_port
        connection.send(msg)