# ip_handler.py
from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp
import pox.openflow.libopenflow_01 as of
from .final_config import INTERFACES, BACKBONE_LINKS, GATEWAY_IPS

log = core.getLogger("ip_handler")

class IPHandler:
    def __init__(self, arp_handler, flow_installer, firewall, debug=True):
        self.arp_handler = arp_handler
        self.flow_installer = flow_installer
        self.firewall = firewall
        self.mac_table = {}
        self.debug = debug
        log.info("IP Handler initialized")

    def handle_ip(self, connection, packet, in_port, controller):
        """Main IP packet routing handler"""
        ip_pkt = packet.payload
        dst_ip = ip_pkt.dstip
        src_ip = ip_pkt.srcip
        dpid = connection.dpid
        protocol = ip_pkt.protocol
        
        # L2 learning
        self.learn_mac(dpid, packet.src, in_port)

        src_subnet = self.get_subnet_dpid(src_ip)
        dst_subnet = self.get_subnet_dpid(dst_ip)

        # Firewall check
        should_drop, drop_proto, drop_port = self.firewall.check_packet(
            dpid, packet, in_port, src_subnet, dst_subnet
        )
        
        if should_drop:
            self.flow_installer.install_drop_flow(connection, src_ip, dst_ip, 
                                                  drop_proto, drop_port)
            return

        # Handle packets destined to gateway
        gw_ip = GATEWAY_IPS.get(dpid)
        if dst_ip == gw_ip:
            icmp_pkt = packet.find('icmp')
            if icmp_pkt and icmp_pkt.type == 8:
                if self.debug:
                    log.info("Gateway ICMP: %s -> %s on s%s", src_ip, dst_ip, dpid)
                
                # Install flow for monitoring
                gw_mac = INTERFACES[dpid][in_port]['mac']
                host_mac = packet.src
                self.flow_installer.install_local_flow(
                    connection, src_ip, gw_ip, gw_mac, gw_mac, in_port, protocol=protocol
                )
                self.flow_installer.install_local_flow(
                    connection, gw_ip, src_ip, gw_mac, host_mac, in_port, protocol=protocol
                )
                
                # Send ICMP reply
                self.send_icmp_reply(connection, packet, in_port, dpid)
            return

        # Local delivery (same subnet)
        if dst_subnet == dpid:
            if self.debug:
                log.info("Delivering on s%s: %s -> %s", dpid, src_ip, dst_ip)
            self.forward_local(connection, packet, dst_ip, in_port, src_ip, protocol)
            return

        # Inter-subnet routing
        out_port = 0
        next_hop_mac = None

        if dpid == 1:
            if dst_subnet in [2, 3]: 
                out_port = 3
                next_hop_mac = BACKBONE_LINKS[1][3]['dst_mac']
                if self.debug:
                    log.info("s1: Routing to s2 via port 3")
        elif dpid == 2:
            if dst_subnet == 1:
                out_port = 3
                next_hop_mac = BACKBONE_LINKS[2][3]['dst_mac']
                if self.debug:
                    log.info("s2: Routing to s1 via port 3")
            elif dst_subnet == 3:
                out_port = 4
                next_hop_mac = BACKBONE_LINKS[2][4]['dst_mac']
                if self.debug:
                    log.info("s2: Routing to s3 via port 4")
        elif dpid == 3:
            if dst_subnet in [1, 2]:
                out_port = 3
                next_hop_mac = BACKBONE_LINKS[3][3]['dst_mac']
                if self.debug:
                    log.info("s3: Routing to s2 via port 3")

        if out_port != 0 and next_hop_mac:
            router_out_mac = INTERFACES[dpid][out_port]['mac']
            
            router_in_mac = None
            if in_port in INTERFACES[dpid]:
                router_in_mac = INTERFACES[dpid][in_port]['mac']
            host_src_mac = packet.src 

            if self.debug:
                log.info("Installing flows: %s -> %s", src_ip, dst_ip)
            
            # Install forward and reverse flows
            # self.flow_installer.install_l3_flow(connection, src_ip, dst_ip, 
            #                                     router_out_mac, next_hop_mac, out_port, 
            #                                     protocol=protocol)
            
            # if router_in_mac:
            #     self.flow_installer.install_reverse_flow(connection, src_ip, dst_ip,
            #                                              router_in_mac, host_src_mac, in_port,
            #                                              protocol=protocol)

            self.send_packet(connection, packet, out_port, router_out_mac, next_hop_mac)
        else:
            log.warning("No route found for %s -> %s on s%s", src_ip, dst_ip, dpid)

    def send_icmp_reply(self, connection, request_packet, in_port, dpid):
        """Reply to ICMP Echo Request sent to gateway"""
        req_eth = request_packet
        req_ip = request_packet.find('ipv4')
        req_icmp = request_packet.find('icmp')
        
        if not req_ip or not req_icmp:
            return
        
        # Build ICMP Echo Reply
        reply_icmp = icmp()
        reply_icmp.type = 0
        reply_icmp.code = 0
        reply_icmp.payload = req_icmp.payload
        
        # Build IP header
        reply_ip = ipv4()
        reply_ip.protocol = ipv4.ICMP_PROTOCOL
        reply_ip.srcip = req_ip.dstip
        reply_ip.dstip = req_ip.srcip
        reply_ip.payload = reply_icmp
        
        # Build Ethernet frame
        reply_eth = ethernet()
        reply_eth.type = ethernet.IP_TYPE
        reply_eth.src = INTERFACES[dpid][in_port]['mac']
        reply_eth.dst = req_eth.src
        reply_eth.payload = reply_ip
        
        # Send packet_out
        msg = of.ofp_packet_out()
        msg.data = reply_eth.pack()
        msg.actions.append(of.ofp_action_output(port=in_port))
        msg.in_port = of.OFPP_NONE
        connection.send(msg)
        
        if self.debug:
            log.info("Sent ICMP Reply: %s -> %s", reply_ip.srcip, reply_ip.dstip)

    def learn_mac(self, dpid, mac, port):
        #Learn MAC-to-port mapping
        if dpid not in self.mac_table: 
            self.mac_table[dpid] = {}
        if mac not in self.mac_table[dpid]:
            self.mac_table[dpid][mac] = port

    def forward_local(self, connection, packet, dst_ip, in_port, src_ip, protocol):
        #Forward packet within same subnet
        dpid = connection.dpid
        dst_mac = self.arp_handler.arp_cache.get(dst_ip)
        
        if dst_mac:
            out_port = self.mac_table.get(dpid, {}).get(dst_mac)
            gw_mac = INTERFACES[dpid][out_port]['mac']
            src_mac = packet.src

            if out_port:
                # Install bidirectional local flows
                # self.flow_installer.install_local_flow(connection, src_ip, dst_ip, 
                #                                        gw_mac, dst_mac, out_port, 
                #                                        protocol=protocol)
                # self.flow_installer.install_local_flow(connection, dst_ip, src_ip,
                #                                        gw_mac, src_mac, in_port,
                #                                        protocol=protocol)
                
                self.send_packet(connection, packet, out_port, gw_mac, dst_mac)
            else:
                gw_mac = INTERFACES[dpid][in_port]['mac']
                self.flood_local(connection, packet, dst_mac, gw_mac)
        else:
            # Queue packet and send ARP request
            if self.debug:
                log.info("Queueing packet for ARP: %s", dst_ip)
            if dst_ip not in self.arp_handler.packet_queues:
                self.arp_handler.packet_queues[dst_ip] = []
            self.arp_handler.packet_queues[dst_ip].append((packet, dpid, in_port))
            self.arp_handler.send_arp_request(connection, dst_ip, dpid)

    def flood_local(self, connection, packet, dst_mac, src_mac):
        #Flood packet to local host ports
        for p in [1, 2]:
            self.send_packet(connection, packet, p, src_mac, dst_mac)

    def send_packet(self, connection, packet, out_port, src_mac, dst_mac):
        #Send packet with MAC rewriting
        eth = ethernet()
        eth.src = src_mac
        eth.dst = dst_mac
        eth.type = packet.type
        eth.payload = packet.payload
        
        msg = of.ofp_packet_out()
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = of.OFPP_NONE
        connection.send(msg)

    def get_subnet_dpid(self, ip):
        #Map IP address to subnet switch ID
        s = ip.toStr()
        if s.startswith("10.0.1."): return 1
        if s.startswith("10.0.2."): return 2
        if s.startswith("10.0.3."): return 3
        return 0