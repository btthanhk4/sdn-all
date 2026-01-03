# monitor.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.recoco import Timer
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.ethernet import ethernet

log = core.getLogger("monitor")

class Monitor:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.cumulative_proto_stats = {}
        self.cumulative_host_stats = {}
        
        # Subnet mapping for each switch
        self.switch_subnets = {
            1: "10.0.1.",
            2: "10.0.2.",
            3: "10.0.3."
        }
        
        if self.enabled:
            log.info("Monitor initialized - polling every 5 seconds")
            Timer(5, self._request_stats, recurring=True)
        else:
            log.info("Monitor DISABLED")

    def _request_stats(self):
        """Request flow statistics from all switches"""
        if not self.enabled:
            return
        for connection in core.openflow.connections:
            connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))

    def handle_flow_stats(self, event):
        """Process flow statistics and display report"""
        if not self.enabled:
            return
            
        dpid = event.connection.dpid
        
        # Initialize cumulative stats
        if dpid not in self.cumulative_proto_stats:
            self.cumulative_proto_stats[dpid] = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        if dpid not in self.cumulative_host_stats:
            self.cumulative_host_stats[dpid] = {}
        
        # Current period stats
        current_proto = {'TCP': 0, 'UDP': 0, 'ICMP': 0}
        current_host = {}
        
        # Get subnet prefix for this switch
        my_subnet = self.switch_subnets.get(dpid, "")

        for f in event.stats:
            byte_count = f.byte_count
            
            if f.match.dl_type == ethernet.IP_TYPE and byte_count > 0:
                nw_proto = f.match.nw_proto
                
                # Aggregate by protocol
                if nw_proto == ipv4.TCP_PROTOCOL:
                    current_proto['TCP'] += byte_count
                elif nw_proto == ipv4.UDP_PROTOCOL:
                    current_proto['UDP'] += byte_count
                elif nw_proto == ipv4.ICMP_PROTOCOL:
                    current_proto['ICMP'] += byte_count

                # Aggregate by host - only count hosts in this subnet
                src = str(f.match.nw_src) if f.match.nw_src else None
                dst = str(f.match.nw_dst) if f.match.nw_dst else None
                
                # Count TX if source belongs to this subnet
                if src and src != "0.0.0.0" and src.startswith(my_subnet):
                    if src not in current_host: 
                        current_host[src] = {'tx': 0, 'rx': 0}
                    current_host[src]['tx'] += byte_count

                # Count RX if destination belongs to this subnet
                if dst and dst != "0.0.0.0" and dst.startswith(my_subnet):
                    if dst not in current_host: 
                        current_host[dst] = {'tx': 0, 'rx': 0}
                    current_host[dst]['rx'] += byte_count

        # Update cumulative stats
        for proto in ['TCP', 'UDP', 'ICMP']:
            self.cumulative_proto_stats[dpid][proto] = max(
                self.cumulative_proto_stats[dpid][proto],
                current_proto[proto]
            )
        
        for ip, stats in current_host.items():
            if ip not in self.cumulative_host_stats[dpid]:
                self.cumulative_host_stats[dpid][ip] = {'tx': 0, 'rx': 0}
            
            self.cumulative_host_stats[dpid][ip]['tx'] = max(
                self.cumulative_host_stats[dpid][ip]['tx'],
                stats['tx']
            )
            self.cumulative_host_stats[dpid][ip]['rx'] = max(
                self.cumulative_host_stats[dpid][ip]['rx'],
                stats['rx']
            )

        # Display report
        log.info("\n" + "=" * 50)
        log.info("MONITOR REPORT SWITCH s%s", dpid)
        log.info("=" * 50)
        
        log.info("--- Protocol Stats (Bytes) ---")
        has_proto_data = False
        for proto in ['TCP', 'UDP', 'ICMP']:
            if self.cumulative_proto_stats[dpid][proto] > 0:
                log.info("  %-4s: %d bytes", proto, 
                         self.cumulative_proto_stats[dpid][proto])
                has_proto_data = True
        
        if not has_proto_data:
            log.info("  No IP traffic recorded")
        
        log.info("-" * 50)
        
        log.info("--- Host Stats (TX/RX Bytes) ---")
        if self.cumulative_host_stats[dpid]:
            for ip in sorted(self.cumulative_host_stats[dpid].keys()):
                stat = self.cumulative_host_stats[dpid][ip]
                log.info("  Host %-12s | TX: %-6d | RX: %-6d", 
                         ip, stat['tx'], stat['rx'])
        else:
            log.info("  No host traffic recorded")
        
        log.info("=" * 50 + "\n")