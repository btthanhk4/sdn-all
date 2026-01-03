# controller.py
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet

from firewall import Firewall
from arp_handler import ARPHandler
from ip_handler import IPHandler
from flow_installer import FlowInstaller
from monitor import Monitor

log = core.getLogger("controller")

# Configuration flags
ENABLE_DEBUG_LOGS = True
ENABLE_MONITOR = True

class FinalController(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.connections = {}
        self.debug_enabled = ENABLE_DEBUG_LOGS
        
        # Initialize all modules
        self.firewall = Firewall()
        self.arp_handler = ARPHandler(debug=self.debug_enabled)
        self.flow_installer = FlowInstaller(debug=self.debug_enabled)
        self.ip_handler = IPHandler(self.arp_handler, self.flow_installer, 
                                     self.firewall, debug=self.debug_enabled)
        self.monitor = Monitor(enabled=ENABLE_MONITOR)
        
        log.info("=" * 60)
        log.info("Router SDN Controller Started")
        log.info("  Debug Logs: %s", "ENABLED" if ENABLE_DEBUG_LOGS else "DISABLED")
        log.info("  Monitoring: %s", "ENABLED" if ENABLE_MONITOR else "DISABLED")
        log.info("=" * 60)

    def _handle_ConnectionUp(self, event):
        """Handle new switch connection"""
        dpid = event.connection.dpid
        self.connections[dpid] = event.connection
        log.info("Switch s%s connected", dpid)
        
        # Install table-miss flow
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)
        log.info("Installed table-miss flow on s%s", dpid)

    def _handle_FlowStatsReceived(self, event):
        """Forward flow stats to monitor"""
        self.monitor.handle_flow_stats(event)

    def _handle_PacketIn(self, event):
        """Process incoming packets"""
        packet = event.parsed
        if not packet.parsed: 
            return
        
        in_port = event.port
        dpid = event.connection.dpid
        
        # L2 learning for all packets
        self.ip_handler.learn_mac(dpid, packet.src, in_port)
        
        # Dispatch to appropriate handler
        if packet.type == ethernet.ARP_TYPE:
            self.arp_handler.handle_arp(event.connection, packet, in_port, self)
            return
        
        if packet.type == ethernet.IP_TYPE:
            self.ip_handler.handle_ip(event.connection, packet, in_port, self)
            return

def launch():
    """POX module launch function"""
    core.registerNew(FinalController)