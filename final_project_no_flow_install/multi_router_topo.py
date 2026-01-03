# multi_router_topo.py
from mininet.topo import Topo

class MultiRouterTopo(Topo):
    def build(self):
        # Add switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Add hosts with default routes
        h1 = self.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.11/24', defaultRoute='via 10.0.1.1')
        
        h3 = self.addHost('h3', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')
        h4 = self.addHost('h4', ip='10.0.2.11/24', defaultRoute='via 10.0.2.1')
        
        h5 = self.addHost('h5', ip='10.0.3.10/24', defaultRoute='via 10.0.3.1')
        h6 = self.addHost('h6', ip='10.0.3.11/24', defaultRoute='via 10.0.3.1')

        # Host-to-switch links
        self.addLink(h1, s1, port2=1)
        self.addLink(h2, s1, port2=2)
        
        self.addLink(h3, s2, port2=1)
        self.addLink(h4, s2, port2=2)
        
        self.addLink(h5, s3, port2=1)
        self.addLink(h6, s3, port2=2)

        # Switch-to-switch links
        self.addLink(s1, s2, port1=3, port2=3)
        self.addLink(s2, s3, port1=4, port2=3)

topos = {'multirouter': (lambda: MultiRouterTopo())}