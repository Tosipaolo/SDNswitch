from mininet.topo import Topo


class Test_Topo(Topo):
    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
       # h4 = self.addHost("h4")
        h5 = self.addHost("h5")
        h6 = self.addHost("h6")
        h7 = self.addHost("h7")
        h8 = self.addHost("h8")
        h9 = self.addHost("h9")
        h10 = self.addHost("h10")

        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
       # s4 = self.addSwitch("s4")
        s5 = self.addSwitch("s5")
        s6 = self.addSwitch("s6")
        s7 = self.addSwitch("s7")
        s8 = self.addSwitch("s8")

        self.addLink(s1, s2)
        self.addLink(s3, s2)
        self.addLink(s1, s5)
        self.addLink(s6, s2)
        self.addLink(s5, s2)
        self.addLink(s6, s8)
        self.addLink(s3, s8)
        self.addLink(s3, s7)
        self.addLink(s1, h1)
        self.addLink(s5, h5)
        self.addLink(s2, h2)
        self.addLink(s3, h3)
       # self.addLink(s4, h4)
        self.addLink(s6, h6)
        self.addLink(s7, h7)
        self.addLink(s8, h8)
        self.addLink(s8, h9)
        self.addLink(s8, h10)


topos = {"first": (lambda: first())}
