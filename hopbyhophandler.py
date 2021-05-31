from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp
import networkx as nx


class HopbyHophandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HopbyHophandler, self).__init__(*args, **kwargs)
        self.Path_list = {}
        self.Link_list = []
        self.Switch_list = []

    # tutti i pacchetti al controllore
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)
                ]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            instructions=inst
        )
        datapath.send_msg(mod)

        self.Link_list = get_all_link(self)
        self.Switch_list = get_all_switch(self)

    # trova switch destinazione e porta dello switch
    def find_destination_switch(self, destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None, None)

    def find_next_hop_to_destination(self, source_id, destination_id):
        net = nx.DiGraph()
        self.Link_list = get_all_link(self)
        for link in self.Link_list:
            net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(
            net,
            source_id,
            destination_id
        )

        first_link = net[path[0]][path[1]]

        return (first_link['port'], path)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        path = None

        # se ARP esegui proxy arp
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.proxy_arp(msg)
            return

        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        destination_mac = eth.dst
        source_mac = eth.src

        # trova switch destinazione
        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)
        # trova switch sorgente
        (src_dpid, src_port) = self.find_destination_switch(source_mac)

        # host non trovato
        if dst_dpid is None:
            # print "DP: ", datapath.id, "Host not found: ", pkt_ip.dst
            return

        if dst_dpid == datapath.id:
            # da usare se l'host e' direttamente collegato
            output_port = dst_port
        else:
            # host non direttamente collegato
            (output_port, path) = self.find_next_hop_to_destination(datapath.id, dst_dpid)

        print("messaggio da", source_mac, "a", destination_mac)
        print("Path trovato", path)

        def IsinPath(present, prev):
            if prev == []:
                return 0
            elif present == prev:
                return 1
            else:
                Lenght = len(present)
                if len(prev) > Lenght:
                    Lenght = len(prev)
                    for i in range(Lenght):
                        if prev[i] == present[0]:
                            n = 1
                            while (n < len(present)) and (prev[i + n] == present[n]):
                                n += 1
                            if n == len(present):
                                return 1
                            else:
                                return 0
                else:
                    for i in range(Lenght):
                        if present[i] == prev[0]:
                            n = 1
                            while (n < len(prev)) and (present[i + n] == prev[n]):
                                n += 1
                            if n == len(prev):
                                return 2
                            else:
                                return 0
                return 0

        if path is not None:
            if destination_mac not in self.Path_list:
                self.Path_list[destination_mac] = [path]
            else:
                check = 0
                print("controllo i path...")
                for previous_path in self.Path_list[destination_mac]:
                    in_path = IsinPath(path, previous_path)
                    print("Rapporto path: ", in_path)
                    if in_path == 2:
                        self.Path_list[destination_mac].remove(previous_path)
                        print("deleted previous path: ", previous_path)
                        if check == 0:
                            print("aggiungo dopo delete check=", check)
                            self.Path_list[destination_mac].append(path)
                            check = check + 1
                        check = 0
                    elif in_path == 1:
                        print("il path è un sottoset di ", previous_path)
                        break
                    elif in_path == 0:
                        self.Path_list[destination_mac].append(path)
                        print("path diversi")

        # print "DP: ", datapath.id, "Host: ", pkt_ip.dst, "Port: ", output_port
        print(self.Path_list)

        # inoltra il pacchetto corrente
        actions = [parser.OFPActionOutput(output_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

        # aggiungi la regola
        match = parser.OFPMatch(
            eth_dst=destination_mac
        )
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(output_port)]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst,
            buffer_id=msg.buffer_id
        )
        datapath.send_msg(mod)

        return

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def Port_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dp_id = dp.id
        ofp = dp.ofproto
        port_no = msg.desc.port_no

        print(dp_id, "porta: ", port_no)

        link_down = None

        lista_link = [(link.src.dpid, link.dst.dpid, {'port': link.dst.port_no}) for link in self.Link_list]
        print(lista_link)

        # troviamo il link che è stato disconnesso
        for link in self.Link_list:
            if (link.src.dpid is dp_id) & (link.src.port_no is port_no):
                link_down = link

        if link_down:
            link_down_dpid = [link_down.src.dpid, link_down.dst.dpid]
            print(link_down_dpid)
        else:
            print("LINK DOWN NON TROVATO! xxxx")

        def generateFlowMod(datapath, eth_dst):
            ofproto = datapath.ofproto
            match = datapath.ofproto_parser.OFPMatch(
                eth_dst=eth_dst
            )

            instructions = []

            flow_del = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, 0,
                                                          ofproto.OFPFC_DELETE, 0, 0,
                                                          1,
                                                          ofproto.OFPCML_NO_BUFFER,
                                                          ofproto.OFPP_ANY,
                                                          ofproto.OFPG_ANY, 0,
                                                          match, instructions)
            print("Cancellazione Flow entries nello switch ", str(datapath.id))
            datapath.send_msg(flow_del)

        def deletePathFlows(link, path, eth_dst):
            lista1 = []
            lista2 = []

            #caso path uguale a link, di lunghezza 2
            if path == link:
                for switch in get_all_switch(self):
                    if switch.id in link:
                        generateFlowMod(switch, eth_dst)
                self.Path_list[eth_dst].remove(path)
                return

            for i in range(len(path) - 1):
                if path[i] == link[0] and path[i + 1] == link[1]:

                    # nel caso di link presente in path salvati si separa il path in due rami
                    for j in range(i):
                        lista1 = lista1.append(path[j])
                    for j in range(i + 1, len(path) - 1):
                        lista2 = lista2.append(path[j])

                    print("DEB-DelPathFlows: link trovato nel path")

                    # aggiornamento della lista Path_list:
                    # rimuovo il path lungo e inserisco i due path separati dalla rottura del link
                    self.Path_list[eth_dst].remove(path)
                    self.Path_list[eth_dst].append(lista2)
                    print(self.Path_list)

                    # individuazione dei DP con regole sbagliate e creazione dei messaggi flowmod
                    # si cancellano le regole con match su eth_dst solo sul percorso "che precede" il link rotto
                    for switch in get_all_switch(self):
                        if switch.id in lista1:
                            generateFlowMod(switch, eth_dst)
            return

        for eth_dst in self.Path_list:
            for path in self.Path_list[eth_dst]:
                deletePathFlows(link_down_dpid, path, eth_dst)

    def proxy_arp(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt_in = packet.Packet(msg.data)
        eth_in = pkt_in.get_protocol(ethernet.ethernet)
        arp_in = pkt_in.get_protocol(arp.arp)

        # gestiamo solo i pacchetti ARP REQUEST
        if arp_in.opcode != arp.ARP_REQUEST:
            return

        destination_host_mac = None

        for host in get_all_host(self):
            if arp_in.dst_ip in host.ipv4:
                destination_host_mac = host.mac
                break

        # host non trovato
        if destination_host_mac is None:
            return

        pkt_out = packet.Packet()
        eth_out = ethernet.ethernet(
            dst=eth_in.src,
            src=destination_host_mac,
            ethertype=ether_types.ETH_TYPE_ARP
        )
        arp_out = arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=destination_host_mac,
            src_ip=arp_in.dst_ip,
            dst_mac=arp_in.src_mac,
            dst_ip=arp_in.src_ip
        )
        pkt_out.add_protocol(eth_out)
        pkt_out.add_protocol(arp_out)
        pkt_out.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=pkt_out.data
        )
        datapath.send_msg(out)

        return
