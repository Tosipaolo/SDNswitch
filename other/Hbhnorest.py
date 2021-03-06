# Implementazione openflow di hop-by-hop routing
# usando la mappa della rete trovata con topology discovery
#
# Si richiede l'uso del topology discovery
# ryu-manager --observe-links
#

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, arp
import networkx as nx

class No_Rest_Downhandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(No_Rest_Downhandler, self).__init__(*args, **kwargs)
        self.FLow_through_Port = {}
        self.Link_list = []
        self.Switch_list = []
        self.Host_list = []

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
            match = parser.OFPMatch(),
            instructions=inst
        )
        datapath.send_msg(mod)
        self.FLow_through_Port[datapath.id] = {}
        print("Creazione dict del datapath", datapath.id)


        # trova switch destinazione e porta dello switch
    def find_destination_switch(self, destination_mac):
        self.Host_list = get_all_host(self)
        for host in self.Host_list:
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None,None)

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

        first_link = net[ path[0] ][ path[1] ]

        return first_link['port']

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # se ARP esegui proxy arp
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self.proxy_arp(msg)
            return

        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        destination_mac = eth.dst
        sender_mac = eth.src

        # trova switch destinazione
        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)
        # trova switch sorgente
        (src_dpid, src_port) = self.find_destination_switch(sender_mac)

        # host non trovato
        if dst_dpid is None:
            print("DP: ", datapath.id, "Host not found: ")
            return

        if dst_dpid == datapath.id:
            # da usare se l'host e' direttamente collegato
            output_port = dst_port
        else:
            # host non direttamente collegato
            output_port = self.find_next_hop_to_destination(datapath.id, dst_dpid)

        # print "DP: ", datapath.id, "Host: ", pkt_ip.dst, "Port: ", output_port

        print("BREAK: PRIMA DI RIEMPIRE LA Flow_through_Port")

        # CREO UNA TABELLA CON LE CORRISPONDENZE MITTENTE-DESTINATARIO CHE SI VERIFICANO
        # SU UNA DATA PORTA DEL DATAPATH
        if datapath.id in self.FLow_through_Port:
            if output_port in self.FLow_through_Port[datapath.id]:
                self.FLow_through_Port[datapath.id][output_port].append((sender_mac, src_dpid, destination_mac, dst_dpid))
            else:
                self.FLow_through_Port[datapath.id][output_port] = [(sender_mac, src_dpid, destination_mac, dst_dpid)]
        else:
            self.FLow_through_Port[datapath.id] = {output_port: [(sender_mac, src_dpid, destination_mac, dst_dpid)]}

        print(self.FLow_through_Port)


        # inoltra il pacchetto corrente
        actions = [ parser.OFPActionOutput(output_port) ]
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
                [ parser.OFPActionOutput(output_port) ]
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

        net = nx.DiGraph()

        def createFlowMod(datapath, source_eth, dest_eth):
            match = parser.OFPMatch(
                eth_dst=dest_eth
            )

            instructions = []

            flow_del = datapath.ofproto_parser.OFPFlowmod(datapath, 0, 0, 0,
                                                          ofproto.OFPFC_DELETE, 0, 0,
                                                          1,
                                                          ofproto.OFPCML_NO_BUFFER,
                                                          ofproto.OFPP_ANY,
                                                          OFPG_ANY, 0,
                                                          match, instructions)
            return flow_del

        if port_no in self.FLow_through_Port[dp_id]:
            print("MATCH SULLE LISTE")
        else:
            print("Liste Vuote: NESSUN FLOW SULLA PORTA:", port_no)
            return

        for link in self.Link_list:
            net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        for flow in self.FLow_through_Port[dp_id][port_no]:
            # si trova il cammino minimo tra il mittente e il destinatario salvati alla packet_in che
            # scambiavano pacchetti attraverso quella porta
            print(type(flow))
            print(flow)
            path = nx.shortest_path(
                net,
                flow[1],
                flow[3]
            )

            if path is None:
                return

            for hop in self.Switch_list:
                if hop.id in path:
                    FlowMod = createFlowMod(hop, flow[0], flow[2])
                    hop.send_msg(FlowMod)

            self.FLow_through_Port[dp_id][port_no].remove(flow)




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
            dst = eth_in.src,
            src = destination_host_mac,
            ethertype = ether_types.ETH_TYPE_ARP
        )
        arp_out = arp.arp(
            opcode  = arp.ARP_REPLY,
            src_mac = destination_host_mac,
            src_ip  = arp_in.dst_ip,
            dst_mac = arp_in.src_mac,
            dst_ip  = arp_in.src_ip
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