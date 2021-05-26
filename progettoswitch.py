# Implementazione openflow di hop-by-hop routing
# usando la mappa della rete trovata con topology discovery
#
# Si richiede l'uso del topology discovery
# ryu-manager --observe-links
#
# Nella versione attuale richiede risoluzione arp gia' fatta
# invocare mininet con
# mn --arp

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types
import networkx as nx


class FRANCO(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FRANCO, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.Lista_links = []





    # def send_set_async(self, datapath):
    #     ofp = datapath.ofproto
    #     ofp_parser = datapath.ofproto_parser
    #
    #     packet_in_mask = 1 << ofp.OFPR_ACTION | 1 << ofp.OFPR_INVALID_TTL | 1 << ofp.OFPR_NO_MATCH
    #     port_status_mask = (1 << ofp.OFPPR_ADD
    #                         | 1 << ofp.OFPPR_DELETE
    #                         | 1 << ofp.OFPPR_MODIFY)
    #     flow_removed_mask = (1 << ofp.OFPRR_IDLE_TIMEOUT
    #                          | 1 << ofp.OFPRR_HARD_TIMEOUT
    #                          | 1 << ofp.OFPRR_DELETE)
    #     req = ofp_parser.OFPSetAsync(datapath,
    #                                  [packet_in_mask, 0],
    #                                  [port_status_mask, 0],
    #                                  [flow_removed_mask, 0])
    #     datapath.send_msg(req)
    #
    # def send_get_async_request(self, datapath):
    #     ofp_parser = datapath.ofproto_parser
    #
    #     req = ofp_parser.OFPGetAsyncRequest(datapath)
    #     datapath.send_msg(req)

    # tutti i pacchetti al controllore

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        self.Lista_links = get_all_link(self)

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port[datapath.id] = {}

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [
                    parser.OFPActionOutput(
                        ofproto.OFPP_CONTROLLER,
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


        print('HO FATTO LA GET TOPOLOGY')
        lista_link = [(link.src.dpid, link.dst.dpid, link.src.port_no) for link in self.Lista_links]
        print(lista_link)



    # trova switch destinazione e porta dello switch
    def find_destination_switch(self, destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None, None)


    def find_next_hop_to_destination(self, source_id, destination_id):
        net = nx.DiGraph()
        for link in get_all_link(self):
            net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(
            net,
            source_id,
            destination_id
        )

        first_link = net[path[0]][path[1]]

        return first_link['port']


    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def Port_handler(self, ev):

        global Lista_links

        def trova_link(lista, dp, port):
            for elem in lista:
                if elem[0] == dp & elem[2] == port:
                    return elem

        msg = ev.msg
        dp = msg.datapath
        dp_id = dp.id
        ofp = dp.ofproto
        port_no = msg.desc.port_no

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
        else:
            reason = 'unknown'

        self.logger.debug('OFPPortStatus received: reason=%s desc=%s DP=%s',
                          reason, msg.desc, dp_id)
        self.logger.debug('_____________POOORT NUMBER__________ %s', msg.desc.port_no)

        if reason == 'MODIFY':

            # lista di elementi link (switch sorgente, switch destinazione, numero di porta)


            link_interessato = trova_link(lista=lista_link, dp=dp_id, port=msg.desc.port_no)
            self.logger.debug('link interessato %s', link_interessato)



            # caso LINK CON HOST:

            if link_interessato == None:
                self.logger.debug("link nullo, hai sbagliato qualcosa", ev.msg.datapath.id, reason, msg.desc)
                return
            elif (link_interessato[0][0] == 's' & link_interessato[1][0] == 'h') | (
                    link_interessato[1][0] == 's' & link_interessato[0][0] == 'h'):

                self.logger.debug('è stato spento un link tra %s e %s, SWITCH-HOST', link_interessato[0],
                                  link_interessato[1])

            else:
                self.logger.debug('è stato spento un link tra %s e %s, SWITCH-SWITCH', link_interessato[0],
                                  link_interessato[1])


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignora pacchetti non IPv4 (es. ARP, LLDP)
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        destination_mac = eth.dst

        # trova switch destinazione
        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)

        # host non trovato
        if dst_dpid is None:
            # print "DP: ", datapath.id, "Host not found: ", pkt_ip.dst
            return

        if dst_dpid == datapath.id:
            # da usare se l'host e' direttamente collegato
            output_port = dst_port
        else:
            # host non direttamente collegato
            output_port = self.find_next_hop_to_destination(datapath.id, dst_dpid)

        # print "DP: ", datapath.id, "Host: ", pkt_ip.dst, "Port: ", output_port

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

        # aggiungi la regola per i prossimi pacchetti
        match = parser.OFPMatch(
            eth_dst=destination_mac
        )
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=10,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

        get_topology()

        return
