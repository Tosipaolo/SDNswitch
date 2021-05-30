from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
import ryu.app.ofctl.api as ofctl
import networkx as nx

import json
import requests
import ryu.app.ofctl_rest


# This implements a learning switch in the controller
# The switch sends all packets to the controller
# The controller implements the MAC table using a python dictionary
# If the MAC dst is known, add rule to the switch
class DOWNHANDLER(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DOWNHANDLER, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.SWITCH_LIST = []
        self.LINK_LIST = []
        self.HOST_LIST = []

    # execute at switch registration
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port[datapath.id] = {}

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

        switch_list = get_all_switch(self)
        link_list = get_all_link(self)
        host_lst = get_all_host(self)

        self.SWITCH_LIST = get_all_switch(self)
        self.LINK_LIST = get_all_link(self)
        self.HOST_LIST = get_all_host(self)

        lista_link = [(link.src.dpid, link.dst.dpid, link.src.port_no) for link in self.LINK_LIST]

        print(lista_link)

        net = nx.DiGraph()
        # net.add_nodes_from(self.SWITCH_LIST)
        # net.add_edges_from(self.LINK_LIST)
        # net.add_nodes_from(self.HOST_LIST)




    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def Port_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dp_id = dp.id
        ofp = dp.ofproto
        port_no = msg.desc.port_no


        def trova_link(dp, port):
            elenco = []
            for src in self.mac_to_port[dp]:
                if self.mac_to_port[dp][src] == port:
                    elenco.append((dp, src, port))
            return elenco


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
        self.logger.debug('_____________PORT NUMBER__________ %s', port_no)

        flow_trough_link = trova_link(dp_id, port_no)
        print(flow_trough_link)

        def getFlowtable(dpid=None):
            """ Method for getting each switch’s flow table (json objects)"""
            url = 'http://localhost:8080/stats/flow/'
            if dpid is not None:
                url = url + str(dpid)
                try:
                    req = requests.get(url)
                    if req.status_code is 200:
                        print("-----returned JSON-----")
                        return json.loads(req.text)
                    if req.status_code is 404:
                        print("FILE NOT FOUND")
                except requests.exceptions.RequestException as e:
                    print("Server error %s " % e)
            else:
                ftables = {}
                for dpid in getAllDatapathID():
                    rl = 'http://localhost:8080/stats/flow/' + str(dpid)
                    ftables[dpid] = getFlowtable(str(dpid))
                return ftables

        def delFlowmatch(addr1, addr2, datapath):
            "function deletes flowtable entries matching the two mac addresses in all the switches"
            match = parser.OFPMatch(
                eth_src=addr1,
                eth_dst=addr2
            )

            instructions = []

            flow_del = datapath.ofproto_parser.OFPFlowmod(datapath,0,0, 0,
                                                          ofproto.OFPFC_DELETE, 0, 0,
                                                          1,
                                                          ofproto.OFPCML_NO_BUFFER,
                                                          ofproto.OFPP_ANY,
                                                          OFPG_ANY, 0,
                                                          match, instructions)
            print("Cancellazione Flow entries nello switch ", str(datapath.id))
            datapath.send_msg(flow_del)




        Dp_Flows = getFlowtable(dp_id)

        print('DOWNLOAD FLOWTABLE DEL DATAPATH %s', str(dp_id))
        print(Dp_Flows)
        print("NUMERO DATAPATH_ID --- ", dp_id, dp)
        print("#########NUMERO DI PORTA: ", port_no)

        port_str = 'OUTPUT:' + str(port_no)
        print("@@@@@@@@@@@      %s", port_str)
        mac1 = None
        mac2 = None

        for item in Dp_Flows[str(dp_id)]:
            if item['actions'][0] == port_str:

                print("MATCH di OUTPUT PORT!")
                mac1 = item['match']['dl_src']
                mac2 = item['match']['dl_dst']
                print(mac1, mac2)

                if (mac1 is not None) & (mac2 is not None):
                    for switch in get_all_switch(self):
                        delFlowmatch(mac1, mac2, switch)
                        delFlowmatch(mac2, mac1, switch)
                        print("MATCH! regola cancellata @@@@@@@@@@@@@@@")




    def find_destination_switch(self,destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None,None)

    def find_next_hop_to_destination(self, source_id, destination_id):
        net = nx.DiGraph()
        for link in get_all_link(self):
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




