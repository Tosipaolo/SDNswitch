from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
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
        self.arp_table = {}
        self.sw = []
        self.SWITCH_LIST = []
        self.LINK_LIST = []
        self.HOST_LIST = []

    # execute at switch registration
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.sw.append(datapath)
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
            ofproto = datapath.ofproto
            match = datapath.ofproto_parser.OFPMatch(
                eth_src=addr1,
                eth_dst=addr2
            )

            instructions = []

            flow_del = datapath.ofproto_parser.OFPFlowMod(datapath,0,0, 0,
                                                          ofproto.OFPFC_DELETE, 0, 0,
                                                          1,
                                                          ofproto.OFPCML_NO_BUFFER,
                                                          ofproto.OFPP_ANY,
                                                          ofproto.OFPG_ANY, 0,
                                                          match, instructions)
            print("Cancellazione Flow entries nello switch ", str(datapath.id))
            datapath.send_msg(flow_del)

        Dp_Flows = getFlowtable(dp_id)

        print('DOWNLOAD FLOWTABLE DEL DATAPATH %s', str(dp_id))
        print(Dp_Flows)
        print("NUMERO DATAPATH_ID --- ", dp_id, dp)
        print("#########NUMERO DI PORTA: ", port_no)

        port_str = 'OUTPUT:' + str(port_no)
        print(port_str)
        mac1 = None
        mac2 = None

        for item in Dp_Flows[str(dp_id)]:
                print(item)
                for action in item['actions']:
                    print(action)
                    if port_str == action:
                        print("MATCH di OUTPUT PORT!")
                        mac1 = item['match']['dl_src']
                        mac2 = item['match']['dl_dst']
                        print(mac1, mac2)

                        if (mac1 is not None) & (mac2 is not None):
                            for switch in self.sw:
                                delFlowmatch(mac1, mac2, switch)
                                delFlowmatch(mac2, mac1, switch)
                                print("MATCH! regola cancellata @@@@@@@@@@@@@@@")


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        self.SWITCH_LIST = get_all_switch(self)
        self.LINK_LIST = get_all_link(self)
        self.HOST_LIST = get_all_host(self)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        assert eth is not None

        dst = eth.dst
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #        self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, out_port)

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        assert msg.buffer_id == ofproto.OFP_NO_BUFFER

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)

        # if the output port is not FLOODING
        # install a new flow rule *for the next packets*
        if out_port != ofproto.OFPP_FLOOD:
            # install a new flow rule
            match = parser.OFPMatch(
                eth_src=src,
                eth_dst=dst
            )
            inst = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]
            ofmsg = parser.OFPFlowMod(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=inst,
            )
            datapath.send_msg(ofmsg)
