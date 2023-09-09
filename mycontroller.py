
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib import hub
import sys
import random
import time


class mycontroller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self,**kwargs):
        super(mycontroller, self).__init__(self,**kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.packet_count_max = 1000
      
        self.mac_packet_count = {}
      
     
        ###############################
        self.mac_ip = {}            #dict
        self.ddos_state=False
        self.dos_state=False
        self.src_of_DDOS =None 
        self.src_of_DOS =None
        self.wait_time_after_DOS = 0
        self.wait_time_after_DDOS = 0
        hub.spawn(self._monitor)
        hub.spawn(self._monitor2)
        
        ###############################

    def _monitor(self):
        while True:
            if(self.ddos_state ):
                self.wait_time_after_DDOS = self.wait_time_after_DDOS + 1
            else:
                self.wait_time_after_DDOS  = 0
            if(self.wait_time_after_DDOS > 30):
                self.mac_ip = {}            #dict
                self.ddos_state=False
                self.src_of_DDOS = 0
              
            hub.sleep(1)
            
    def _monitor2(self):
        while True:
            if(self.dos_state ):
                self.wait_time_after_DOS = self.wait_time_after_DOS + 1
            else:
                self.wait_time_after_DOS  = 0
            if(self.wait_time_after_DOS > 11):
                          
                self.dos_state=False
                self.src_of_DOS = 0
                self.mac_packet_count = {}
            hub.sleep(1)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg=ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

      
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0,cookie=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        cookie =random.randint(0, (2**64)-1) 
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst,cookie=cookie)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst,cookie=cookie)
            
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath	

        #register switch 		
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                print ('register datapath: ',  datapath.id)
                self.datapaths[datapath.id] = datapath

             #unregister switch 
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                print('unregister datapath: ', datapath.id)
                del self.datapaths[datapath.id]
				
				
		
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler (self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)


        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        if(self.src_of_DDOS == src) or self.src_of_DOS == src :

            return
       

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
		####################################
        #self.mac_ip_to_datapath.setdefault(src, {}) 

        self.mac_ip.setdefault(src, []) 
        #print("llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllll",self.mac_ip)
        
                  #src as key        
               #during DDOS        
		####################################

        self.logger.info("packet in  %s %s %s", src, dst, in_port)
        #print("list",self.mac_ip)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
      

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
       # print (f"the mac and port {self.mac_to_port[dpid][src]}")

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            #########################################################
            #print("list the ip ",self.mac_ip[src])
              if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                if len(self.mac_ip[src]) ==1 and srcip not in self.mac_ip[src]:
                   
                    print("the dic for atta:: ",self.mac_ip)
                    self.ddos_state=True
                    self.src_of_DDOS = src
                    print('attacker is:: ' ,src)
                    #print("list",self.mac_ip[src])
                    #print("AAAAAAAA",self.mac_ip)                   
                   # print("self.mac_ip[src]:", self.mac_ip[src])

                    #self.ddos_state=True
                    #self.src_of_DDOS = src
                    #print("DDos state from src ", src)
                    match1 = parser.OFPMatch( eth_dst=dst, eth_src=src)
                    #block src only with low priority
                    match2 = parser.OFPMatch( eth_src=src)    
                					
                    for dp in self.datapaths.values():
                        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                            self.add_flow(dp, 110, match1, [],msg.buffer_id, idle=30, hard=60)
                            self.add_flow(dp, 108, match2, [],msg.buffer_id, idle=30, hard=60)
							
                        else:
                            self.add_flow(dp, 110, match1, [],idle=30, hard=60)
                            self.add_flow(dp, 108, match2, [], idle=30, hard=60)
                   
                    return                                        
                           
                           
                           
                #detect dos attack 
                if src not in self.mac_packet_count:
                 self.mac_packet_count[src]= 0
            
            
                else:    
                  self.mac_packet_count[src] += 1
                if self.mac_packet_count[src] > self.packet_count_max:
                
            
                 
       # Take action to prevent the source from sending more data
                  self.dos_state=True
                  self.src_of_DOS = src
                  print("counter the packet ",self.mac_packet_count[src])
                  parser = datapath.ofproto_parser
                  match77 = parser.OFPMatch(  eth_src=src)
                  match88= parser.OFPMatch( eth_dst=dst, eth_src=src)
                  print(f"Dos state from src {src}")
           
                  for dp1 in self.datapaths.values():
                         if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                             self.add_flow(dp1, 250, match88, [],msg.buffer_id,idle=0, hard=0)
                             self.add_flow(dp1, 250, match77, [],msg.buffer_id,idle=0, hard=0)
                             
                         else:
                             self.add_flow(dp1, 250, match88, [],idle=0, hard=0)
                             self.add_flow(dp1, 250, match77, [],idle=0, hard=0)  

                 
                  return


                add_rule_to_switch =0
            # check IP Protocol and create a match for IP
            #if eth.ethertype == ether_types.ETH_TYPE_IP:
             #   ip = pkt.get_protocol(ipv4.ipv4)
              #  srcip = ip.src
               # dstip = ip.dst
                #protocol = ip.proto
               # print("list",self.mac_ip)
                #self.mac_ip_to_datapath[src][srcip]=0
                if srcip not in self.mac_ip[src]:

                    self.mac_ip[src].append(srcip)
                  
                  
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)
                    add_rule_to_switch =1


            
                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                  
                  #flags tcp header
                    if(t.bits >2):
                        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)                    
                        add_rule_to_switch 
            
                #  If UDP Protocol 
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port)            
                    add_rule_to_switch =1
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if  msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    if(add_rule_to_switch):
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id,idle =30, hard =60)
                    return
                else:
                    if(add_rule_to_switch):
                        self.add_flow(datapath, 1, match, actions,idle=30,hard =60)


                #packet out 
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        
        
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        
        datapath.send_msg(out)
        
        
        
        
        
        
        
        
        