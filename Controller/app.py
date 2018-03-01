from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
import time
import pox.lib.packet as pkt
from collections import defaultdict
log = core.getLogger()

array = defaultdict(dict)
#MAC addresses, IP addresses of web-server and authenticator
web_mac = EthAddr("00:21:9b:da:76:b3")
web_ip = IPAddr("192.168.2.1")
auth_mac = EthAddr("00:1b:21:23:35:28")
auth_ip = IPAddr("192.168.2.2")

#main function for handing packet_in request
class LearningSwitch (object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

  def _handle_PacketIn (self, event):
    global array
    global web_mac
    global web_ip
    global auth_mac
    global auth_ip
    packet = event.parsed

    #arp and topology information gathering code
    if packet.type == packet.ARP_TYPE:
      arp_packet = packet.payload
      src_ip = arp_packet.protosrc
      dst_ip = arp_packet.protodst
      src_mac = arp_packet.hwsrc
      dst_mac = arp_packet.hwdst
      msg = of.ofp_packet_out()
      msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("ff:ff:ff:ff:ff:ff")))
      msg.in_port = event.ofp.in_port 
      msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      msg.data = event.ofp.data
      self.connection.send(msg)
      array[event.dpid][src_mac]=event.port
      if src_ip == IPAddr("192.168.2.1"):
        print array
    
    #packet type ipv4 and ICMP 
    elif packet.type == packet.IP_TYPE: 
      ip_packet = packet.payload
      src_ip = ip_packet.srcip
      dst_ip = ip_packet.dstip
      src_mac = packet.src
      dst_mac = packet.dst
      #for ICMP packets
      if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
          print "icmp packet"
          print event.dpid
          print src_ip
          print dst_ip
          msg = of.ofp_packet_out()
          msg.in_port = event.ofp.in_port
          msg.actions.append(of.ofp_action_output(port = array[event.dpid][dst_mac]))
          msg.data = event.ofp.data
          self.connection.send(msg)

      #packet type ipv4 and TCP
      #redirection, authentication and modification of flow entries   
      if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
        tcp_packet = ip_packet.payload
        src_port = tcp_packet.srcport
        dst_port = tcp_packet.dstport
        if (dst_mac == web_mac and dst_ip == web_ip and dst_port == 80):
          x=time.clock()
          m = time.time()
          print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
          print(x,m)
          print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
  	      print "Request reached controller with destination mac as web-server and redirected to authenticator"
          print ("dpid of the ovs:",event.dpid)
          print ("source IP & Destination IP",src_ip,dst_ip)
          msg = of.ofp_packet_out()
          msg.actions.append(of.ofp_action_nw_addr.set_dst(auth_ip))
          msg.actions.append(of.ofp_action_dl_addr.set_dst(auth_mac))
          msg.in_port = event.ofp.in_port
          msg.actions.append(of.ofp_action_output(port = array[event.dpid][auth_mac]))
          msg.data = event.ofp.data
          self.connection.send(msg)
          y = time.clock()-x
          n = time.time()-m
          print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
          print (y,n)
          print ("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")

        elif (dst_mac == auth_mac and dst_ip == auth_ip and dst_port == 80):
          print "Request reached controller with destination mac as authenticator and send to authenticator"
          print ("dpid of the ovs:",event.dpid)
          print ("source IP & Destination IP",src_ip,dst_ip)
          msg = of.ofp_packet_out()
          msg.in_port = event.ofp.in_port
          msg.actions.append(of.ofp_action_output(port = array[event.dpid][auth_mac]))
          msg.data = event.ofp.data
          self.connection.send(msg)

        elif (src_mac == auth_mac and src_ip == auth_ip and src_port == 80):
          print ("Reply from authenticator")
          print ("dpid of the ovs:",event.dpid)
          print ("source IP & Destination IP",src_ip,dst_ip)
          print ("source MAC & Destination MAC",src_mac,dst_mac)
          msg = of.ofp_packet_out()
          msg.in_port = event.ofp.in_port
          msg.actions.append(of.ofp_action_nw_addr.set_dst(src_ip))
          msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr("ff:ff:ff:ff:ff:ff")))
          msg.actions.append(of.ofp_action_dl_addr.set_src(dst_mac))
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.data = event.ofp.data
          print ("authenticated packet Broadcasting")
          self.connection.send(msg)
          if (array[event.dpid][web_mac]!=array[event.dpid][dst_mac]):
            print ("Modifying flow-table")
            print ("dpid of the ovs:",event.dpid)
            print ("source IP & Destination IP",src_ip,dst_ip)
            print ("source MAC & Destination MAC",src_mac,dst_mac)
            self.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=array[event.dpid][web_mac]),
                                       match=of.ofp_match(dl_type=0x800,nw_proto=6,
                                                           dl_src=dst_mac,dl_dst=web_mac,tp_dst=80)))
            self.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=array[event.dpid][dst_mac]),
                                       match=of.ofp_match(dl_type=0x800,nw_proto=6,
                                                           dl_src=web_mac,dl_dst=dst_mac,tp_src=80)))
        elif (src_ip == auth_ip and dst_ip == auth_ip and src_port == 80):
          print ("Reply from authenticator")
          print ("dpid of the ovs:",event.dpid)
          print ("source IP & Destination IP",src_ip,dst_ip)
          print ("source MAC & Destination MAC",src_mac,dst_mac)
          msg = of.ofp_packet_out()
          msg.in_port = event.ofp.in_port
          msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
          msg.data = event.ofp.data
          print ("authenticated packet Broadcasting")
          self.connection.send(msg)
          if (array[event.dpid][web_mac]!=array[event.dpid][src_mac]):
            print ("Modifying flow-table")
            print ("dpid of the ovs:",event.dpid)
            print ("source IP & Destination IP",src_ip,dst_ip)
            print ("source MAC & Destination MAC",src_mac,dst_mac)
            self.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=array[event.dpid][web_mac]),
                                       match=of.ofp_match( dl_type=0x800,nw_proto=6,
                                                           dl_src=src_mac,dl_dst=web_mac,tp_dst=80)))
            self.connection.send( of.ofp_flow_mod( action=of.ofp_action_output( port=array[event.dpid][src_mac]),
                                       match=of.ofp_match( dl_type=0x800,nw_proto=6,
                                                           dl_src=web_mac,dl_dst=src_mac,tp_src=80)))
#first function , called by lauch
class l2_learning (object):
  def __init__ (self):
    core.openflow.addListeners(self)
  def _handle_ConnectionUp (self, event):
    log.debug("Connection starting .... %s" % (event.connection,))
    LearningSwitch(event.connection)

#launch function, it gets hit when you start the script
def launch ():
  core.registerNew(l2_learning)
