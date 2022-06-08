## TUGAS AKHIR ARISTEKTUR JARINGAN TERKINI 

# Table Of Contents

- [MEMBUAT EC2 INSTANCE di AWS ACADEMY](#membuat-ec2-instance-di-aws-academy)
- [MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2](#membuat-custom-topology-mininet-seperti-pada-tugas2)
- [MEMBUAT APLIKASI RYU LOAD BALANCER SEPERTI PADA TUGAS 3](#membuat-aplikasi-ryu-load-balancer-seperti-pada-tugas-3)




## MEMBUAT EC2 INSTANCE di AWS ACADEMY
Pada Ketentuan tugas Kita akan membuat akun EC2 INSTANCE dengan spesifikasi sebagai berikut
- Name and tags	= Tugas Akhir
- OS Images	= Ubuntu Server 22.04 LTS 64 bit
- Instance type	= t2.medium
- Key pair	= vockey
- Edit Network settings	= allow SSH, allow HTTP, allow HTTPS, allow TCP port 8080, allow TCP port 8081
- Configure storage	= 30 GiB, gp3


![Screenshot from 2022-06-07 13-40-04](https://user-images.githubusercontent.com/83495936/172538348-95fb5e09-5cbb-47da-95aa-714586f75dc0.png)


![Screenshot from 2022-06-07 13-40-13](https://user-images.githubusercontent.com/83495936/172538546-d7891727-138a-4c47-a70c-eee8fcbe9c04.png)


![Screenshot from 2022-06-07 13-40-20](https://user-images.githubusercontent.com/83495936/172538590-c31be9e6-cef6-438d-b786-6227f6ddacb2.png)

![Screenshot from 2022-06-07 13-40-34](https://user-images.githubusercontent.com/83495936/172538607-85841ed0-52c9-4f0e-bb06-cc9c17ff6dd3.png)

![Screenshot from 2022-06-07 13-40-37](https://user-images.githubusercontent.com/83495936/172538637-555f1387-4f73-4fc1-958e-c475d21e7354.png)

![Screenshot from 2022-06-07 13-41-10](https://user-images.githubusercontent.com/83495936/172538678-635fde78-47df-4748-8147-21a8eb170b09.png)

- ### Setelah Selesai Melakukan Konfigurasi EC2, Saya akan menghubungkannya dengan terminal ubuntu
<br> Dengan melakukan perintah ssh -i labsuser.pem ubuntu@ipaddress </br>

![Screenshot from 2022-06-07 13-54-32](https://user-images.githubusercontent.com/83495936/172539424-5be6a254-6bb1-4a45-aff5-fc7117841a47.png)

- ### Setelah EC2 Instance siap, Selanjunta instalasi Mininet+OpenFlow, Ryu
<br> Langkah Pertama dengan mengupdate dan mengupgrade server ubuntu dengan perintah sudo apt -yy update && sudo apt -yy upgrade  </br>


![Screenshot from 2022-06-07 13-57-27](https://user-images.githubusercontent.com/83495936/172539980-c9303556-870e-4a19-906d-f29122ec253f.png)


<br> Langkah Kedua Unduh repository Mininet dengan perintah git clone https://github.com/mininet/mininet  dan lakukan instalasi dengan perintah mininet/util/install.sh -nfv </br>

<br> Langkah Ketiga Unduh repository RYU dengan perintah git clone https://github.com/mininet/mininet  dan lakukan instalasi dengan perintah cd ryu; pip install </br>

<br> Langkah Keempat Unduh repository Flow Manager dengan perintah git clone https://github.com/martimy/flowmanager  setelah selesai kita cek dengan perintah ls </br>



![Screenshot from 2022-06-07 14-06-25](https://user-images.githubusercontent.com/83495936/172542516-8d7b9a65-31a8-4931-9a5c-857d747a7d60.png)

## MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2

- ### Topolgy yang digunakan


 ![Screenshot from 2022-06-08 13-17-19](https://user-images.githubusercontent.com/83495936/172545421-123c3add-bbb6-404c-9bcd-5fcf994a82f2.png)



- ### Program yang digunakan


- ### Setelah itu akan menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
<br> Lakukan dengan perintah sudo mn --controller=none --custom custom_topo_2sw2h.py --topo mytopo --mac --arp


- ### Membuat Flow agar h1,h2 dan h3 saling terhubung dengan perintah 


- ### Melakuka Uji Koneksi


## MEMBUAT APLIKASI RYU LOAD BALANCER SEPERTI PADA TUGAS 3


- ### Topolgy yang digunakan



![Screenshot from 2022-06-08 13-41-57](https://user-images.githubusercontent.com/83495936/172551474-cc26435a-4aff-4cf4-8c34-2d16da56d352.png)



- ### Program yang digunakan

```
# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#Reference:
https://bitbucket.org/sdnhub/ryu-starter-kit/src/7a162d81f97d080c10beb
15d8653a8e0eff8a469/stateless_lb.py?at=master&fileviewer=file-view-
default
import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,
MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, arp, tcp, ipv4
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
#from ryu.app.sdnhub_apps import learning_switch
class SimpleSwitch13(app_manager.RyuApp):
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
def __init__(self, *args, **kwargs):
super(SimpleSwitch13, self).__init__(*args, **kwargs)
self.mac_to_port = {}
self.serverlist=[] #Creating a list of servers
self.virtual_lb_ip = "10.0.0.100" #Virtual Load Balancer IP
self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC" #Virtual Load Balancer MAC
Address
self.counter = 0 #Used to calculate mod in server selection belowself.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02",
"outport":"2"}) #Appending all given IP's, assumed MAC's and ports of
switch to which servers are connected to the list created
self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03",
"outport":"3"})
self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04",
"outport":"4"})
print("Done with initial setup related to server list creation.")
@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
def switch_features_handler(self, ev):
datapath = ev.msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# install table-miss flow entry
#
# We specify NO BUFFER to max_len of the output action due to
# OVS bug. At this moment, if we specify a lesser number, e.g.,
# 128, OVS will send Packet-In with invalid buffer_id and
# truncated packet data. In that case, we cannot output packets
# correctly. The bug has been fixed in OVS v2.1.0.
match = parser.OFPMatch()
actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
ofproto.OFPCML_NO_BUFFER)]
self.add_flow(datapath, 0, match, actions)
def add_flow(self, datapath, priority, match, actions, buffer_id=None):
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
if buffer_id:
mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
priority=priority, match=match,
instructions=inst)
else:
mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
match=match, instructions=inst)
datapath.send_msg(mod)
def function_for_arp_reply(self, dst_ip, dst_mac): #Function placed here,
source MAC and IP passed from below now become the destination for
the reply ppacket
print("(((Entered the ARP Reply function to build a packet and reply back
appropriately)))")
arp_target_ip = dst_ip
arp_target_mac = dst_mac
src_ip = self.virtual_lb_ip #Making the load balancers IP and MAC assource IP and MAC
src_mac = self.virtual_lb_mac
arp_opcode = 2 #ARP opcode is 2 for ARP reply
hardware_type = 1 #1 indicates Ethernet ie 10Mb
arp_protocol = 2048 #2048 means IPv4 packet
ether_protocol = 2054 #2054 indicates ARP protocol
len_of_mac = 6 #Indicates length of MAC in bytes
len_of_ip = 4 #Indicates length of IP in bytes
pkt = packet.Packet()
ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)
#Dealing with only layer 2
arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac,
len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip) #Building
the ARP reply packet, dealing with layer 3
pkt.add_protocol(ether_frame)
pkt.add_protocol(arp_reply_pkt)
pkt.serialize()
print("{{{Exiting the ARP Reply Function as done with processing for ARP
reply packet}}}")
return pkt
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
# If you hit this you might want to increase
# the "miss_send_length" of your switch
if ev.msg.msg_len < ev.msg.total_len:
self.logger.debug("packet truncated: only %s of %s bytes",
ev.msg.msg_len, ev.msg.total_len)
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
in_port = msg.match['in_port']
dpid = datapath.id
#print("Debugging purpose dpid", dpid)
pkt = packet.Packet(msg.data)
eth = pkt.get_protocols(ethernet.ethernet)[0]
if eth.ethertype == ether_types.ETH_TYPE_LLDP:
# ignore lldp packet
return
if eth.ethertype == ether.ETH_TYPE_ARP: #If the ethernet frame has eth
type as 2054 indicating as ARP packet..
arp_header = pkt.get_protocols(arp.arp)[0]
if arp_header.dst_ip == self.virtual_lb_ip and arp_header.opcode ==
arp.ARP_REQUEST: #..and if the destination is the virtual IP of the load
balancer and Opcode = 1 indicating ARP Requestreply_packet=self.function_for_arp_reply(arp_header.src_ip,
arp_header.src_mac) #Call the function that would build a packet for ARP
reply passing source MAC and source IP
actions = [parser.OFPActionOutput(in_port)]
packet_out = parser.OFPPacketOut(datapath=datapath,
in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions,
buffer_id=0xffffffff)
datapath.send_msg(packet_out)
print("::::Sent the packet_out::::")
"""else: #Not needed as we ARP only for the load balancer MAC address.
This is needed when we ARP for other device's MAC
dst = eth.dst
src = eth.src
self.mac_to_port.setdefault(dpid, {})
self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
# learn a mac address to avoid FLOOD next time.
self.mac_to_port[dpid][src] = in_port
if dst in self.mac_to_port[dpid]:
out_port = self.mac_to_port[dpid][dst]
else:
out_port = ofproto.OFPP_FLOOD
actions = [parser.OFPActionOutput(out_port)]
# install a flow to avoid packet_in next time
if out_port != ofproto.OFPP_FLOOD:
match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
# verify if we have a valid buffer_id, if yes avoid to send both
# flow_mod & packet_out
if msg.buffer_id != ofproto.OFP_NO_BUFFER:
self.add_flow(datapath, 1, match, actions, msg.buffer_id)
return
else:
self.add_flow(datapath, 1, match, actions)
data = None
if msg.buffer_id == ofproto.OFP_NO_BUFFER:
data = msg.data
out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
in_port=in_port, actions=actions, data=data)
datapath.send_msg(out)"""
return
ip_header = pkt.get_protocols(ipv4.ipv4)[0]
#print("IP_Header", ip_header)
tcp_header = pkt.get_protocols(tcp.tcp)[0]
#print("TCP_Header", tcp_header)
count = self.counter % 3 #Round robin fashion setup
server_ip_selected = self.serverlist[count]['ip']
server_mac_selected = self.serverlist[count]['mac']
server_outport_selected = self.serverlist[count]['outport']server_outport_selected = int(server_outport_selected)
self.counter = self.counter + 1
print("The selected server is ===> ", server_ip_selected)
#Route to server
match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_header.proto,
ipv4_src=ip_header.src, ipv4_dst=ip_header.dst,
tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)
actions = [parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
parser.OFPActionSetField(eth_dst=server_mac_selected),
parser.OFPActionSetField(ipv4_dst=server_ip_selected),
parser.OFPActionOutput(server_outport_selected)]
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
cookie = random.randint(0, 0xffffffffffffffff)
flow_mod = parser.OFPFlowMod(datapath=datapath, match=match,
idle_timeout=7, instructions=inst, buffer_id = msg.buffer_id,
cookie=cookie)
datapath.send_msg(flow_mod)
print("<========Packet from client: "+str(ip_header.src)+". Sent to
server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+"
and on switch port: "+str(server_outport_selected)+"========>")
#Reverse route from server
match = parser.OFPMatch(in_port=server_outport_selected,
eth_type=eth.ethertype, eth_src=server_mac_selected,
eth_dst=self.virtual_lb_mac, ip_proto=ip_header.proto,
ipv4_src=server_ip_selected, ipv4_dst=self.virtual_lb_ip,
tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
parser.OFPActionSetField(ipv4_dst=ip_header.src),
parser.OFPActionSetField(eth_dst=eth.src),
parser.OFPActionOutput(in_port)]
inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
actions)]
cookie = random.randint(0, 0xffffffffffffffff)
flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match,
idle_timeout=7, instructions=inst2, cookie=cookie)
datapath.send_msg(flow_mod2)
print("<++++++++Reply sent from server: "+str(server_ip_selected)+",
MAC: "+str(server_mac_selected)+". Via load balancer:
"+str(self.virtual_lb_ip)+".
```

### Memodifikasi Source Code pada sisi server dengan ip, mac dan outport sebagai berikut dan menentukan virtual ip server: 10.0.0.100

<br>self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02",
"outport":"2"}) </br>

<br>self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03",
"outport":"3"}) </br>

<br>self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04",
"outport":"4"}) </br>



