## TUGAS AKHIR ARISTEKTUR JARINGAN TERKINI <br></br> <br>Fauzan Ghozi Mubarak</br> <br>205150301111006</br> <br>Teknik Komputer</br>

# Table Of Contents

- [MEMBUAT EC2 INSTANCE di AWS ACADEMY](#membuat-ec2-instance-di-aws-academy)
- [MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2](#membuat-custom-topology-mininet-seperti-pada-tugas2)
- [MEMBUAT APLIKASI RYU LOAD BALANCER SEPERTI PADA TUGAS 3](#membuat-aplikasi-ryu-load-balancer-seperti-pada-tugas-3)
- [MEMBUAT APLIKASI RYU SHORTEST PATH ROUTING SEPERTI PADA TUGAS 4](#membuat-aplikasi-ryu-shortest-path-routing-seperti-pada-tugas-4)



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
<br> Dengan melakukan perintah ``` ssh -i labsuser.pem ubuntu@ipaddress``` </br>

![Screenshot from 2022-06-07 13-54-32](https://user-images.githubusercontent.com/83495936/172539424-5be6a254-6bb1-4a45-aff5-fc7117841a47.png)

- ### Setelah EC2 Instance siap, Selanjunta instalasi Mininet+OpenFlow, Ryu
<br> Langkah Pertama dengan mengupdate dan mengupgrade server ubuntu dengan perintah ``` sudo apt -yy update && sudo apt -yy upgrade```  </br>


![Screenshot from 2022-06-07 13-57-27](https://user-images.githubusercontent.com/83495936/172539980-c9303556-870e-4a19-906d-f29122ec253f.png)


<br> Langkah Kedua Unduh repository Mininet dengan perintah ``` git clone https://github.com/mininet/mininet ``` dan lakukan instalasi dengan perintah ``` mininet/util/install.sh -nfv``` </br>

<br> Langkah Ketiga Unduh repository RYU dengan perintah ``` git clone https://github.com/mininet/mininet```  dan lakukan instalasi dengan perintah ```cd ryu; pip install``` </br>

<br> Langkah Keempat Unduh repository Flow Manager dengan perintah ```git clone https://github.com/martimy/flowmanager ``` setelah selesai kita cek dengan perintah ```ls``` </br>



![Screenshot from 2022-06-07 14-06-25](https://user-images.githubusercontent.com/83495936/172542516-8d7b9a65-31a8-4931-9a5c-857d747a7d60.png)

## MEMBUAT CUSTOM TOPOLOGY MININET SEPERTI PADA TUGAS2

## Topology Mininet 2 host dan 2 switch


- ### Topolgy yang digunakan

![Screenshot from 2022-06-08 15-57-17](https://user-images.githubusercontent.com/83495936/172575987-d1532576-84d5-4495-849c-f43aed2dedf5.png)


- ### Source Code Yang Digunakan

```
#!/usr/bin/env python

"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.log import setLogLevel, info

class MyTopo( Topo ):

    def addSwitch(self, name, **opts ):
        kwargs = { 'protocols' : 'OpenFlow13'}
        kwargs.update( opts )
        return super(MyTopo, self).addSwitch( name, **kwargs )

    def __init__( self ):
        "Create MyTopo topology..."
        
        # Inisialisasi Topology
        Topo.__init__( self )

        # Tambahkan node, switch, dan host
        info( '*** Add switches\n')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        info( '*** Add hosts\n')
        h1 = self.addHost('h1', ip='10.1.0.1/24')
        h2 = self.addHost('h2', ip='10.1.0.2/24')
     
        info( '*** Add links\n')
        self.addLink(s1, h1, port1=1, port2=1)
        self.addLink(s1, s2, port1=2, port2=1)
        self.addLink(s2, h2, port1=2, port2=1)

topos = { 'mytopo': ( lambda: MyTopo() ) }

```

- ### Menjalankan mininet tanpa controller menggunakan custom topo yang anda sudah buat
``` sudo mn --controller=none --custom custom_topo_2sw2h.py --topo mytopo --mac --arp
```


![Screenshot from 2022-06-08 16-01-41](https://user-images.githubusercontent.com/83495936/172576915-ed54895d-95be-41d7-947f-73acfc2062d8.png)

- ### Membuat flow agar h1 dapat terhubung dengan h2
```
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=1,action=output:2"
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=2,action=output:1"
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=1,action=output:2"
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=2,action=output:1???
```

![Screenshot from 2022-06-08 16-05-25](https://user-images.githubusercontent.com/83495936/172577741-36c2f034-8ddc-4e70-b732-479684f3b5b3.png)

- ### Uji koneksi agar h1 dan h2 terhubung


![Screenshot from 2022-06-08 16-06-29](https://user-images.githubusercontent.com/83495936/172577994-816940b7-d6f5-4d1f-b5c7-e11403078f70.png)





## Topology Mininet 3 host dan 3 switch

- ### Topolgy yang digunakan


 ![Screenshot from 2022-06-08 13-17-19](https://user-images.githubusercontent.com/83495936/172545421-123c3add-bbb6-404c-9bcd-5fcf994a82f2.png)



- ### Program yang digunakan

```



#!/usr/bin/env python

"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.log import setLogLevel, info


class MyTopo( Topo ):

    def addSwitch(self, name, **opts ):
        kwargs = { 'protocols' : 'OpenFlow13'}
        kwargs.update( opts )
        return super(MyTopo, self).addSwitch( name, **kwargs )

    def __init__( self ):
        "Create MyTopo topology..."

        # Inisialisasi Topology
        Topo.__init__( self )

        # Tambahkan node, switch, dan host
        info( '*** Add switches\n')
        s1 = self.addSwitch('s1',protocols= 'OpenFlow13')
        s2 = self.addSwitch('s2',protocols= 'OpenFlow13')
        s3 = self.addSwitch('s3',protocols= 'OpenFlow13')

        info( '* Add hosts\n')
        h1 = self.addHost('h1', ip='10.1.0.1/24')
        h2 = self.addHost('h2', ip='10.1.0.2/24')
        h3 = self.addHost('h3', ip='10.2.0.3/24')
        h4 = self.addHost('h4', ip='10.2.0.4/24')
        h5 = self.addHost('h5', ip='10.3.0.5/24')
        h6 = self.addHost('h6', ip='10.3.0.6/24')

        info( '*** Add links\n')
        self.addLink(s1, h1, port1=2, port2=1)
        self.addLink(s1, h2, port1=3, port2=1)
        self.addLink(s2, h3, port1=3, port2=1)
        self.addLink(s2, h4, port1=4, port2=1)
        self.addLink(s3, h5, port1=2, port2=1)
        self.addLink(s3, h6, port1=1, port2=1)

        self.addLink(s3, s1, port1=3, port2=1)
        self.addLink(s3, s2, port1=4, port2=1)
        self.addLink(s1, s2, port1=4, port2=2)

topos = { 'mytopo': ( lambda: MyTopo() ) }

```


- ### Setelah itu akan menjalankan mininet tanpa controller menggunakan custom topo yang sudah dibuat
<br> Lakukan dengan perintah ```sudo mn --controller=none --custom custom_topo_2sw2h.py --topo mytopo --mac --arp```

![Screenshot from 2022-06-08 15-15-33](https://user-images.githubusercontent.com/83495936/172567255-8b906d91-82b0-4eea-aa47-bc0839d276ce.png)



- ### Membuat Flow agar h1,h2 dan h3 saling terhubung dengan perintah 
```
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=4,action=output:1"
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=1,action=output:4"
mininet> sh ovs-ofctl add-flow s3 -O OpenFlow13 "in_port=4,action=output:1"
mininet> sh ovs-ofctl add-flow s3 -O OpenFlow13 "in_port=1,action=output:4"
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=2,action=output:4"
mininet> sh ovs-ofctl add-flow s2 -O OpenFlow13 "in_port=4,action=output:2"
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=4,action=output:2"
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=2,action=output:4"
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=1,action=output:3"
mininet> sh ovs-ofctl add-flow s1 -O OpenFlow13 "in_port=3,action=output:1"
mininet> sh ovs-ofctl add-flow s3 -O OpenFlow13 "in_port=3,action=output:1"
mininet> sh ovs-ofctl add-flow s3 -O OpenFlow13 "in_port=1,action=output:3"
```

![Screenshot from 2022-06-08 15-24-03](https://user-images.githubusercontent.com/83495936/172568948-f303bbd2-9652-4bf7-b4ee-7184da32ba8a.png)




- ### Melihat flow dengan perintah

```dpctl dump-flows -O OpenFlow13```

![Screenshot from 2022-06-08 15-26-56](https://user-images.githubusercontent.com/83495936/172569712-9b387acf-8dfd-4b13-af0f-9568e23c5a3c.png)







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


```
self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02",
"outport":"2"}) 

self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03",
"outport":"3"}) 

self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04",
"outport":"4"}) 
```


![Screenshot from 2022-06-08 15-38-39](https://user-images.githubusercontent.com/83495936/172572523-df2b6b87-cb22-4837-9ebf-31ab792906ea.png)



### Melakukan perintah pada console pertama 
```ryu-manager``` 


![Screenshot from 2022-04-10 15-53-58](https://user-images.githubusercontent.com/83495936/172579401-4b54df52-7dd6-43f3-a3dd-4dd774611055.png)




### Melakukan perintah pada console kedua 
```sudo mn --controller=remote --topo single,4 ???mac ```


![Screenshot from 2022-04-10 15-53-58](https://user-images.githubusercontent.com/83495936/172579401-4b54df52-7dd6-43f3-a3dd-4dd774611055.png)


### Web Server Memberikan Packet ke CLient

Pada bagian h2,h3,h4 akan menjadi web server dan memberikan paket ke client yaitu h1. Pada sisi h1 melakukan akses ke webserver dan didapati dengan algoritma round robin yang memberikan paket ke h1 adalah server h2 dengan ip 10.0.0.2

![Screenshot from 2022-04-10 15-58-22](https://user-images.githubusercontent.com/83495936/172579471-471f1797-0485-473e-9f06-8288b7c1d126.png)


### Melakukan akses kembali ke webserver 

<br> Melakukan akses ke webserver dengan  h1 berulang kali untuk memastikan algoritma Round-Robin berjalan dengan baik dan melakukan ```dpctl dump-flows -O openflow13``` untuk melihat flow </br>



![Screenshot from 2022-04-10 16-07-06](https://user-images.githubusercontent.com/83495936/172579495-28041daa-ba33-493e-ba6f-657b6a493504.png)



## MEMBUAT APLIKASI RYU SHORTEST PATH ROUTING SEPERTI PADA TUGAS 4


### Topology yang digunakan

![Screenshot from 2022-06-08 14-31-22](https://user-images.githubusercontent.com/83495936/172558321-1c30c48a-c7c0-4fab-9c3d-2bc7b5207360.png)

### Source Code yang digunakan 

```
rom ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER,
MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
# switches
switches = []
# mymacs[srcmac]->(switch, port)
mymacs = {}
# adjacency map [sw1][sw2]->port from sw1 to sw2
adjacency = defaultdict(lambda:defaultdict(lambda:None))
# getting the node with lowest distance in Q
def minimum_distance(distance, Q):
min = float('Inf')
node = 0
for v in Q:
if distance[v] < min:
min = distance[v]
node = v
return node
def get_path (src, dst, first_port, final_port):
# executing Dijkstra's algorithm
print( "get_path function is called, src=", src," dst=", dst, " first_port=",
first_port, " final_port=", final_port)
# defining dictionaries for saving each node's distance and its previous
node in the path from first node to that node
distance = {}
previous = {}
# setting initial distance of every node to infinityfor dpid in switches:
distance[dpid] = float('Inf')
previous[dpid] = None
# setting distance of the source to 0
distance[src] = 0
# creating a set of all nodes
Q = set(switches)
# checking for all undiscovered nodes whether there is a path that goes
through them to their adjacent nodes which will make its adjacent nodes
closer to src
while len(Q) > 0:
# getting the closest node to src among undiscovered nodes
u = minimum_distance(distance, Q)
# removing the node from Q
Q.remove(u)
# calculate minimum distance for all adjacent nodes to u
for p in switches:
# if u and other switches are adjacent
if adjacency[u][p] != None:
# setting the weight to 1 so that we count the number of routers in the
path
w = 1
# if the path via u to p has lower cost then make the cost equal to this
new path's cost
if distance[u] + w < distance[p]:
distance[p] = distance[u] + w
previous[p] = u
# creating a list of switches between src and dst which are in the shortest
path obtained by Dijkstra's algorithm reversely
r = []
p = dst
r.append(p)
# set q to the last node before dst
q = previous[p]
while q is not None:
if q == src:
r.append(q)
break
p = q
r.append(p)
q = previous[p]
# reversing r as it was from dst to src
r.reverse()
# setting pathif src == dst:
path=[src]
else:
path=r
# Now adding in_port and out_port to the path
r = []
in_port = first_port
for s1, s2 in zip(path[:-1], path[1:]):
out_port = adjacency[s1][s2]
r.append((s1, in_port, out_port))
in_port = adjacency[s2][s1]
r.append((dst, in_port, final_port))
return r
class ProjectController(app_manager.RyuApp):
OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
def __init__(self, *args, **kwargs):
super(ProjectController, self).__init__(*args, **kwargs)
self.topology_api_app = self
self.datapath_list = []
def install_path(self, p, ev, src_mac, dst_mac):
print("install_path function is called!")
#print( "p=", p, " src_mac=", src_mac, " dst_mac=", dst_mac)
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# adding path to flow table of each switch inside the shortest path
for sw, in_port, out_port in p:
#print( src_mac,"->", dst_mac, "via ", sw, " in_port=", in_port, "
out_port=", out_port)
# setting match part of the flow table
match = parser.OFPMatch(in_port=in_port, eth_src=src_mac,
eth_dst=dst_mac)
# setting actions part of the flow table
actions = [parser.OFPActionOutput(out_port)]
# getting the datapath
datapath = self.datapath_list[int(sw)-1]
# getting instructions based on the actions
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS ,
actions)]
mod = datapath.ofproto_parser.OFPFlowMod(datapath=datapath,
match=match, idle_timeout=0, hard_timeout=0,
priority=1, instructions=inst)
# finalizing the change to switch datapath
datapath.send_msg(mod)# defining event handler for setup and configuring of switches
@set_ev_cls(ofp_event.EventOFPSwitchFeatures , CONFIG_DISPATCHER)
def switch_features_handler(self , ev):
print("switch_features_handler function is called")
# getting the datapath, ofproto and parser objects of the event
datapath = ev.msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# setting match condition to nothing so that it will match to anything
match = parser.OFPMatch()
# setting action to send packets to OpenFlow Controller without buffering
actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
ofproto.OFPCML_NO_BUFFER)]
inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS ,
actions)]
# setting the priority to 0 so that it will be that last entry to match any
packet inside any flow table
mod = datapath.ofproto_parser.OFPFlowMod(
datapath=datapath, match=match, cookie=0,
command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
priority=0, instructions=inst)
# finalizing the mod
datapath.send_msg(mod)
# defining an event handler for packets coming to switches event
@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
def _packet_in_handler(self, ev):
# getting msg, datapath, ofproto and parser objects
msg = ev.msg
datapath = msg.datapath
ofproto = datapath.ofproto
parser = datapath.ofproto_parser
# getting the port switch received the packet with
in_port = msg.match['in_port']
# creating a packet encoder/decoder class with the raw data obtained by
msg
pkt = packet.Packet(msg.data)
# getting the protocl that matches the received packet
eth = pkt.get_protocol(ethernet.ethernet)
# avoid broadcasts from LLDP
if eth.ethertype == 35020 or eth.ethertype == 34525:
return
# getting source and destination of the link
dst = eth.dst
src = eth.src
dpid = datapath.id
print("packet in. src=", src, " dst=", dst," dpid=", dpid)# add the host to the mymacs of the first switch that gets the packet
if src not in mymacs.keys():
mymacs[src] = (dpid, in_port)
print("mymacs=", mymacs)
# finding shortest path if destination exists in mymacs
if dst in mymacs.keys():
print("destination is known.")
p = get_path(mymacs[src][0], mymacs[dst][0], mymacs[src][1],
mymacs[dst][1])
self.install_path(p, ev, src, dst)
print("installed path=", p)
out_port = p[0][2]
else:
print("destination is unknown.Flood has happened.")
out_port = ofproto.OFPP_FLOOD
# getting actions part of the flow table
actions = [parser.OFPActionOutput(out_port)]
data = None
if msg.buffer_id == ofproto.OFP_NO_BUFFER:
data = msg.data
out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
in_port=in_port,
actions=actions, data=data)
datapath.send_msg(out)
# defining an event handler for adding/deleting of switches, hosts, ports
and links event
events = [event.EventSwitchEnter,
event.EventSwitchLeave, event.EventPortAdd,
event.EventPortDelete, event.EventPortModify,
event.EventLinkAdd, event.EventLinkDelete]
@set_ev_cls(events)
def get_topology_data(self, ev):
global switches
print("get_topology_data is called.")
# getting the list of known switches
switch_list = get_switch(self.topology_api_app, None)
switches = [switch.dp.id for switch in switch_list]
print("current known switches=", switches)
# getting the list of datapaths from the list of switches
self.datapath_list = [switch.dp for switch in switch_list]
# sorting the datapath list based on their id so that indexing them in
install_function will be correct
self.datapath_list.sort(key=lambda dp: dp.id)
# getting the list of links between switcheslinks_list = get_link(self.topology_api_app, None)
mylinks = [(link.src.dpid,link.dst.dpid,link.src.port_no,link.dst.port_no) for
link in links_list]
# setting adjacency of nodes
for s1, s2, port1, port2 in mylinks:
adjacency[s1][s2] = port1
adjacency[s2][s1] =
```

### Pada Terminal Console satu jalankan 

```
ryu-manager --observe-links dijkstra_Ryu_controller.py
```

![Screenshot from 2022-04-28 19-57-33](https://user-images.githubusercontent.com/83495936/172581484-55620e83-a0b2-45ea-9052-6c3644f8b342.png)







### Pada Terminal Console dua jalankan 
```
sudo python3 topo-spf_lab.py

```
![Screenshot from 2022-04-28 19-58-47](https://user-images.githubusercontent.com/83495936/172581574-fe596788-a43d-4b8c-b3ea-19cf2b920dd7.png)


### Melakukan cek Konektivitas

```
pingall

```

<br>Pada Percobaan Pertama Pingall tidak semua paket terkirim
Hal ini dikarenakan pada saat awal melakukan pingall masih proses
melakukan komputasi sehingga seluruh paket tidak terkirim </br>

![Screenshot from 2022-04-28 20-04-07](https://user-images.githubusercontent.com/83495936/172581658-ced6eaf5-6f17-4882-9c55-4825fa1b8d81.png)

<br>Pada Percobaan Kedua Pingall semua paket terkirim</br>

![Screenshot from 2022-04-28 20-04-16](https://user-images.githubusercontent.com/83495936/172581717-175c0a93-110a-45d7-a946-0e9eee5743cb.png)


### Mengecek Flow dengan melakukan perintah dpctl dump-flows -O openflow13

<br> Pada hal ini semua Flow sudah tertanam pada semua switchnya untuk
semua tujuan sesuai dengan Topology. Pada perintah ini kita bisa melihat jalur node yang akan dilalui dengan algoritma Shortest Path Routing, dimana algoritma tersebut mencari rute terpendek.


![Screenshot from 2022-04-28 20-09-11](https://user-images.githubusercontent.com/83495936/172582079-d61ddef9-1cc8-4451-a9c7-5fcba3cb1fc1.png)

![Screenshot from 2022-04-28 20-09-31](https://user-images.githubusercontent.com/83495936/172582137-146707ff-37c7-4a1a-951a-737b5d707124.png)

![Screenshot from 2022-04-28 20-09-36](https://user-images.githubusercontent.com/83495936/172582167-062897aa-275f-4610-907c-3df01b1f3c2f.png)

