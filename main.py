from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP, ICMP, Ether, ARP
from util import *
import scapy

interface = 'wlan0'
myMAC = get_if_hwaddr(interface)
myIP = get_if_addr(interface)
if_list = get_if_list()
 


ip_candidate = get_ip_range(myIP, 50)
get_alive_ip_and_mac(interface, ip_candidate)