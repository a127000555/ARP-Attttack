from scapy.all import *
from util import *

    
interface = 'wlan0'
myMAC = get_if_hwaddr(interface)
myIP = get_if_addr(interface)
if_list = get_if_list()



print("myMac" ,myMAC)
print("myIP" , myIP)
print("myIP" , if_list)
print(get_ip_range(myIP))