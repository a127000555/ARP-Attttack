from scapy.all import *
# For escape pylint's bug
from scapy.layers.inet import IP, UDP, TCP, ICMP, Ether
from random import randint
import threading
import struct

def ip_to_num(ip):
    ip_split_list = list(map(int,ip.split('.')))
    assert len(ip_split_list) == 4

    ip_num =    (ip_split_list[0] << 24) + \
                (ip_split_list[1] << 16) + \
                (ip_split_list[2] << 8) + \
                (ip_split_list[3])

    return ip_num

def num_to_ip(num):
    ip_split_list = []

    while num != 0:
        ip_split_list += [ str(num & 0xff) ]
        num >>= 8
    
    return '.'.join(ip_split_list[::-1])

def get_ip_range(ip, scan_range = 20):
    # Input : ip - str
    
    if ip.startswith("192.168"):
        
        # except ip
        scan_range += 1

        # 192.168.0.0 private network
        low_bound = ip_to_num('192.168.0.0')

        # Note that .255.255 is boardcast.
        upp_bound = ip_to_num('192.168.255.255')
        target_ip_num = ip_to_num(ip)
    

        left = target_ip_num - scan_range // 2
        right = target_ip_num + scan_range // 2 + scan_range % 2

        if left < low_bound:
            fix = low_bound - left
            right += fix
            left += fix
        
        if right >= upp_bound:
            right = upp_bound - 1

        num_range_list = list(range(left,target_ip_num)) + \
                        list(range(target_ip_num+1,right)) 
        
        ip_range_list = list(map(num_to_ip,num_range_list))

        return ip_range_list

def get_alive_ip(interface, dst_ip_list, times = 10, verbose= True):

    # Try to bind the socket (Faster than send/sendp from scapy)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(0x0800))
    s.bind((interface,0))

    global now_counting

    alive_list = []
    now_counting = 0
    if verbose:
        print(f"Try to ping everyone in {times} times.")

    def send_ping(dst_ip):
        global now_counting
        id_ip = randint(1,65535)
        id_ping = randint(1,65535)
        for i in range(1,times+1):

            if dst_ip not in alive_list:

                packet = Ether()/IP(dst = dst_ip, id = id_ip)/ICMP(id = id_ping, seq = i)
                packet = bytes(packet)
                # magic data
                packet +=   b'\xc1\xaf\x07\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17' + \
                            b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27' + \
                            b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'

            s.send(packet)
            now_counting += 1

            if verbose:
                dash_num = int(now_counting / len(dst_ip_list) / 10 * 100)
                dot_num = 100 - dash_num
                statistics = f"{now_counting} / {len(dst_ip_list)*10}, find: {len(alive_list)}"
                output = '>' * dash_num + '.' * dot_num + '| ' + statistics
                print(output, end = '\r')

    threads = []
    for i, dst_ip in enumerate(dst_ip_list):
        
        threads.append(threading.Thread(target = send_ping, args = (dst_ip,)))
        threads[i].start()


    while now_counting != len(dst_ip_list) * times:

        pkt = s.recvfrom(1500)[0]
        storeobj = struct.unpack("!BBHHHBBH4s4s", pkt[14:34])
        ip_src = socket.inet_ntoa(storeobj[8])

        if ip_src in dst_ip_list and ip_src not in alive_list: 
            alive_list.append(ip_src)

    if verbose:
        print(f"\nresult: find {len(alive_list)} / {len(dst_ip_list)}: {alive_list}")

    return alive_list

