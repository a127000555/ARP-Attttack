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