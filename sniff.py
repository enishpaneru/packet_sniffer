from socket import *
from struct import *

interface = 'wlp6s0'
s = socket(AF_PACKET, SOCK_RAW, ntohs(3))
s.bind((interface, 0))


# if os.name == "nt":
#     s.ioctl(SIO_RCVALL, RCVALL_ON)

def unpack_ether_frame(raw_data):
    mac_addr_list = []
    frame = unpack('! 6s 6s H', raw_data[:14])
    for each in frame[:2]:
        bytes_str = map('{:02x}'.format, each)

        address = ':'.join(bytes_str).upper()
        mac_addr_list.append(address)
    return mac_addr_list[0], mac_addr_list[1], htons(frame[2]), raw_data[14:]


def unpack_ipv4_header(data):
    ver_hlen = data[0]
    version = ver_hlen >> 4
    hlen = (ver_hlen & 15) * 4
    ttl, protocol, src_ip, dst_ip = unpack('!B B 2x 4s 4s', data[8:20])
    return version, hlen, ttl, protocol, '.'.join(map(str, src_ip)), '.'.join(map(str, dst_ip)),data[hlen:]

# Unpacks TCP header
def unpack_tcp_header(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,\
           data[offset:]

# Unpacks UDP header
def unpack_udp_header(data):
    src_port, dest_port, size = unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

while True:
    raw_data, _ = s.recvfrom(10000)
    dst_mac, src_mac, eth_type, frame_unpacked_data = unpack_ether_frame(raw_data)
    print(dst_mac, src_mac, eth_type)

    # if ethernet type is 2048 i.e for ipv4 host byte order for little-endian is 8
    if eth_type == 8:
        parsed_ipv4_packet=unpack_ipv4_header(frame_unpacked_data)
        print(parsed_ipv4_packet[:-1])

        # for TCP protocol
        if parsed_ipv4_packet[3]==6:
            parsed_tcp_packet=unpack_tcp_header(parsed_ipv4_packet[6])
            print(parsed_tcp_packet[:10])
            print("Payload",parsed_tcp_packet[10])

        # for udp protocol
        if parsed_ipv4_packet[3]==17:
            parsed_udp_packet = unpack_udp_header(parsed_ipv4_packet[6])
            print(parsed_udp_packet[:2])
            print("Payload",parsed_udp_packet[2])



