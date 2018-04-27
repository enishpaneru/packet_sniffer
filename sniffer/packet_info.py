from struct import *
from socket import *

class packet():
    def __init__(self, data):
        self.raw_data = data
        self.dst_mac, self.src_mac, self.eth_type, frame_unpacked_data = self.unpack_ether_frame(self.raw_data)
        # if ethernet type is 2048 i.e for ipv4 host byte order for little-endian is 8
        if self.eth_type == 8:
            self.version, self.hlen, self.ttl, self.protocol, self.src_ip, self.dst_ip, unpacked_ipv4_packet = self.unpack_ipv4_header(
                frame_unpacked_data)

            # for TCP protocol
            if self.protocol == 6:
                self.src_port, self.dst_port, self.sequence, self.acknowledgement, self.flags, \
                self.payload = self.unpack_tcp_header(unpacked_ipv4_packet)

            # for udp protocol
            if self.protocol == 17:
                self.src_port, self.dst_port, self.size, self.payload = self.unpack_udp_header(unpacked_ipv4_packet)

    def unpack_ether_frame(self, raw_data):
        mac_addr_list = []
        frame = unpack('! 6s 6s H', raw_data[:14])
        for each in frame[:2]:
            bytes_str = map('{:02x}'.format, each)

            address = ':'.join(bytes_str).upper()
            mac_addr_list.append(address)
        return mac_addr_list[0], mac_addr_list[1], htons(frame[2]), raw_data[14:]

    def unpack_ipv4_header(self, data):
        ver_hlen = data[0]
        version = ver_hlen >> 4
        hlen = (ver_hlen & 15) * 4
        ttl, protocol, src_ip, dst_ip = unpack('!B B 2x 4s 4s', data[8:20])
        return version, hlen, ttl, protocol, '.'.join(map(str, src_ip)), '.'.join(map(str, dst_ip)), data[hlen:]

    # Unpacks TCP header
    def unpack_tcp_header(self, data):
        src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        # flag_urg = (offset_reserved_flags & 32) >> 5
        # flag_ack = (offset_reserved_flags & 16) >> 4
        # flag_psh = (offset_reserved_flags & 8) >> 3
        # flag_rst = (offset_reserved_flags & 4) >> 2
        # flag_syn = (offset_reserved_flags & 2) >> 1
        # flag_fin = offset_reserved_flags & 1
        flags = (offset_reserved_flags & 255)
        return src_port, dest_port, sequence, acknowledgement, flags, \
               data[offset:]

    # Unpacks UDP header
    def unpack_udp_header(self, data):
        src_port, dest_port, size = unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

