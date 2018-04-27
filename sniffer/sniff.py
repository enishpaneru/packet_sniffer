from sniffer.packet_info import *

from time import time

def sniff(interface, protocol, duration):
    pk_list = []
    s = socket(AF_PACKET, SOCK_RAW, htons(protocol))
    s.bind((interface, 0))

    # if os.name == "nt":
    #     s.ioctl(SIO_RCVALL, RCVALL_ON)
    start_time = current_time = time()
    while current_time - start_time < duration:
        raw_data, _ = s.recvfrom(10000)
        pk = packet(raw_data)
        pk_list.append(pk)
        current_time = time()
