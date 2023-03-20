import dpkt

import parser
import time

from scapy.all import *


def get_devices():
    # Return a list of all the devices detected on the machine
    devices = []
    for i in repr(conf.route).split('\n')[1:]:
        tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]', i).group()[0:44].rstrip()
        if len(tmp) > 0:
            devices.append(tmp)
    devices = list(set(devices))
    devices.sort()
    return devices


class Sniffer:
    def __init__(self):
        self.capture = None
        self.frame_index = 0

    def packet_callback(self, pkt_data):
        wrpcap('packet.pcap', [pkt_data])

        try:
            with open('packet.pcap', 'rb') as f:
                capture = dpkt.pcap.Reader(f)
                for timestamp, packet in capture:  # 键值对，提取packet进行解码
                    parser.parse(self.frame_index, timestamp, packet)
        except Exception as e:
            print(e)

    def start(self, device):
        while True:
            sniff(iface=device, prn=self.packet_callback, count=1)

    def stop(self):
        pass
