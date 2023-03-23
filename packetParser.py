import pickle

import dpkt
from scapy.all import *


# frame_index = 0

class PacketParser:
    def __init__(self, frame_index):
        self.frame_index = frame_index
        self.info = {'index': None, 'timestamp': None, 'time': None, 'curTime': None, 'dst': None, 'src': None,
                     'protocol': None, 'len': None, 'info': '', 'pktData': None}
        # 数据链路层 Ethernet
        self.layer1 = {'name': None, 'smac': None, 'dmac': None, 'type': None}
        # 网络层 IPv4 (IPv6 ARP
        self.layer2 = {'name': None, 'src': None, 'dst': None, 'version': None, 'headerLen': None,
                       'headerLenBytes': None, 'tos': None, 'totLen': None, 'identification': None, 'flags': None,
                       'rf': None, 'df': None, 'mf': None, 'offset': None, 'ttl': None, 'protocol': None,
                       'checksum': None, 'trafficClass': None, 'ecn': None, 'dsc': None, 'flowLab': None,
                       'payloadLen': None, 'nxtHeader': None, 'hopLim': None}
        # 传输层 TCP UDP (ICMP
        self.layer3 = {'name': None, 'sport': None, 'dport': None, 'seq': None, 'ack': None, 'headerLen': None,
                       'headerLenBytes': None, 'flags': None, 'rf': None, 'ecn': None, 'cwr': None, 'ece': None,
                       'urg': None, 'ackFlag': None, 'psh': None, 'rst': None, 'syn': None, 'fin': None, 'window': None,
                       'checksum': None, 'urp': None, 'opts': None, 'payload': None}
        # 应用层 HTTP (HTTPS TLS DNS SSL FTP SSDP QUIC
        self.layer4 = {'name': None, 'method': None, 'url': None, 'version': None, 'headers': None, 'host': None,
                       'userAgent': None, 'body': None, 'statusCode': None, 'responsePhrase': None}

    # 抓包监听
    def packet_callback(self, pkt_data):
        wrpcap('packet.pcap', [pkt_data])

        # global frame_index
        frame_index = 0
        frame_index += 1

        try:
            with open('packet.pcap', 'rb') as f:
                capture = dpkt.pcap.Reader(f)
                for timestamp, packet in capture:  # 键值对，提取packet进行解码
                    self.parse(frame_index, timestamp, packet)
        except Exception as e:
            print(e)

    def parse(self, timestamp, pkt_data, start_time):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))
        pkt_time = timestamp - start_time
        pkt_len = len(pkt_data)  # bytes

        self.info['index'] = str(self.frame_index)
        self.info['timestamp'] = str(timestamp)
        self.info['time'] = str(pkt_time)
        self.info['curTime'] = current_time
        self.info['len'] = str(pkt_len)
        self.info['pktData'] = pkt_data

        output1 = {'Frame': self.frame_index}
        output2 = {'time': current_time}
        output3 = {'len': pkt_len}
        print()
        print(timestamp)
        print(output1)
        print(output2)
        print(output3)

        eth = dpkt.ethernet.Ethernet(pkt_data)
        self.parse_layer1(eth)

    def parse_layer1(self, eth):  # 数据链路层
        smac = ":".join(["%02x" % (b) for b in eth.src])
        dmac = ":".join(["%02x" % (b) for b in eth.dst])
        packet_type = type(eth)  # Ethernet
        data_protocol = eth.type

        if data_protocol == 0x0800:  # IP
            data_protocol = 'IPv4 (0x0800)'

        self.layer1['name'] = 'Ethernet'
        self.layer1['smac'] = smac
        self.layer1['dmac'] = dmac
        self.layer1['type'] = data_protocol

        # 输出数据包信息
        output1 = packet_type
        output2 = {'smac': smac, 'dmac': dmac}
        output3 = {'type': data_protocol}
        print(output1)
        print(output2)
        print(output3)

        self.parse_layer2(eth.data)

    def parse_layer2(self, packet):  # 网络层
        packet_type = type(packet)  # IPv4

        # 判断数据报类型
        if isinstance(packet, dpkt.ip.IP):  # IPv4
            # 取出分片信息
            src = packet.src
            print(type(src))
            print(src)
            src = '%d.%d.%d.%d' % tuple(src)
            dst = packet.dst
            dst = '%d.%d.%d.%d' % tuple(dst)
            version = packet.v
            head_len = packet.hl
            head_len_bytes = head_len * 4
            differentiated_services = '0x{:02x}'.format(packet.tos)
            packet_len = packet.len  # 首部+数据
            identification = packet.id
            rf = packet.rf  # Reserved bit
            df = packet.df  # don't fragment
            mf = packet.mf  # more fragments (not last frag)
            flags = str(rf) + str(df) + str(mf)
            flags = hex(int(flags, 2))
            offset = packet.offset
            ttl = packet.ttl
            protocol = packet.p  # tcp udp
            if protocol == 6:  # TCP
                protocol = 'TCP (6)'
            elif protocol == 17:  # UDP
                protocol = 'UDP (17)'
            elif protocol == 1:  # ICMP
                protocol = 'UDP (1)'
            pkt_checksum = '0x{:04x}'.format(packet.sum)

            self.layer2['name'] = 'IPv4'
            self.layer2['src'] = src
            self.layer2['dst'] = dst
            self.layer2['version'] = version
            self.layer2['headerLen'] = head_len
            self.layer2['headerLenBytes'] = head_len_bytes
            self.layer2['tos'] = differentiated_services
            self.layer2['totLen'] = packet_len
            self.layer2['identification'] = identification
            self.layer2['flags'] = flags
            self.layer2['rf'] = rf
            self.layer2['df'] = df
            self.layer2['mf'] = mf
            self.layer2['offset'] = offset
            self.layer2['ttl'] = ttl
            self.layer2['protocol'] = protocol
            self.layer2['checksum'] = pkt_checksum

            self.info['src'] = src
            self.info['dst'] = dst
            self.info['protocol'] = 'IPv4'

            # 输出数据包信息
            output1 = {'type': packet_type, 'version': version}
            output2 = {'src': src, 'dst': dst}
            output8 = {'head len': head_len}
            output9 = {'Differentiated Services': differentiated_services}
            output3 = {'id': identification, 'len': packet_len}
            output4 = {'df': df, 'mf': mf, 'offset': offset}
            output5 = {'ttl': ttl}
            output6 = {'protocol': protocol}
            output7 = {'checksum': pkt_checksum}
            print(output1)
            print(output2)
            print(output8)
            print(output9)
            print(output3)
            print(output4)
            print(output5)
            print(output6)
            print(output7)
        elif isinstance(packet, dpkt.ip6.IP6):  # IPv6
            src = packet.src
            src = ":".join(['%x' % (src[i] * 16 ** 2 + src[i + 1]) for i in range(0, len(src), 2)])
            dst = packet.dst
            dst = ":".join(['%x' % (dst[i] * 16 ** 2 + dst[i + 1]) for i in range(0, len(dst), 2)])
            version = packet.v
            pkt_tc = packet.fc
            traffic_class = '0x{:02x}'.format(pkt_tc)
            ecn = pkt_tc & 3
            dsc = pkt_tc >> 2
            flow_label = '0x{:x}'.format(packet.flow)
            payload_len = packet.plen
            nxt_header = packet.nxt
            if nxt_header == 6:  # TCP
                nxt_header = 'TCP (6)'
            elif nxt_header == 17:  # UDP
                nxt_header = 'UDP (17)'
            elif nxt_header == 58:  # ICMPv6
                nxt_header = 'ICMPv6 (58)'
            elif nxt_header == 0:  # IPv6 hop-by-hop options
                nxt_header = 'IPv6 Hop-by-Hop Option (0)'
            hop_lim = packet.hlim

            self.layer2['name'] = 'IPv6'
            self.layer2['src'] = src
            self.layer2['dst'] = dst
            self.layer2['version'] = version
            self.layer2['trafficClass'] = traffic_class
            self.layer2['ecn'] = ecn
            self.layer2['dsc'] = dsc
            self.layer2['flowLab'] = flow_label
            self.layer2['payloadLen'] = payload_len
            self.layer2['nxtHeader'] = nxt_header
            self.layer2['hopLim'] = hop_lim

            self.info['src'] = src
            self.info['dst'] = dst
            self.info['protocol'] = 'IPv6'

            # 输出数据包信息
            output1 = {'type': packet_type, 'version': version}
            output2 = {'src': src, 'dst': dst}
            output3 = {'dsc': dsc}
            print(output1)
            print(output2)
            print(output3)

        elif isinstance(packet, dpkt.arp.ARP):  # ARP
            pass
        else:
            print("Non IPv4/IPv6/ARP packet type not supported ", packet.__class__.__name__)

        self.parse_layer3(packet.data)

    def parse_layer3(self, packet):  # 传输层
        if len(packet) == 0:  # 如果传输负载长度为0，即该包为单纯的arp包，没有负载，则丢弃
            return

        packet_type = type(packet)  # TCP

        # 判断数据报类型
        if isinstance(packet, dpkt.tcp.TCP):  # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
            sport = packet.sport
            dport = packet.dport
            seq = packet.seq
            ack = packet.ack
            header_len = packet.off
            header_len_bytes = header_len * 4
            pkt_flags = packet.flags  # int
            flags = '0x{:03x}'.format(pkt_flags)
            rf = pkt_flags >> 9
            ecn = (pkt_flags >> 8) & 1
            cwr = (pkt_flags >> 7) & 1
            ece = (pkt_flags >> 6) & 1
            urg = (pkt_flags >> 5) & 1
            ack_flag = (pkt_flags >> 4) & 1
            psh = (pkt_flags >> 3) & 1
            rst = (pkt_flags >> 2) & 1
            syn = (pkt_flags >> 1) & 1
            fin = pkt_flags & 1
            window_size = packet.win
            pkt_checksum = '0x{:04x}'.format(packet.sum)
            urp = packet.urp
            opts = packet.opts
            opts = dpkt.tcp.parse_opts(opts)
            payload = len(packet.data)

            self.layer3['name'] = 'TCP'
            self.layer3['sport'] = sport
            self.layer3['dport'] = dport
            self.layer3['seq'] = seq
            self.layer3['ack'] = ack
            self.layer3['headerLen'] = header_len
            self.layer3['headerLenBytes'] = header_len_bytes
            self.layer3['flags'] = flags
            self.layer3['rf'] = rf
            self.layer3['ecn'] = ecn
            self.layer3['cwr'] = cwr
            self.layer3['ece'] = ece
            self.layer3['urg'] = urg
            self.layer3['ackFlag'] = ack_flag
            self.layer3['psh'] = psh
            self.layer3['rst'] = rst
            self.layer3['syn'] = syn
            self.layer3['fin'] = fin
            self.layer3['window'] = window_size
            self.layer3['checksum'] = pkt_checksum
            self.layer3['urp'] = urp
            self.layer3['opts'] = opts
            self.layer3['payload'] = payload

            self.info['protocol'] = 'TCP'
            self.info['info'] = str(sport) + ' --> ' + str(dport)

            # 输出数据包信息
            output1 = {'type': packet_type}
            output2 = {'sport': sport, 'dport': dport}
            output3 = {'seq': seq, 'ack': ack}
            output7 = {'offset': header_len}
            output4 = {'flags': flags, 'window': window_size}
            output5 = {'urgent pointer': urp}
            output6 = {'options': opts}
            print(output1)
            print(output2)
            print(output3)
            print(output7)
            print(output4)
            print(output5)
            print(output6)
        elif isinstance(packet, dpkt.udp.UDP):  # UDP
            sport = packet.sport
            dport = packet.dport
            tot_len = packet.ulen
            pkt_checksum = '0x{:04x}'.format(packet.sum)
            payload = len(packet.data)

            self.layer3['name'] = 'UDP'
            self.layer3['sport'] = sport
            self.layer3['dport'] = dport
            self.layer3['len'] = tot_len
            self.layer3['checksum'] = pkt_checksum
            self.layer3['payload'] = payload

            self.info['protocol'] = 'UDP'

            # 输出数据包信息
            output1 = {'type': packet_type}
            output2 = {'sport': sport, 'dport': dport}
            output3 = {'length': tot_len}
            output4 = {'checksum': checksum}
            print(output1)
            print(output2)
            print(output3)
            print(output4)
        else:
            print("Non TCP/UDP packet type not supported ", packet.__class__.__name__)

        self.parse_layer4(packet.data)

    def parse_layer4(self, packet):  # 应用层
        if not len(packet):  # 如果应用层负载长度为0，即该包为单纯的tcp/udp包，没有负载，则丢弃
            return

        packet_type = type(packet)  # HTTP
        print(packet_type)

        if isinstance(packet, dpkt.http.Message):  # HTTP
            self.layer4['name'] = 'HTTP'
            self.info['protocol'] = 'HTTP'
            if isinstance(packet, dpkt.http.Request):  # Request
                self.layer4['method'] = packet.method
                self.layer4['url'] = packet.uri
                self.layer4['version'] = packet.version
                self.layer4['headers'] = packet.headers
                self.layer4['host'] = packet.headers['host']
                self.layer4['userAgent'] = packet.headers['user-agent']
                self.layer4['body'] = packet.body

            elif isinstance(packet, dpkt.http.Response):  # Response
                self.layer4['version'] = packet.version
                self.layer4['statusCode'] = packet.status
                self.layer4['responsePhrase'] = packet.reason
                self.layer4['headers'] = packet.headers
                self.layer4['body'] = packet.body
        else:
            print("Non HTTP packet type not supported ", packet.__class__.__name__)

    # scapy抓包：
    def catch_pack(self, device):
        while True:
            sniff(iface=device, prn=self.packet_callback, count=1)


if __name__ == '__main__':
    # Return a list of all the devices detected on the machine
    devices = []
    for i in repr(conf.route).split('\n')[1:]:
        tmp = re.search(r'[a-zA-Z](.*)[a-zA-Z0-9]', i).group()[0:44].rstrip()
        if len(tmp) > 0:
            devices.append(tmp)
    devices = list(set(devices))
    devices.sort()

    print(devices)

    print("------------------------------------------------")

    deviceIndex = int(input("请输入你想要监听的网卡序号: "))

    device = devices[deviceIndex]

    print(device)

    PacketParser.catch_pack(device)
