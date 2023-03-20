import pickle

import dpkt
from scapy.all import *


# frame_index = 0

class PacketParser:
    def __init__(self, frame_index):
        self.frame_index = frame_index
        self.info = {'index': None, 'time': None, 'len': None}
        # 数据链路层
        self.layer1 = {'name': None, 'smac': None, 'dmac': None, 'type': None}
        # 网络层
        self.layer2 = {'name': None, 'src': None, 'dst': None, 'version': None, 'headerLen': None, 'tos': None,
                       'totLen': None, 'identification': None, 'flags': None, 'rf': None, 'df': None, 'mf': None,
                       'offset': None, 'ttl': None, 'protocol': None, 'checksum': None}
        # 传输层
        self.layer3 = {'name': None, 'sport': None, 'dport': None, 'seq': None, 'ack': None, 'headerLen': None,
                       'flags': None, 'reserved': None, 'ecn': None, 'cwr': None, 'ece': None, 'urg': None, 'ack': None,
                       'psh': None, 'rst': None, 'syn': None, 'fin': None, 'window': None, 'checksum': None,
                       'urp': None, 'opts': None, 'payload': None}
        # 应用层
        self.layer4 = {'name': None, 'method': None, 'url': None, 'version': None, 'headers': None, 'host': None,
                       'userAgent': None, 'body': None}

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

    def parse(self, timestamp, pkt_data):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', (time.localtime()))
        pkt_len = len(pkt_data)  # bytes

        self.info['index'] = self.frame_index
        self.info['time'] = current_time
        self.info['len'] = pkt_len

        output1 = {'Frame': self.frame_index}
        output2 = {'time': current_time}
        output3 = {'len': pkt_len}
        print()
        print(output1)
        print(output2)
        print(output3)

        eth = dpkt.ethernet.Ethernet(pkt_data)
        self.parse_layer1(eth)

    def parse_layer1(self, eth):  # 数据链路层
        smac = "-".join(["%02x" % (b) for b in eth.src])
        dmac = "-".join(["%02x" % (b) for b in eth.dst])
        packet_type = type(eth)  # Ethernet
        data_protocol = eth.type

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
        packet_type = type(packet)  # IP

        # 判断数据报类型
        if isinstance(packet, dpkt.ip.IP):  # IP数据报
            # 取出分片信息
            src = packet.src
            dst = packet.dst
            version = packet.v
            head_len = packet.hl
            type_of_service = packet.tos
            packet_len = packet.len  # 首部+数据
            identification = packet.id
            rf = packet.rf  # Reserved bit
            df = packet.df  # don't fragment
            mf = packet.mf  # more fragments (not last frag)
            offset = packet.offset
            ttl = packet.ttl
            protocol = packet.p  # tcp udp
            pkt_checksum = packet.sum

            self.layer1['name'] = 'IPv4'
            self.layer1['src'] = src
            self.layer1['dst'] = dst
            self.layer1['version'] = version
            self.layer1['headerLen'] = head_len
            self.layer1['tos'] = type_of_service
            self.layer1['totLen'] = packet_len
            self.layer1['identification'] = identification
            # self.layer1['flags'] =
            self.layer1['rf'] = rf
            self.layer1['df'] = df
            self.layer1['mf'] = mf
            self.layer1['offset'] = offset
            self.layer1['ttl'] = ttl
            self.layer1['protocol'] = protocol
            self.layer1['checksum'] = pkt_checksum

            # 输出数据包信息
            output1 = {'type': packet_type, 'version': version}
            output2 = {'src': '%d.%d.%d.%d' % tuple(src), 'dst': '%d.%d.%d.%d' % tuple(dst)}
            output8 = {'head len': head_len}
            output9 = {'Type of service': type_of_service}
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
        else:
            print("Non IP packet type not supported ", packet.__class__.__name__)

        self.parse_layer3(packet.data)

    def parse_layer3(self, packet):  # 传输层
        packet_type = type(packet)  # TCP

        # 判断数据报类型
        if isinstance(packet, dpkt.tcp.TCP):  # 解包，判断传输层协议是否是TCP，即当你只需要TCP时，可用来过滤
            sport = packet.sport
            dport = packet.dport
            seq = packet.seq
            ack = packet.ack
            header_len = packet.off
            flags = packet.flags
            window_size = packet.win
            pkt_checksum = packet.sum
            urp = packet.urp
            opts = packet.opts
            opts = dpkt.tcp.parse_opts(opts)
            payload = len(packet.data)

            self.layer1['name'] = 'TCP'
            self.layer1['sport'] = sport
            self.layer1['dport'] = dport
            self.layer1['seq'] = seq
            self.layer1['ack'] = ack
            self.layer1['headerLen'] = header_len
            self.layer1['flags'] = flags
            self.layer1['window'] = window_size
            self.layer1['checksum'] = pkt_checksum
            self.layer1['urp'] = urp
            self.layer1['opts'] = opts
            self.layer1['payload'] = payload

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
            pkt_checksum = packet.sum
            payload = len(packet.data)

            self.layer1['name'] = 'UDP'
            self.layer1['sport'] = sport
            self.layer1['dport'] = dport
            self.layer1['len'] = tot_len
            self.layer1['checksum'] = pkt_checksum
            self.layer1['payload'] = payload

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
        if not len(packet):  # 如果应用层负载长度为0，即该包为单纯的tcp包，没有负载，则丢弃
            return

        packet_type = type(packet)  # HTTP
        print(packet_type)

        if isinstance(packet, dpkt.http.Message):  # HTTP
            self.layer4['name'] = 'HTTP'
            if isinstance(packet, dpkt.http.Request):  # Request
                method = packet.method
                url = packet.uri
                version = packet.version
                headers = packet.headers
                host = packet.headers['host']
                user_agent = packet.headers['user-agent']
                body = packet.body

                self.layer1['method'] = method
                self.layer1['url'] = url
                self.layer1['version'] = version
                self.layer1['headers'] = headers
                self.layer1['host'] = host
                self.layer1['userAgent'] = user_agent
                self.layer1['body'] = body

            elif isinstance(packet, dpkt.http.Response):  # Response
                pass
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
