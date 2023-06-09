import time

import dpkt
from PyQt5 import QtWidgets, QtCore
from scapy.utils import wrpcap, hexdump

import packetParser
import sniffer


class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None
        self.device = None
        self.stop_flag = True  # 是否处于停止抓包状态
        self.start_time = None
        self.frame_index = 0
        self.packets = []
        self.pkt_parsers = []  # 用来显示detail
        self.captures = []

    def load_devices(self):
        devices = sniffer.get_devices()
        for device in devices:
            self.ui.devices.addItem(device)

    def set_connection(self):
        self.ui.startButton.clicked.connect(self.start)
        self.ui.stopButton.clicked.connect(self.stop)
        self.ui.resetButton.clicked.connect(self.reset)
        self.ui.filterAfterCapture.editingFinished.connect(self.filter)
        self.ui.packetsTable.itemClicked.connect(self.show_item_detail)

    def packet_callback(self, pkt_data):
        self.captures.append(pkt_data)
        self.frame_index += 1
        wrpcap('packet.pcap', [pkt_data])
        self.packets.append(pkt_data)

        try:
            with open('packet.pcap', 'rb') as f:
                capture = dpkt.pcap.Reader(f)
                for timestamp, pkt in capture:  # 键值对，提取packet进行解码
                    print(pkt_data)
                    print(pkt)
                    # self.packets.append(pkt)
                    pkt_parser = packetParser.PacketParser(self.frame_index)
                    pkt_parser.parse(timestamp, pkt, self.start_time)
                    self.pkt_parsers.append(pkt_parser)
                    self.set_packets_table(pkt_parser)
        except Exception as e:
            print(e)

    def start(self):
        print("start")
        if self.sniffer is None:
            try:
                self.sniffer = sniffer.Sniffer()
                self.device = self.get_device()
                self.sniffer.device = self.device
                self.sniffer.filter = self.get_filter_before_capture()
                print(self.get_filter_before_capture())
                self.sniffer.HandleSignal.connect(self.packet_callback)
                self.start_time = time.time()
                print("sniff on " + self.device)
                self.stop_flag = False
                self.sniffer.start()
            except Exception as e:
                print(e)
        elif self.stop_flag:  # 停止后重新开始抓包
            self.frame_index = 0
            # self.packets = []
            self.pkt_parsers = []
            self.clear_packets_table()
            self.clear_packet_detail()
            self.clear_packet_data()

            self.device = self.get_device()
            self.sniffer.device = self.device
            self.sniffer.filter = self.get_filter_before_capture()
            self.start_time = time.time()
            print("sniff on " + self.device)
            self.stop_flag = False
            self.sniffer.resume()

    def stop(self):
        if self.sniffer is not None:
            self.stop_flag = True
            self.sniffer.stop()
            wrpcap('packets.pcap', self.packets)

    def reset(self):
        self.clear_filter_after_capture()
        self.set_table_display('')
        self.clear_packet_detail()
        self.clear_packet_data()

    def filter(self):
        if self.stop_flag:  # 停止后过滤
            fl = self.get_filter_after_capture()
            self.set_table_display(fl)
            self.clear_packet_detail()
            self.clear_packet_data()

    def show_item_detail(self):
        row = self.ui.packetsTable.currentRow()  # 获取当前行
        pkt_parser = self.pkt_parsers[row]
        # packet = self.packets[row]
        capture = self.captures[row]

        self.set_packet_detail(pkt_parser)
        self.set_packet_data(capture)

    def get_device(self):
        device = self.ui.devices.currentText()
        return device

    def set_packets_table(self, pkt_parser):
        row = self.ui.packetsTable.rowCount()
        self.ui.packetsTable.insertRow(row)
        self.ui.packetsTable.setItem(row, 0, QtWidgets.QTableWidgetItem(str(row + 1)))
        self.ui.packetsTable.setItem(row, 1, QtWidgets.QTableWidgetItem(pkt_parser.info['time']))
        self.ui.packetsTable.setItem(row, 2, QtWidgets.QTableWidgetItem(pkt_parser.info['dst']))
        self.ui.packetsTable.setItem(row, 3, QtWidgets.QTableWidgetItem(pkt_parser.info['src']))
        self.ui.packetsTable.setItem(row, 4, QtWidgets.QTableWidgetItem(pkt_parser.info['protocol']))
        self.ui.packetsTable.setItem(row, 5, QtWidgets.QTableWidgetItem(pkt_parser.info['len']))
        self.ui.packetsTable.setItem(row, 6, QtWidgets.QTableWidgetItem(pkt_parser.info['info']))

    def clear_packets_table(self):
        # self.ui.packetsTable.clear()
        self.ui.packetsTable.setRowCount(0)

    def set_packet_detail(self, pkt_parser):
        try:
            self.ui.packetDetail.clear()
            # self.ui.packetDetail.setColumnCount(1)
            self.set_info(pkt_parser)
            self.set_layer1(pkt_parser)
            self.set_layer2(pkt_parser)
            self.set_layer3(pkt_parser)
            self.set_layer4(pkt_parser)
        except Exception as e:
            print(e)

    def set_info(self, pkt_parser):
        frame = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
        frame.setText(0, 'Frame %s: %s bytes on %s' % (pkt_parser.info['index'], pkt_parser.info['len'], self.device))
        frame_iface = QtWidgets.QTreeWidgetItem(frame)
        frame_iface.setText(0, 'Interface: %s' % self.device)
        encapsulation_type = QtWidgets.QTreeWidgetItem(frame)
        encapsulation_type.setText(0, 'Encapsulation Type: %s' % pkt_parser.layer1['name'])
        arrival_time = QtWidgets.QTreeWidgetItem(frame)
        arrival_time.setText(0, 'Arrival Time: %s' % pkt_parser.info['curTime'])
        epoch_time = QtWidgets.QTreeWidgetItem(frame)
        epoch_time.setText(0, 'Epoch Time: %s seconds' % pkt_parser.info['timestamp'])
        frame_number = QtWidgets.QTreeWidgetItem(frame)
        frame_number.setText(0, 'Frame Number: %s' % pkt_parser.info['index'])
        frame_length = QtWidgets.QTreeWidgetItem(frame)
        frame_length.setText(0, 'Frame Length: %s bytes' % pkt_parser.info['len'])

    def set_layer1(self, pkt_parser):
        eth = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
        eth.setText(0, '%s, Src: %s, Dst: %s' % (
            pkt_parser.layer1['name'], pkt_parser.layer1['smac'], pkt_parser.layer1['dmac']))
        dst = QtWidgets.QTreeWidgetItem(eth)
        dst.setText(0, 'Destination: %s' % pkt_parser.layer1['dmac'])
        src = QtWidgets.QTreeWidgetItem(eth)
        src.setText(0, 'Source: %s' % pkt_parser.layer1['smac'])
        typ = QtWidgets.QTreeWidgetItem(eth)
        typ.setText(0, 'Type: %s' % pkt_parser.layer1['type'])

    def set_layer2(self, pkt_parser):
        if pkt_parser.layer2['name'] == 'IPv4':  # IPv4
            ipv4 = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            ipv4.setText(0, 'IPv4, Src: %s, Dst: %s' % (pkt_parser.layer2['src'], pkt_parser.layer2['dst']))
            version = QtWidgets.QTreeWidgetItem(ipv4)
            version.setText(0, 'Version: %s' % pkt_parser.layer2['version'])
            h_len = QtWidgets.QTreeWidgetItem(ipv4)
            h_len.setText(0, 'Header Length: %s bytes (%s)' % (
                pkt_parser.layer2['headerLenBytes'], pkt_parser.layer2['headerLen']))
            tos = QtWidgets.QTreeWidgetItem(ipv4)
            tos.setText(0, 'Differentiated Services Field: %s' % pkt_parser.layer2['tos'])
            tot_len = QtWidgets.QTreeWidgetItem(ipv4)
            tot_len.setText(0, 'Total Length: %s' % pkt_parser.layer2['totLen'])
            identification = QtWidgets.QTreeWidgetItem(ipv4)
            identification.setText(0, 'Identification: %s' % pkt_parser.layer2['identification'])
            flags = QtWidgets.QTreeWidgetItem(ipv4)
            flags.setText(0, 'Flags: %s' % pkt_parser.layer2['flags'])
            rf = QtWidgets.QTreeWidgetItem(flags)
            rf.setText(0, 'Reserved bit: %s' % pkt_parser.layer2['rf'])
            df = QtWidgets.QTreeWidgetItem(flags)
            df.setText(0, 'Don\'t fragment: %s' % pkt_parser.layer2['df'])
            mf = QtWidgets.QTreeWidgetItem(flags)
            mf.setText(0, 'More fragments: %s' % pkt_parser.layer2['mf'])
            offset = QtWidgets.QTreeWidgetItem(ipv4)
            offset.setText(0, 'Fragment offset: %s' % pkt_parser.layer2['offset'])
            ttl = QtWidgets.QTreeWidgetItem(ipv4)
            ttl.setText(0, 'Time to Live: %s' % pkt_parser.layer2['ttl'])
            protocol = QtWidgets.QTreeWidgetItem(ipv4)
            protocol.setText(0, 'Protocol: %s' % pkt_parser.layer2['protocol'])
            checksum = QtWidgets.QTreeWidgetItem(ipv4)
            checksum.setText(0, 'Header Checksum: %s' % pkt_parser.layer2['checksum'])
            src = QtWidgets.QTreeWidgetItem(ipv4)
            src.setText(0, 'Source Address: %s' % pkt_parser.layer2['src'])
            dst = QtWidgets.QTreeWidgetItem(ipv4)
            dst.setText(0, 'Destination Address: %s' % pkt_parser.layer2['dst'])

        elif pkt_parser.layer2['name'] == 'IPv6':  # IPv6
            ipv6 = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            ipv6.setText(0, 'IPv6, Src: %s, Dst: %s' % (pkt_parser.layer2['src'], pkt_parser.layer2['dst']))
            version = QtWidgets.QTreeWidgetItem(ipv6)
            version.setText(0, 'Version: %s' % pkt_parser.layer2['version'])
            tc = QtWidgets.QTreeWidgetItem(ipv6)
            tc.setText(0, 'Traffic Class: %s' % pkt_parser.layer2['trafficClass'])
            dsc = QtWidgets.QTreeWidgetItem(tc)
            dsc.setText(0, 'Differentiated Services Codepoint: %s' % pkt_parser.layer2['dsc'])
            ecn = QtWidgets.QTreeWidgetItem(tc)
            ecn.setText(0, 'Explicit Congestion Notification: %s' % pkt_parser.layer2['ecn'])
            fl = QtWidgets.QTreeWidgetItem(ipv6)
            fl.setText(0, 'Flow Label: %s' % pkt_parser.layer2['flowLab'])
            p_len = QtWidgets.QTreeWidgetItem(ipv6)
            p_len.setText(0, 'Payload Length: %s' % pkt_parser.layer2['payloadLen'])
            nxt_h = QtWidgets.QTreeWidgetItem(ipv6)
            nxt_h.setText(0, 'Next Header: %s' % pkt_parser.layer2['nxtHeader'])
            hl = QtWidgets.QTreeWidgetItem(ipv6)
            hl.setText(0, 'Hop Limit: %s' % pkt_parser.layer2['hopLim'])
            src = QtWidgets.QTreeWidgetItem(ipv6)
            src.setText(0, 'Source Address: %s' % pkt_parser.layer2['src'])
            dst = QtWidgets.QTreeWidgetItem(ipv6)
            dst.setText(0, 'Destination Address: %s' % pkt_parser.layer2['dst'])

        elif pkt_parser.layer2['name'] == 'ARP':  # ARP
            arp = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            arp.setText(0, 'ARP (%s)' % pkt_parser.layer2['type'])
            hrd = QtWidgets.QTreeWidgetItem(arp)
            hrd.setText(0, 'Hardware Type: %s' % pkt_parser.layer2['hrdType'])
            p = QtWidgets.QTreeWidgetItem(arp)
            p.setText(0, 'Protocol Type: %s' % pkt_parser.layer2['protocol'])
            hrd_len = QtWidgets.QTreeWidgetItem(arp)
            hrd_len.setText(0, 'Hardware size: %s' % pkt_parser.layer2['hrdLen'])
            p_len = QtWidgets.QTreeWidgetItem(arp)
            p_len.setText(0, 'Protocol size: %s' % pkt_parser.layer2['protocolLen'])
            op = QtWidgets.QTreeWidgetItem(arp)
            op.setText(0, 'Opcode: %s' % pkt_parser.layer2['op'])
            smac = QtWidgets.QTreeWidgetItem(arp)
            smac.setText(0, 'Sender MAC addresss: %s' % pkt_parser.layer2['smac'])
            sip = QtWidgets.QTreeWidgetItem(arp)
            sip.setText(0, 'Sender IP addresss: %s' % pkt_parser.layer2['sip'])
            tmac = QtWidgets.QTreeWidgetItem(arp)
            tmac.setText(0, 'Target MAC addresss: %s' % pkt_parser.layer2['tmac'])
            tip = QtWidgets.QTreeWidgetItem(arp)
            tip.setText(0, 'Sender IP addresss: %s' % pkt_parser.layer2['tip'])

        else:
            pass

    def set_layer3(self, pkt_parser):
        if pkt_parser.layer3['name'] is None:
            return
        if pkt_parser.layer3['name'] == 'TCP':  # TCP
            tcp = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            tcp.setText(0, 'TCP, Src Port: %s, Dst Port: %s, Seq: %s, Ack:%s, Len: %s' % (
                pkt_parser.layer3['sport'], pkt_parser.layer3['dport'], pkt_parser.layer3['seq'],
                pkt_parser.layer3['ack'], pkt_parser.layer3['payload']))
            sport = QtWidgets.QTreeWidgetItem(tcp)
            sport.setText(0, 'Source Port: %s' % pkt_parser.layer3['sport'])
            dport = QtWidgets.QTreeWidgetItem(tcp)
            dport.setText(0, 'Destination Port: %s' % pkt_parser.layer3['dport'])
            seq = QtWidgets.QTreeWidgetItem(tcp)
            seq.setText(0, 'Sequence Number: %s' % pkt_parser.layer3['seq'])
            ack = QtWidgets.QTreeWidgetItem(tcp)
            ack.setText(0, 'Acknowledgement Number: %s' % pkt_parser.layer3['ack'])
            h_len = QtWidgets.QTreeWidgetItem(tcp)
            h_len.setText(0, 'Header Length: %s bytes (%s)' % (
                pkt_parser.layer3['headerLenBytes'], pkt_parser.layer3['headerLen']))
            flags = QtWidgets.QTreeWidgetItem(tcp)
            flags.setText(0, 'Flags: %s' % pkt_parser.layer3['flags'])
            rf = QtWidgets.QTreeWidgetItem(flags)
            rf.setText(0, 'Reserved: %s' % pkt_parser.layer3['rf'])
            ecn = QtWidgets.QTreeWidgetItem(flags)
            ecn.setText(0, 'Accurate ECN: %s' % pkt_parser.layer3['ecn'])
            cwr = QtWidgets.QTreeWidgetItem(flags)
            cwr.setText(0, 'Congestion Window Reduced: %s' % pkt_parser.layer3['cwr'])
            ece = QtWidgets.QTreeWidgetItem(flags)
            ece.setText(0, 'ECN-Echo: %s' % pkt_parser.layer3['ece'])
            urg = QtWidgets.QTreeWidgetItem(flags)
            urg.setText(0, 'Urgent: %s' % pkt_parser.layer3['urg'])
            ack_flag = QtWidgets.QTreeWidgetItem(flags)
            ack_flag.setText(0, 'Acknowledgement: %s' % pkt_parser.layer3['ackFlag'])
            psh = QtWidgets.QTreeWidgetItem(flags)
            psh.setText(0, 'Push: %s' % pkt_parser.layer3['psh'])
            rst = QtWidgets.QTreeWidgetItem(flags)
            rst.setText(0, 'Reset: %s' % pkt_parser.layer3['rst'])
            syn = QtWidgets.QTreeWidgetItem(flags)
            syn.setText(0, 'Syn: %s' % pkt_parser.layer3['syn'])
            fin = QtWidgets.QTreeWidgetItem(flags)
            fin.setText(0, 'Fin: %s' % pkt_parser.layer3['fin'])
            win = QtWidgets.QTreeWidgetItem(tcp)
            win.setText(0, 'Window: %s' % pkt_parser.layer3['window'])
            checksum = QtWidgets.QTreeWidgetItem(tcp)
            checksum.setText(0, 'Checksum: %s' % pkt_parser.layer3['checksum'])
            urp = QtWidgets.QTreeWidgetItem(tcp)
            urp.setText(0, 'Urgent Pointer: %s' % pkt_parser.layer3['urg'])
            if pkt_parser.layer3['optsLen'] == 0:
                opts = QtWidgets.QTreeWidgetItem(tcp)
                opts.setText(0, 'Options: (%s bytes)' % pkt_parser.layer3['optsLen'])
            else:
                opts = QtWidgets.QTreeWidgetItem(tcp)
                opts.setText(0, 'Options: (%s bytes), %s' % (pkt_parser.layer3['optsLen'], pkt_parser.layer3['opts']))
                for detail in pkt_parser.layer3['optsDetail']:
                    opt = QtWidgets.QTreeWidgetItem(opts)
                    opt.setText(0, 'TCP Option - %s' % detail['opt'])
                    kind = QtWidgets.QTreeWidgetItem(opt)
                    kind.setText(0, 'Kind: %s' % detail['kind'])
                    if detail['num'] == 1:  # NOP
                        continue
                    elif detail['num'] == 2:  # MSS
                        length = QtWidgets.QTreeWidgetItem(opt)
                        length.setText(0, 'Length: %s' % detail['len'])
                        mss = QtWidgets.QTreeWidgetItem(opt)
                        mss.setText(0, 'MSS Value: %s' % detail['mss'])
                    elif detail['num'] == 3:  # WS
                        length = QtWidgets.QTreeWidgetItem(opt)
                        length.setText(0, 'Length: %s' % detail['len'])
                        sc = QtWidgets.QTreeWidgetItem(opt)
                        sc.setText(0, 'Shift count: %s' % detail['sc'])
                        mul = QtWidgets.QTreeWidgetItem(opt)
                        mul.setText(0, '[Multiplier: %s]' % detail['mul'])
                    elif detail['num'] == 4:  # SACK_PERM
                        length = QtWidgets.QTreeWidgetItem(opt)
                        length.setText(0, 'Length: %s' % detail['len'])
                    elif detail['num'] == 5:  # SACK
                        length = QtWidgets.QTreeWidgetItem(opt)
                        length.setText(0, 'Length: %s' % detail['len'])
            payload = QtWidgets.QTreeWidgetItem(tcp)
            payload.setText(0, 'TCP payload (%s bytes)' % pkt_parser.layer3['payload'])

        elif pkt_parser.layer3['name'] == 'UDP':  # UDP
            udp = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            udp.setText(0, 'UDP, Src Port: %s, Dst Port: %s' % (pkt_parser.layer3['sport'], pkt_parser.layer3['dport']))
            sport = QtWidgets.QTreeWidgetItem(udp)
            sport.setText(0, 'Source Port: %s' % pkt_parser.layer3['sport'])
            dport = QtWidgets.QTreeWidgetItem(udp)
            dport.setText(0, 'Destination Port: %s' % pkt_parser.layer3['dport'])
            totlen = QtWidgets.QTreeWidgetItem(udp)
            totlen.setText(0, 'Length: %s' % (pkt_parser.layer3['len']))
            checksum = QtWidgets.QTreeWidgetItem(udp)
            checksum.setText(0, 'Checksum: %s' % pkt_parser.layer3['checksum'])
            payload = QtWidgets.QTreeWidgetItem(udp)
            payload.setText(0, 'UDP payload (%s bytes)' % pkt_parser.layer3['payload'])

        elif pkt_parser.layer3['name'] == 'IGMP':  # IGMP
            igmp = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            igmp.setText(0, 'IGMP')
            v = QtWidgets.QTreeWidgetItem(igmp)
            v.setText(0, '[IGMP Version: 3]')
            typ = QtWidgets.QTreeWidgetItem(igmp)
            typ.setText(0, 'Type: %s' % pkt_parser.layer3['type'])
            rf1 = QtWidgets.QTreeWidgetItem(igmp)
            rf1.setText(0, 'Reserved: %s' % (pkt_parser.layer3['rf1']))
            checksum = QtWidgets.QTreeWidgetItem(igmp)
            checksum.setText(0, 'Checksum: %s' % pkt_parser.layer3['checksum'])
            rf2 = QtWidgets.QTreeWidgetItem(igmp)
            rf2.setText(0, 'Reserved: %s' % (pkt_parser.layer3['rf2']))
            ngr = QtWidgets.QTreeWidgetItem(igmp)
            ngr.setText(0, 'Num Group Records: %s' % (pkt_parser.layer3['ngr']))
            gr = QtWidgets.QTreeWidgetItem(igmp)
            gr.setText(0, 'Group Record: %s  %s' % (pkt_parser.layer3['mulAddr'], pkt_parser.layer3['recordType']))
            rt = QtWidgets.QTreeWidgetItem(gr)
            rt.setText(0,
                       'Record Type: %s (%s)' % (pkt_parser.layer3['recordType'], pkt_parser.layer3['recordTypeNum']))
            adl = QtWidgets.QTreeWidgetItem(gr)
            adl.setText(0, 'Aux Data Len: %s' % pkt_parser.layer3['adlen'])
            ns = QtWidgets.QTreeWidgetItem(gr)
            ns.setText(0, 'Num Src: %s' % pkt_parser.layer3['numSrc'])
            mul_a = QtWidgets.QTreeWidgetItem(gr)
            mul_a.setText(0, 'Multicast Address: %s' % pkt_parser.layer3['mulAddr'])

        elif pkt_parser.layer3['name'] == 'ICMPv6':  # ICMPv6
            icmp6 = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            icmp6.setText(0, 'ICMPv6')
            typ = QtWidgets.QTreeWidgetItem(icmp6)
            typ.setText(0, 'Type: %s' % pkt_parser.layer3['type'])
            code = QtWidgets.QTreeWidgetItem(icmp6)
            code.setText(0, 'Code: %s' % (pkt_parser.layer3['code']))
            checksum = QtWidgets.QTreeWidgetItem(icmp6)
            checksum.setText(0, 'Checksum: %s' % pkt_parser.layer3['checksum'])
        else:
            pass

    def set_layer4(self, pkt_parser):
        if pkt_parser.layer4['name'] is None:
            return
        if pkt_parser.layer4['name'] == 'HTTP':  # HTTP
            http = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            http.setText(0, 'HTTP')
            if pkt_parser.layer4['type'] == 'Request':  # Request
                d = QtWidgets.QTreeWidgetItem(http)
                d.setText(0, '%s %s HTTP/%s' % (
                    pkt_parser.layer4['method'], pkt_parser.layer4['url'], pkt_parser.layer4['version']))
                method = QtWidgets.QTreeWidgetItem(d)
                method.setText(0, 'Request Method: %s' % pkt_parser.layer4['method'])
                uri = QtWidgets.QTreeWidgetItem(d)
                uri.setText(0, 'Request URI: %s' % pkt_parser.layer4['url'])
                v = QtWidgets.QTreeWidgetItem(d)
                v.setText(0, 'Request Version: HTTP/%s' % pkt_parser.layer4['version'])
                con = QtWidgets.QTreeWidgetItem(http)
                con.setText(0, 'Connection: %s' % pkt_parser.layer4['connection'])
                ua = QtWidgets.QTreeWidgetItem(http)
                ua.setText(0, 'User-Agent: %s' % pkt_parser.layer4['userAgent'])
                host = QtWidgets.QTreeWidgetItem(http)
                host.setText(0, 'Host: %s' % pkt_parser.layer4['host'])

            elif pkt_parser.layer4['type'] == 'Response':  # Response
                d = QtWidgets.QTreeWidgetItem(http)
                d.setText(0, 'HTTP/%s %s %s' % (
                    pkt_parser.layer4['version'], pkt_parser.layer4['status'], pkt_parser.layer4['reason']))
                v = QtWidgets.QTreeWidgetItem(d)
                v.setText(0, 'Response Version: HTTP/%s' % pkt_parser.layer4['version'])
                sc = QtWidgets.QTreeWidgetItem(d)
                sc.setText(0, 'Status Code: %s' % pkt_parser.layer4['status'])
                uri = QtWidgets.QTreeWidgetItem(d)
                uri.setText(0, 'Response Phrase: %s' % pkt_parser.layer4['reason'])
                cl1 = 0
                ct1 = ''
                con = QtWidgets.QTreeWidgetItem(http)
                con.setText(0, 'Connection: %s' % pkt_parser.layer4['connection'])
                if pkt_parser.layer4['content-length'] is not None:
                    cl = QtWidgets.QTreeWidgetItem(http)
                    cl.setText(0, 'Content Length: %s' % pkt_parser.layer4['content-length'])
                    cl1 = pkt_parser.layer4['content-length']
                if pkt_parser.layer4['content-type'] is not None:
                    ct = QtWidgets.QTreeWidgetItem(http)
                    ct.setText(0, 'Content Type: %s' % pkt_parser.layer4['content-type'])
                    dl = QtWidgets.QTreeWidgetItem(http)
                    dl.setText(0, 'File Data: %s bytes' % pkt_parser.layer4['content-length'])
                    ct1 = pkt_parser.layer4['content-type']
                data = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
                data.setText(0, 'Data (%s bytes) : %s' % (cl1, ct1))
                # d = QtWidgets.QTreeWidgetItem(data)
                # d.setText(0, 'Data: ' % pkt_parser.layer4['body'])

        elif pkt_parser.layer4['name'] == 'TLS':  # HTTPS (TLS)
            https = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            https.setText(0, 'TLS')
            ct = QtWidgets.QTreeWidgetItem(https)
            ct.setText(0, 'Content Type: %s' % pkt_parser.layer4['content-type'])

        elif pkt_parser.layer4['name'] == 'DNS' or pkt_parser.layer4['name'] == 'MDNS':  # DNS/MDNS
            dns = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            if pkt_parser.layer4['op'] == 'Standard query':
                dns.setText(0, '%s (query)' % pkt_parser.layer4['name'])
            elif pkt_parser.layer4['op'] == 'Standard query response':
                dns.setText(0, '%s (response)' % pkt_parser.layer4['name'])
            else:
                dns.setText(0, '%s' % pkt_parser.layer4['name'])
            id1 = QtWidgets.QTreeWidgetItem(dns)
            id1.setText(0, 'Transaction ID: %s' % pkt_parser.layer4['id'])
            flags = QtWidgets.QTreeWidgetItem(dns)
            flags.setText(0, 'Flags: %s %s' % (pkt_parser.layer4['flags'], pkt_parser.layer4['op']))
            if pkt_parser.layer4['op'] == 'Standard query' or pkt_parser.layer4['op'] == 'Standard query response':
                qs = QtWidgets.QTreeWidgetItem(dns)
                qs.setText(0, 'Questions: 1')
            else:
                qs = QtWidgets.QTreeWidgetItem(dns)
                qs.setText(0, 'Questions: 0')
            if pkt_parser.layer4['op'] == 'Standard query response':
                ar = QtWidgets.QTreeWidgetItem(dns)
                ar.setText(0, 'Answer RRs: %s' % len(pkt_parser.layer4['ans']))
            else:
                ar = QtWidgets.QTreeWidgetItem(dns)
                ar.setText(0, 'Answer RRs: 0')
            if pkt_parser.layer4['op'] == 'Standard query' or pkt_parser.layer4['op'] == 'Standard query response':
                q = QtWidgets.QTreeWidgetItem(dns)
                q.setText(0, 'Queries')
                qn = QtWidgets.QTreeWidgetItem(q)
                qn.setText(0, 'Name: %s' % pkt_parser.layer4['qd'])
            if pkt_parser.layer4['op'] == 'Standard query response':
                a = QtWidgets.QTreeWidgetItem(dns)
                a.setText(0, 'Answers')
                for ans in pkt_parser.layer4['ans']:
                    an = QtWidgets.QTreeWidgetItem(a)
                    an.setText(0, '%s: type %s, cname %s' % (ans['name'], ans['typeInfo'], ans['cname']))
                    name = QtWidgets.QTreeWidgetItem(an)
                    name.setText(0, 'Name: %s' % ans['name'])
                    typ = QtWidgets.QTreeWidgetItem(an)
                    typ.setText(0, 'Type: %s' % ans['type'])
                    ttl = QtWidgets.QTreeWidgetItem(an)
                    ttl.setText(0, 'Time to live: %s' % ans['ttl'])
                    dl = QtWidgets.QTreeWidgetItem(an)
                    dl.setText(0, 'Data Length: %s' % ans['dataLen'])
                    cn = QtWidgets.QTreeWidgetItem(an)
                    cn.setText(0, 'CNAME: %s' % ans['cname'])

        elif pkt_parser.layer4['name'] == 'SSDP':  # SSDP
            ssdp = QtWidgets.QTreeWidgetItem(self.ui.packetDetail)
            ssdp.setText(0, 'SSDP')

        else:
            pass

    def clear_packet_detail(self):
        self.ui.packetDetail.clear()

    def set_packet_data(self, capture):
        try:
            self.ui.packetData.clear()
            content = hexdump(capture, dump=True)
            self.ui.packetData.append(content)
        except Exception as e:
            print(e)

    def clear_packet_data(self):
        self.ui.packetData.clear()

    def get_filter_before_capture(self):
        return self.ui.filterBeforeCapture.text()

    def get_filter_after_capture(self):
        return self.ui.filterAfterCapture.text()

    def clear_filter_after_capture(self):
        self.ui.filterAfterCapture.clear()

    def set_table_display(self, fl):
        rows = self.ui.packetsTable.rowCount()
        for row in range(rows):
            if fl == '':
                self.ui.packetsTable.setRowHidden(row, False)
                continue
            pkt_parser = self.pkt_parsers[row]
            if fl == 'ip':
                fl = 'ipv4'
            if (pkt_parser.layer1['name'] is not None and pkt_parser.layer1['name'].lower() == fl) or (
                    pkt_parser.layer2['name'] is not None and pkt_parser.layer2['name'].lower() == fl) or (
                    pkt_parser.layer3['name'] is not None and pkt_parser.layer3['name'].lower() == fl) or (
                    pkt_parser.layer4['name'] is not None and pkt_parser.layer4['name'].lower() == fl):
                self.ui.packetsTable.setRowHidden(row, False)
            else:
                index = fl.find('.')
                index2 = fl.find('==')
                if index != -1:
                    protocol = fl[0:index]
                    if protocol == 'ip':
                        if fl[index2 + 2] == ' ':
                            addr = fl[index2 + 3:]
                        else:
                            addr = fl[index2 + 2:]
                        if pkt_parser.layer2['name'] == 'IPv4' and (
                                pkt_parser.layer2['src'] == addr or pkt_parser.layer2['dst'] == addr):
                            self.ui.packetsTable.setRowHidden(row, False)
                        else:
                            self.ui.packetsTable.setRowHidden(row, True)
                    elif protocol == 'ipv6':
                        if fl[index2 + 2] == ' ':
                            addr = fl[index2 + 3:]
                        else:
                            addr = fl[index2 + 2:]
                        if pkt_parser.layer2['name'] == 'IPv6' and (
                                pkt_parser.layer2['src'] == addr or pkt_parser.layer2['dst'] == addr):
                            self.ui.packetsTable.setRowHidden(row, False)
                        else:
                            self.ui.packetsTable.setRowHidden(row, True)
                    elif protocol == 'tcp':
                        if fl[index2 + 2] == ' ':
                            port = fl[index2 + 3:]
                        else:
                            port = fl[index2 + 2:]
                        if pkt_parser.layer3['name'] == 'TCP' and (
                                str(pkt_parser.layer3['sport']) == port or str(pkt_parser.layer3['dport']) == port):
                            self.ui.packetsTable.setRowHidden(row, False)
                        else:
                            self.ui.packetsTable.setRowHidden(row, True)
                    elif protocol == 'udp':
                        if fl[index2 + 2] == ' ':
                            port = fl[index2 + 3:]
                        else:
                            port = fl[index2 + 2:]
                        if pkt_parser.layer3['name'] == 'UDP' and (
                                str(pkt_parser.layer3['sport']) == port or str(pkt_parser.layer3['dport']) == port):
                            self.ui.packetsTable.setRowHidden(row, False)
                        else:
                            self.ui.packetsTable.setRowHidden(row, True)
                else:
                    self.ui.packetsTable.setRowHidden(row, True)
