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
        self.packets = []  # 用来显示data
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
        self.ui.protocolFilterAfterCapture.activated.connect(self.filter)
        self.ui.packetsTable.itemClicked.connect(self.show_item_detail)

    def packet_callback(self, pkt_data):
        self.captures.append(pkt_data)
        self.frame_index += 1
        wrpcap('packet.pcap', [pkt_data])

        try:
            with open('packet.pcap', 'rb') as f:
                capture = dpkt.pcap.Reader(f)
                for timestamp, pkt in capture:  # 键值对，提取packet进行解码
                    print(pkt_data)
                    print(pkt)
                    self.packets.append(pkt)
                    pkt_parser = packetParser.PacketParser(self.frame_index)
                    pkt_parser.parse(timestamp, pkt, self.start_time)
                    self.pkt_parsers.append(pkt_parser)
                    self.set_packets_table(pkt_parser)
        except Exception as e:
            print(e)

    def start(self):
        print("start")
        self.device = self.get_device()
        if self.sniffer is None:
            try:
                self.sniffer = sniffer.Sniffer()
                self.sniffer.device = self.device
                self.sniffer.HandleSignal.connect(self.packet_callback)
            except Exception as e:
                print(e)
            self.start_time = time.time()
            print("sniff on " + self.device)
            self.stop_flag = False
            self.sniffer.start()
        elif self.stop_flag:  # 停止后重新开始抓包
            self.frame_index = 0
            self.packets = []
            self.pkt_parsers = []
            self.clear_packets_table()
            self.clear_packet_detail()
            self.clear_packet_data()

            self.sniffer.device = self.device
            self.start_time = time.time()
            print("sniff on " + self.device)
            self.stop_flag = False
            self.sniffer.resume()

    def stop(self):
        if self.sniffer is not None:
            self.stop_flag = True
            self.sniffer.stop()

    def reset(self):
        pass

    def filter(self):
        pass

    def show_item_detail(self):
        row = self.ui.packetsTable.currentRow()  # 获取当前行
        pkt_parser = self.pkt_parsers[row]
        packet = self.packets[row]
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
        if pkt_parser.layer2['name'] == 'IPv4':
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

        else:
            pass

    def set_layer4(self, pkt_parser):
        if pkt_parser.layer4['name'] is None:
            return
        if pkt_parser.layer4['name'] == 'HTTP':  # HTTP
            pass
        elif pkt_parser.layer4['name'] == 'DNS':  # DNS
            pass
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
