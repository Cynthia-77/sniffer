import time

import dpkt
from PyQt5 import QtWidgets, QtCore
from scapy.utils import wrpcap

import packetParser
import sniffer


class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None
        self.start_time = None
        self.frame_index = 0
        self.packets = []  # 用来显示data
        self.pkt_parsers = []  # 用来显示detail

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
        print("start2")
        self.frame_index += 1
        wrpcap('packet.pcap', [pkt_data])

        try:
            with open('packet.pcap', 'rb') as f:
                capture = dpkt.pcap.Reader(f)
                for timestamp, pkt in capture:  # 键值对，提取packet进行解码
                    self.packets.append(pkt)
                    pkt_parser = packetParser.PacketParser(self.frame_index)
                    pkt_parser.parse(timestamp, pkt, self.start_time)
                    self.pkt_parsers.append(pkt_parser)
                    self.set_packets_table(pkt_parser)
        except Exception as e:
            print(e)

    def start(self):
        print("start")
        device = self.get_device()
        if self.sniffer is None:
            try:
                self.sniffer = sniffer.Sniffer()
                self.sniffer.device = device
                self.sniffer.HandleSignal.connect(self.packet_callback)
            except Exception as e:
                print(e)
            self.start_time = time.time()
            print("sniff on " + device)
            self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

    def reset(self):
        pass

    def filter(self):
        pass

    def show_item_detail(self):
        pass

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
