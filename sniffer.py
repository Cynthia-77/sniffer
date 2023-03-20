import dpkt
from PyQt5 import QtCore
from PyQt5.QtCore import *

import packetParser
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


class Sniffer(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.packet.Packet)

    def __init__(self):
        super().__init__()
        self.mutex_1 = QMutex()
        self.cond = QWaitCondition()
        self.device = None

    def run(self):
        while True:
            self.mutex_1.lock()
            sniff(iface=self.device, prn=lambda x: self.HandleSignal.emit(x), count=1, timeout=2)
            self.mutex_1.unlock()

    def stop(self):
        pass
