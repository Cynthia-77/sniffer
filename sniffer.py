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
        self.filter = None
        self.cond_flag = False

    def run(self):
        while True:
            self.mutex_1.lock()
            if self.cond_flag:
                self.cond.wait(self.mutex_1)
            print(self.filter)
            try:
                sniff(filter=self.filter, iface=self.device, prn=lambda x: self.HandleSignal.emit(x), count=1, timeout=2)
            except Exception as e:
                print(e)
            self.mutex_1.unlock()

    def stop(self):
        self.cond_flag = True

    def resume(self):
        self.cond_flag = False
        self.cond.wakeAll()
