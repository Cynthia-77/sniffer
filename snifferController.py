import sniffer


class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

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

    def start(self):
        print("start")
        if self.sniffer is None:
            self.sniffer = sniffer.Sniffer()
        device = self.get_device()
        print("sniff on " + device)
        return
        self.sniffer.start(device)

    def stop(self):
        pass

    def reset(self):
        pass

    def filter(self):
        pass

    def show_item_detail(self):
        pass

    def get_device(self):
        device = self.ui.devices.currentText()
        return device
