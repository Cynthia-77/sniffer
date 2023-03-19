import parse


class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

    def load_devices(self):
        devices = parse.get_devices()
        index = 0
        for device in devices:
            index += 1
            self.ui.devices.addItem(str(index) + ": " + device)

    def set_connection(self):
        self.ui.startButton.clicked.connect(self.start)
        self.ui.pauseButton.clicked.connect(self.pause)
        self.ui.resetButton.clicked.connect(self.reset)
        self.ui.protocolFilterAfterCapture.activated.connect(self.filter)
        self.ui.packetsTable.itemClicked.connect(self.show_item_detail)

    def start(self):
        pass

    def pause(self):
        pass

    def reset(self):
        pass

    def filter(self):
        pass

    def show_item_detail(self):
        pass
