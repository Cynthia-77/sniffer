class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

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
