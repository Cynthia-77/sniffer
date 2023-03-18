class SnifferController:
    def __init__(self, ui):
        self.ui = ui
        self.sniffer = None

    def set_connection(self):

        self.ui.startButton.clicked.connect(self.start)
        self.ui.pauseButton.clicked.connect(self.pause)
        self.ui.resetButton.clicked.connect(self.ui.reset)

        self.ui.buttonFilter.clicked.connect(self.Filter)
        self.ui.tableWidget.itemClicked.connect(self.ui.showItemDetail)
        self.ui.buttonPostFilter.clicked.connect(self.PostFilter)
        self.ui.tableWidget.customContextMenuRequested.connect(self.ui.showContextMenu)
        self.ui.TraceAction.triggered.connect(self.Trace)
        self.ui.saveAction.triggered.connect(self.Save)
