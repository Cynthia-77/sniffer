# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'snifferGUI.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1500, 890)
        MainWindow.setToolTip("")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.startButton = QtWidgets.QPushButton(self.centralwidget)
        self.startButton.setGeometry(QtCore.QRect(20, 90, 150, 51))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(False)
        font.setWeight(50)
        self.startButton.setFont(font)
        self.startButton.setToolTip("")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("static/start.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.startButton.setIcon(icon)
        self.startButton.setIconSize(QtCore.QSize(20, 20))
        self.startButton.setObjectName("startButton")
        self.stopButton = QtWidgets.QPushButton(self.centralwidget)
        self.stopButton.setGeometry(QtCore.QRect(190, 90, 150, 50))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.stopButton.setFont(font)
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap("static/pause.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.stopButton.setIcon(icon1)
        self.stopButton.setIconSize(QtCore.QSize(20, 20))
        self.stopButton.setObjectName("stopButton")
        self.devices = QtWidgets.QComboBox(self.centralwidget)
        self.devices.setGeometry(QtCore.QRect(20, 40, 721, 41))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.devices.setFont(font)
        self.devices.setInputMethodHints(QtCore.Qt.ImhNone)
        self.devices.setEditable(False)
        self.devices.setObjectName("devices")
        self.protocolFilterBeforeCapture = QtWidgets.QComboBox(self.centralwidget)
        self.protocolFilterBeforeCapture.setGeometry(QtCore.QRect(820, 40, 471, 41))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.protocolFilterBeforeCapture.setFont(font)
        self.protocolFilterBeforeCapture.setInputMethodHints(QtCore.Qt.ImhNone)
        self.protocolFilterBeforeCapture.setEditable(True)
        self.protocolFilterBeforeCapture.setObjectName("protocolFilterBeforeCapture")
        self.protocolFilterBeforeCapture.addItem("")
        self.protocolFilterBeforeCapture.addItem("")
        self.protocolFilterBeforeCapture.addItem("")
        self.protocolFilterBeforeCapture.addItem("")
        self.protocolFilterBeforeCapture.addItem("")
        self.protocolFilterBeforeCapture.addItem("")
        self.deviceLabel = QtWidgets.QLabel(self.centralwidget)
        self.deviceLabel.setGeometry(QtCore.QRect(20, 10, 381, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.deviceLabel.setFont(font)
        self.deviceLabel.setObjectName("deviceLabel")
        self.filterLabelBeforeCapture = QtWidgets.QLabel(self.centralwidget)
        self.filterLabelBeforeCapture.setGeometry(QtCore.QRect(820, 10, 381, 21))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.filterLabelBeforeCapture.setFont(font)
        self.filterLabelBeforeCapture.setObjectName("filterLabelBeforeCapture")
        self.protocolFilterAfterCapture = QtWidgets.QComboBox(self.centralwidget)
        self.protocolFilterAfterCapture.setGeometry(QtCore.QRect(820, 95, 471, 41))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.protocolFilterAfterCapture.setFont(font)
        self.protocolFilterAfterCapture.setInputMethodHints(QtCore.Qt.ImhNone)
        self.protocolFilterAfterCapture.setEditable(True)
        self.protocolFilterAfterCapture.setObjectName("protocolFilterAfterCapture")
        self.protocolFilterAfterCapture.addItem("")
        self.protocolFilterAfterCapture.addItem("")
        self.protocolFilterAfterCapture.addItem("")
        self.protocolFilterAfterCapture.addItem("")
        self.protocolFilterAfterCapture.addItem("")
        self.protocolFilterAfterCapture.addItem("")
        self.filterLabelAfterCapture = QtWidgets.QLabel(self.centralwidget)
        self.filterLabelAfterCapture.setGeometry(QtCore.QRect(550, 100, 311, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.filterLabelAfterCapture.setFont(font)
        self.filterLabelAfterCapture.setObjectName("filterLabelAfterCapture")
        self.packetsTable = QtWidgets.QTableWidget(self.centralwidget)
        self.packetsTable.setGeometry(QtCore.QRect(20, 150, 1451, 391))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.packetsTable.setFont(font)
        self.packetsTable.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.packetsTable.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.packetsTable.setObjectName("packetsTable")
        self.packetsTable.setColumnCount(7)
        self.packetsTable.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.packetsTable.setHorizontalHeaderItem(6, item)
        self.packetsTable.verticalHeader().setVisible(False)
        self.packetDetail = QtWidgets.QTreeWidget(self.centralwidget)
        self.packetDetail.setGeometry(QtCore.QRect(20, 550, 961, 291))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.packetDetail.setFont(font)
        self.packetDetail.setObjectName("packetDetail")
        item_0 = QtWidgets.QTreeWidgetItem(self.packetDetail)
        item_0 = QtWidgets.QTreeWidgetItem(self.packetDetail)
        item_0 = QtWidgets.QTreeWidgetItem(self.packetDetail)
        self.packetDetail.header().setVisible(False)
        self.packetData = QtWidgets.QTextBrowser(self.centralwidget)
        self.packetData.setGeometry(QtCore.QRect(990, 550, 481, 291))
        self.packetData.setObjectName("packetData")
        self.resetButton = QtWidgets.QPushButton(self.centralwidget)
        self.resetButton.setGeometry(QtCore.QRect(360, 90, 150, 50))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.resetButton.setFont(font)
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap("static/reset.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.resetButton.setIcon(icon2)
        self.resetButton.setIconSize(QtCore.QSize(20, 20))
        self.resetButton.setObjectName("resetButton")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1500, 22))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        font = QtGui.QFont()
        font.setPointSize(11)
        self.statusbar.setFont(font)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Sniffer"))
        self.startButton.setText(_translate("MainWindow", "开始捕获"))
        self.stopButton.setText(_translate("MainWindow", "停止捕获"))
        self.protocolFilterBeforeCapture.setItemText(0, _translate("MainWindow", "eth"))
        self.protocolFilterBeforeCapture.setItemText(1, _translate("MainWindow", "ip"))
        self.protocolFilterBeforeCapture.setItemText(2, _translate("MainWindow", "tcp"))
        self.protocolFilterBeforeCapture.setItemText(3, _translate("MainWindow", "udp"))
        self.protocolFilterBeforeCapture.setItemText(4, _translate("MainWindow", "http"))
        self.protocolFilterBeforeCapture.setItemText(5, _translate("MainWindow", "https"))
        self.deviceLabel.setText(_translate("MainWindow", "开始捕获前，选择想要监听的网卡："))
        self.filterLabelBeforeCapture.setText(_translate("MainWindow", "开始捕获前，选择过滤器："))
        self.protocolFilterAfterCapture.setItemText(0, _translate("MainWindow", "eth"))
        self.protocolFilterAfterCapture.setItemText(1, _translate("MainWindow", "ip"))
        self.protocolFilterAfterCapture.setItemText(2, _translate("MainWindow", "tcp"))
        self.protocolFilterAfterCapture.setItemText(3, _translate("MainWindow", "udp"))
        self.protocolFilterAfterCapture.setItemText(4, _translate("MainWindow", "http"))
        self.protocolFilterAfterCapture.setItemText(5, _translate("MainWindow", "https"))
        self.filterLabelAfterCapture.setText(_translate("MainWindow", "停止捕获后，选择过滤器："))
        item = self.packetsTable.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.packetsTable.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.packetsTable.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.packetsTable.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Source"))
        item = self.packetsTable.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.packetsTable.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length"))
        item = self.packetsTable.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Info"))
        self.packetDetail.headerItem().setText(0, _translate("MainWindow", "1"))
        __sortingEnabled = self.packetDetail.isSortingEnabled()
        self.packetDetail.setSortingEnabled(False)
        self.packetDetail.topLevelItem(0).setText(0, _translate("MainWindow", "1"))
        self.packetDetail.topLevelItem(1).setText(0, _translate("MainWindow", "2"))
        self.packetDetail.topLevelItem(2).setText(0, _translate("MainWindow", "3"))
        self.packetDetail.setSortingEnabled(__sortingEnabled)
        self.packetData.setMarkdown(_translate("MainWindow", "123\n"
"\n"
""))
        self.resetButton.setText(_translate("MainWindow", "重置过滤"))
