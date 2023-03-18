import sys

from PyQt5 import QtWidgets

import snifferGUI
from snifferController import *

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ui = snifferGUI.Ui_MainWindow()  # view
    MainWindow = QtWidgets.QMainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sc = SnifferController(ui)  # controller
    # sc.loadAdapterIfaces()
    sc.set_connection()
    sys.exit(app.exec_())
