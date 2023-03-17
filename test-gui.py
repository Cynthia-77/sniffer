import sys

from PyQt5 import QtWidgets

import snifferGUI

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ui = snifferGUI.Ui_MainWindow()  # v
    MainWindow = QtWidgets.QMainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    # sc = SnifferController(ui)  # C
    # sc.loadAdapterIfaces()
    # sc.setConnection()
    sys.exit(app.exec_())
