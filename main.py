import sys

from PyQt5 import QtWidgets

import snifferGUI
import snifferController

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    ui = snifferGUI.Ui_MainWindow()  # view
    MainWindow = QtWidgets.QMainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    # sc = snifferGUIController(ui)  # controller
    # sc.loadAdapterIfaces()
    # sc.setConnection()
    sys.exit(app.exec_())
