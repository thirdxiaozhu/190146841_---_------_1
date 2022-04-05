import sys
from PyQt5 import sip
try:
    import PyQt5.QtGui as QtGui
    from PyQt5.QtWidgets import *
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
except ImportError:
    import sip
import MainWindow
import Work


#启动窗口
def main():
    app = QApplication(sys.argv)
    mainWindow = QMainWindow()
    ui = MainWindow.Ui_Form()
    ui.setupUi(mainWindow)
    mainWindow.setWindowTitle("课程设计")
    Work.Total(mainWindow)
    mainWindow.show()
    sys.exit(app.exec_())



if __name__ == "__main__":
    main()