from struct import pack
try:
    from PyQt5 import QtWidgets
except ImportError:
    import sip

class Tool:
    def __init__(self) -> None:
        pass

    def getText(text):
        if text == '':
            return None
        return text

class Item(QtWidgets.QListWidgetItem):
    def __init__(self, packet) -> None:
        super(Item, self).__init__()
        self.packet = packet
