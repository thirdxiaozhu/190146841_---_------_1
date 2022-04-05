from unicodedata import name
from Tool import *
from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, in4_chksum, UDP, ICMP

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtGui import *
    from PyQt5.QtCore import *
    from PyQt5 import QtCore
except ImportError:
    import sip

# 构造窗口，绑定信号和槽


class Total:
    def __init__(self, mainWindow) -> None:
        self.ui = mainWindow
        self.terminal = self.ui.findChild(QTextEdit, "Terminal")
        self.clearBtn = self.ui.findChild(QPushButton, "clearTerminalBtn")
        self.panelList = self.ui.findChild(QListWidget, "panelList")
        self.stackedWidget = self.ui.findChild(QStackedWidget, "stackedWidget")

        self.panelList.itemClicked.connect(lambda: self.switchPanel())
        self.clearBtn.clicked.connect(lambda: self.clearTerminal())
        Mac(self)
        Arp(self)
        Ip(self)
        Udp(self)
        Tcp(self)
        Receiver(self)

    #根据左边list选定的序号切换窗口
    def switchPanel(self):
        currentRow = self.panelList.currentRow()
        self.stackedWidget.setCurrentIndex(currentRow)

    #清空terminal
    def clearTerminal(self):
        self.terminal.clear()

#MAC标签页
class Mac(QObject):
    #由于不能跨线程操作qt组件，故设置一信号，通过该信号触发主线程的槽以更改qt组件
    sniffcallback = QtCore.pyqtSignal(str)

    def __init__(self, total) -> None:
        super(Mac, self).__init__()
        self.isSniff = True
        self.sniffCount = 0
        self.total = total
        self.ui = total.ui
        self.targetLine = self.ui.findChild(QLineEdit, "targetMacLine")
        self.payloadLine = self.ui.findChild(QLineEdit, "payloadMacLine")
        self.timesLine = self.ui.findChild(QLineEdit, "timesMacLine")
        self.sendBtn = self.ui.findChild(QPushButton, "sendMacBtn")
        self.startSniffBtn = self.ui.findChild(QPushButton, "sniffStartMacBtn")
        self.stopSniffBtn = self.ui.findChild(QPushButton, "sniffStopMacBtn")
        self.sniffTimesLine = self.ui.findChild(QLineEdit, "sniffTimesMacLine")
        self.sendBtn.clicked.connect(lambda: self.sendMac())
        self.startSniffBtn.clicked.connect(lambda: self.startSniff())
        self.stopSniffBtn.clicked.connect(lambda: self.stopSniff())
        self.sniffcallback.connect(self.sniffCallBack)

    def sendMac(self):
        dst = self.targetLine.text()
        payload = self.payloadLine.text()
        times = self.timesLine.text()

        packet = Ether(dst=dst)/payload

        self.total.terminal.append(
            "<font color=#FF0000>##########  发送的  <font color=#FF9933>MAC</font>  帧内容  ##########</font>")
        self.total.terminal.append(
            "<font color=#FF9933>dst：</font>  %s" % packet[Ether].dst)
        self.total.terminal.append(
            "<font color=#FF9933>src：</font>  %s" % packet[Ether].src)
        self.total.terminal.append(
            "<font color=#FF9933>load：</font>  %s" % packet.load)
        packet.show()
        for i in range(int(times)):
            sendp(packet)
            self.total.terminal.append(
                "<font color=#C0C0C0>第%s个包已发送</font>" % (str(i+1)))

    def startSniff(self):
        def sniffThread():
            sniffNum = int(self.sniffTimesLine.text())
            if sniffNum > 0:
                sniff(prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff, count=sniffNum)
                self.stopSniff()
            elif sniffNum == 0:
                sniff(prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff)
            else:
                QMessageBox.warning(
                    self.ui, "警告", "捕获报文数量大于等于0", QMessageBox.Yes)
                self.stopSniff()

        if self.isSniff is True:
            self.sniffcallback.emit(
                "<font color=#FF0000>##########  开始捕获  <font color=#FF9933>MAC</font>  报文  ##########</font>")
            self.isSniff = False
            t = threading.Thread(target=sniffThread, name='LoopThread')
            t.start()
            self.startSniffBtn.setEnabled(False)
            self.stopSniffBtn.setEnabled(True)

    def ether_callback(self, pkt):
        self.sniffCount += 1
        self.sniffcallback.emit(
            '<font color=#000000>------------------</font>')
        self.sniffcallback.emit(
            '<font color=#C0C0C0>捕获到第%d个数据帧 </font>' % self.sniffCount)
        self.sniffcallback.emit(
            '<font color=#FF9933>目的MAC为：%s </font>' % pkt[Ether].dst)
        self.sniffcallback.emit(
            '<font color=#FF9933>源MAC为：%s </font>' % pkt[Ether].src)
        self.sniffcallback.emit(
            '<font color=#C0C0C0>捕获时间为：%s </font>' % pkt.time)
        self.sniffcallback.emit(
            '<font color=#000000>------------------</font>')

        time.sleep(1)

    def stopSniff(self):
        self.isSniff = True
        self.sniffCount = 0
        self.startSniffBtn.setEnabled(True)
        self.stopSniffBtn.setEnabled(False)

    def sniffCallBack(self, str):
        self.total.terminal.append(str)

#ARP窗口
class Arp(QObject):
    def __init__(self, total) -> None:
        super(Arp, self).__init__()
        self.total = total
        self.ui = total.ui
        self.op = self.ui.findChild(QComboBox, "opArpCombo")
        self.hwSrcArpLine = self.ui.findChild(QLineEdit, "hwSrcArpLine")
        self.hwDstArpLine = self.ui.findChild(QLineEdit, "hwDstArpLine")
        self.ipSrcArpLine = self.ui.findChild(QLineEdit, "ipSrcArpLine")
        self.ipDstArpLine = self.ui.findChild(QLineEdit, "ipDstArpLine")
        self.sendBtn = self.ui.findChild(QPushButton, "sendArpBtn")

        self.sendBtn.clicked.connect(lambda: self.sendArp())

    def sendArp(self):
        opValue = self.op.currentText()
        hwSrc = Tool.getText(self.hwSrcArpLine.text())
        hwDst = Tool.getText(self.hwDstArpLine.text())
        ipSrc = Tool.getText(self.ipSrcArpLine.text())
        ipDst = Tool.getText(self.ipDstArpLine.text())

        #广播
        eth = Ether()
        eth.dst = 'ff:ff:ff:ff:ff:ff'
        arp = ARP(op=opValue, hwsrc=hwSrc, psrc=ipSrc, hwdst=hwDst,
                  pdst=ipDst)

        pkt = eth/arp

        ans, unans = srp(pkt, timeout=2)
        self.total.terminal.append(
            "<font color=#FF0000>##########  开始捕获  <font color=#FA8072>MAC</font>  报文  ##########</font>")
        for i in range(len(ans)):
            self.total.terminal.append(
                "<font color=#FF0000>第%s个包</font>" % (i+1))
            self.total.terminal.append(str(ans[i]))

        #阻塞住，更好的解决方法是放在另一线程内
        ans.summary(lambda s, r: r.sprintf("%Ether.src% %ARP.psrc%"))

# IP窗口
class Ip(QObject):
    sniffcallback = QtCore.pyqtSignal(str)

    def __init__(self, total) -> None:
        super(Ip, self).__init__()
        self.total = total
        self.ui = total.ui
        self.isSniff = True
        self.sniffCount = 0
        self.srcLine = self.ui.findChild(QLineEdit, "ipSrcIpLine")
        self.dstLine = self.ui.findChild(QLineEdit, "ipDstIpLine")
        self.payloadLine = self.ui.findChild(QLineEdit, "payloadIpLine")
        self.sendBtn = self.ui.findChild(QPushButton, "sendIpBtn")
        self.startSniffBtn = self.ui.findChild(QPushButton, "sniffStartIpBtn")
        self.stopSniffBtn = self.ui.findChild(QPushButton, "sniffStopIpBtn")
        self.sniffTimesLine = self.ui.findChild(QLineEdit, "sniffTimesIpLine")
        self.sniffDstLine = self.ui.findChild(QLineEdit, "sniffDstIpLine")

        self.sendBtn.clicked.connect(lambda: self.sendIp())
        self.startSniffBtn.clicked.connect(lambda: self.startSniff())
        self.stopSniffBtn.clicked.connect(lambda: self.stopSniff())
        self.sniffcallback.connect(self.sniffCallBack)

    def sendIp(self):
        srcip = Tool.getText(self.srcLine.text())
        dstip = Tool.getText(self.dstLine.text())
        payload = Tool.getText(self.payloadLine.text())
        ip_packet = IP(dst=dstip, src=srcip)
        ip_packet_payload = ip_packet/payload
        x = raw(ip_packet_payload)
        ipraw = IP(x)
        ipraw.show()
        eth = Ether()
        packet = eth/ipraw
        sendp(packet)

        self.total.terminal.append(
            "<font color=#FF0000>##########  发送的  <font color=#0000FF>IP</font>  报文内容  ##########</font>")
        self.total.terminal.append(
            "<font color=#0000FF>version：</font>  %s" % packet[IP].version)
        self.total.terminal.append(
            "<font color=#0000FF>ihl：</font>  %s" % packet[IP].ihl)
        self.total.terminal.append(
            "<font color=#0000FF>tos：</font>  %s" % packet[IP].tos)
        self.total.terminal.append(
            "<font color=#0000FF>len：</font>%s" % packet[IP].len)
        self.total.terminal.append(
            "<font color=#0000FF>id：</font>  %s" % packet[IP].id)
        self.total.terminal.append(
            "<font color=#0000FF>flags：</font>%s" % packet[IP].flags)
        self.total.terminal.append(
            "<font color=#0000FF>frag：</font>%s" % packet[IP].frag)
        self.total.terminal.append(
            "<font color=#0000FF>ttl：</font>%s" % packet[IP].ttl)
        self.total.terminal.append(
            "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
        self.total.terminal.append(
            "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
        self.total.terminal.append(
            "<font color=#0000FF>src：</font>%s" % packet[IP].src)
        self.total.terminal.append(
            "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)

    def startSniff(self):
        def sniffThread():
            self.sniffCount = int(self.sniffTimesLine.text())
            #如果次数>0，通过sniffCount控制次数
            if self.sniffCount > 0:
                sniff(filter="ip", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff, count=self.sniffCount)
                self.stopSniff()
            elif self.sniffCount == 0:
                sniff(filter="ip", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff)
            else:
                QMessageBox.warning(
                    self.ui, "警告", "捕获报文数量大于等于0", QMessageBox.Yes)
                self.stopSniff()

        if self.isSniff is True:
            self.sniffcallback.emit(
                "<font color=#FF0000>##########  开始捕获  <font color=#0000FF>IP</font>  报文  ##########</font>")
            self.isSniff = False
            #线程
            t = threading.Thread(target=sniffThread, name='LoopThread')
            t.start()
            #按钮状态
            self.startSniffBtn.setEnabled(False)
            self.stopSniffBtn.setEnabled(True)

    def ether_callback(self, packet):
        if packet[IP].dst == Tool.getText(self.sniffDstLine.text()):
            self.sniffCount -= 1
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')
            self.sniffcallback.emit('<font color=#C0C0C0>捕获到第%d个数据帧 </font>' %
                                    (int(self.sniffTimesLine.text()) - int(self.sniffCount)))
            self.sniffcallback.emit(
                "<font color=#0000FF>version：</font>  %s" % packet[IP].version)
            self.sniffcallback.emit(
                "<font color=#0000FF>ihl：</font>  %s" % packet[IP].ihl)
            self.sniffcallback.emit(
                "<font color=#0000FF>tos：</font>  %s" % packet[IP].tos)
            self.sniffcallback.emit(
                "<font color=#0000FF>len：</font>%s" % packet[IP].len)
            self.sniffcallback.emit(
                "<font color=#0000FF>id：</font>  %s" % packet[IP].id)
            self.sniffcallback.emit(
                "<font color=#0000FF>flags：</font>%s" % packet[IP].flags)
            self.sniffcallback.emit(
                "<font color=#0000FF>frag：</font>%s" % packet[IP].frag)
            self.sniffcallback.emit(
                "<font color=#0000FF>ttl：</font>%s" % packet[IP].ttl)
            self.sniffcallback.emit(
                "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
            self.sniffcallback.emit(
                "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
            self.sniffcallback.emit(
                "<font color=#0000FF>src：</font>%s" % packet[IP].src)
            self.sniffcallback.emit(
                "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)
            self.sniffcallback.emit(
                '<font color=#C0C0C0>捕获时间为：%s</font>' % packet.time)
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')

        time.sleep(1)

    def stopSniff(self):
        self.isSniff = True
        self.sniffCount = int(self.sniffTimesLine.text())
        self.startSniffBtn.setEnabled(True)
        self.stopSniffBtn.setEnabled(False)

    def sniffCallBack(self, str):
        self.total.terminal.append(str)

#UDP窗口
class Udp(QObject):
    sniffcallback = QtCore.pyqtSignal(str)

    def __init__(self, total) -> None:
        super(Udp, self).__init__()
        self.total = total
        self.ui = total.ui
        self.isSniff = True
        self.sniffCount = 0
        self.srcIpLine = self.ui.findChild(QLineEdit, "ipSrcUdpLine")
        self.dstIpLine = self.ui.findChild(QLineEdit, "ipDstUdpLine")
        self.srcPortLine = self.ui.findChild(QLineEdit, "portSrcUdpLine")
        self.dstPortLine = self.ui.findChild(QLineEdit, "portDstUdpLine")
        self.sendBtn = self.ui.findChild(QPushButton, "sendUdpBtn")
        self.startSniffBtn = self.ui.findChild(QPushButton, "sniffStartUdpBtn")
        self.stopSniffBtn = self.ui.findChild(QPushButton, "sniffStopUdpBtn")
        self.sniffTimesLine = self.ui.findChild(QLineEdit, "sniffTimesUdpLine")
        self.sniffIpDstLine = self.ui.findChild(QLineEdit, "sniffIpDstUdpLine")
        self.sniffPortDstLine = self.ui.findChild(
            QLineEdit, "sniffPortDstUdpLine")

        self.sendBtn.clicked.connect(lambda: self.sendUdp())
        self.startSniffBtn.clicked.connect(lambda: self.startSniff())
        self.stopSniffBtn.clicked.connect(lambda: self.stopSniff())
        self.sniffcallback.connect(self.sniffCallBack)

    def sendUdp(self):
        srcip = Tool.getText(self.srcIpLine.text())
        dstip = Tool.getText(self.dstIpLine.text())
        srcport = Tool.getText(self.dstPortLine.text())
        dstport = Tool.getText(self.dstPortLine.text())
        ip_packet = IP(dst=dstip, src=srcip) / \
            UDP(dport=int(dstport), sport=int(srcport))
        ip_packet_payload = ip_packet
        x = raw(ip_packet_payload)
        ipraw = IP(x)
        ipraw.show()
        eth = Ether()
        packet = eth/ipraw
        sendp(packet)

        self.total.terminal.append(
            "<font color=#FF0000>##########  发送的  <font color=#00FF00>UDP</font>  报文内容  ##########</font>")
        self.total.terminal.append(
            "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
        self.total.terminal.append(
            "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
        self.total.terminal.append(
            "<font color=#0000FF>src：</font>%s" % packet[IP].src)
        self.total.terminal.append(
            "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)
        self.total.terminal.append(
            "<font color=#00FF00>sport：</font>%s" % packet[UDP].sport)
        self.total.terminal.append(
            "<font color=#00FF00>dport：</font>%s" % packet[UDP].dport)
        self.total.terminal.append(
            "<font color=#00FF00>len：</font>%s" % packet[UDP].len)
        self.total.terminal.append(
            "<font color=#00FF00>chksum：</font>%s" % packet[UDP].chksum)

    def startSniff(self):
        def sniffThread():
            self.sniffCount = int(self.sniffTimesLine.text())
            print(self.sniffCount)
            if self.sniffCount > 0:
                sniff(filter="udp", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff, count=self.sniffCount)
                self.stopSniff()
            elif self.sniffCount == 0:
                sniff(filter="udp", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff)
            else:
                QMessageBox.warning(
                    self.ui, "警告", "捕获报文数量大于等于0", QMessageBox.Yes)
                self.stopSniff()

        if self.isSniff is True:
            self.sniffcallback.emit(
                "<font color=#FF0000>##########  开始捕获  <font color=#00FF00>UDP</font>  报文  ##########</font>")
            self.isSniff = False
            t = threading.Thread(target=sniffThread, name='LoopThread')
            t.start()
            self.startSniffBtn.setEnabled(False)
            self.stopSniffBtn.setEnabled(True)

    def ether_callback(self, packet):
        if packet[UDP].dport == int(Tool.getText(self.sniffPortDstLine.text())) and packet[IP].dst == Tool.getText(self.sniffIpDstLine.text()):
            self.sniffCount -= 1
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')
            self.sniffcallback.emit('<font color=#C0C0C0>捕获到第%d个数据帧 </font>' %
                                    (int(self.sniffTimesLine.text()) - int(self.sniffCount)))
            self.sniffcallback.emit(
                "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
            self.sniffcallback.emit(
                "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
            self.sniffcallback.emit(
                "<font color=#0000FF>src：</font>%s" % packet[IP].src)
            self.sniffcallback.emit(
                "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)
            self.sniffcallback.emit(
                "<font color=#00FF00>sport：</font>%s" % packet[UDP].sport)
            self.sniffcallback.emit(
                "<font color=#00FF00>dport：</font>%s" % packet[UDP].dport)
            self.sniffcallback.emit(
                "<font color=#00FF00>len：</font>%s" % packet[UDP].len)
            self.sniffcallback.emit(
                "<font color=#00FF00>chksum：</font>%s" % packet[UDP].chksum)
            self.sniffcallback.emit(
                '<font color=#C0C0C0>捕获时间为：%s</font>' % packet.time)
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')

        time.sleep(1)

    def stopSniff(self):
        self.isSniff = True
        self.sniffCount = int(self.sniffTimesLine.text())
        self.startSniffBtn.setEnabled(True)
        self.stopSniffBtn.setEnabled(False)

    def sniffCallBack(self, str):
        self.total.terminal.append(str)

#TCP窗口
class Tcp(QObject):
    sniffcallback = QtCore.pyqtSignal(str)

    def __init__(self, total) -> None:
        super(Tcp, self).__init__()
        self.total = total
        self.ui = total.ui
        self.isSniff = True
        self.sniffCount = 0
        self.srcIpLine = self.ui.findChild(QLineEdit, "ipSrcTcpLine")
        self.dstIpLine = self.ui.findChild(QLineEdit, "ipDstTcpLine")
        self.srcPortLine = self.ui.findChild(QLineEdit, "portSrcTcpLine")
        self.dstPortLine = self.ui.findChild(QLineEdit, "portDstTcpLine")
        self.sendBtn = self.ui.findChild(QPushButton, "sendTcpBtn")
        self.startSniffBtn = self.ui.findChild(QPushButton, "sniffStartTcpBtn")
        self.stopSniffBtn = self.ui.findChild(QPushButton, "sniffStopTcpBtn")
        self.sniffTimesLine = self.ui.findChild(QLineEdit, "sniffTimesTcpLine")
        self.sniffIpDstLine = self.ui.findChild(QLineEdit, "sniffIpDstTcpLine")
        self.sniffPortDstLine = self.ui.findChild(
            QLineEdit, "sniffPortDstTcpLine")

        self.sendBtn.clicked.connect(lambda: self.sendTcp())
        self.startSniffBtn.clicked.connect(lambda: self.startSniff())
        self.stopSniffBtn.clicked.connect(lambda: self.stopSniff())
        self.sniffcallback.connect(self.sniffCallBack)

    def sendTcp(self):
        srcip = Tool.getText(self.srcIpLine.text())
        dstip = Tool.getText(self.dstIpLine.text())
        srcport = Tool.getText(self.dstPortLine.text())
        dstport = Tool.getText(self.dstPortLine.text())
        ip_packet = IP(dst=dstip, src=srcip) / \
            TCP(dport=int(dstport), sport=int(srcport))
        ip_packet_payload = ip_packet
        x = raw(ip_packet_payload)
        ipraw = IP(x)
        ipraw.show()
        eth = Ether()
        packet = eth/ipraw
        sendp(packet)

        self.total.terminal.append(
            "<font color=#FF0000>##########  发送的  <font color=#FF00FF>TCP</font>  报文内容  ##########</font>")
        self.total.terminal.append(
            "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
        self.total.terminal.append(
            "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
        self.total.terminal.append(
            "<font color=#0000FF>src：</font>%s" % packet[IP].src)
        self.total.terminal.append(
            "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)
        self.total.terminal.append(
            "<font color=#FF00FF>sport：</font>%s" % packet[TCP].sport)
        self.total.terminal.append(
            "<font color=#FF00FF>dport：</font>%s" % packet[TCP].dport)
        self.total.terminal.append(
            "<font color=#FF00FF>seq：</font>%s" % packet[TCP].seq)
        self.total.terminal.append(
            "<font color=#FF00FF>ack：</font>%s" % packet[TCP].ack)
        self.total.terminal.append(
            "<font color=#FF00FF>dataofs：</font>%s" % packet[TCP].dataofs)
        self.total.terminal.append(
            "<font color=#FF00FF>reserved：</font>%s" % packet[TCP].reserved)
        self.total.terminal.append(
            "<font color=#FF00FF>flags：</font>%s" % packet[TCP].flags)
        self.total.terminal.append(
            "<font color=#FF00FF>window：</font>%s" % packet[TCP].window)
        self.total.terminal.append(
            "<font color=#FF00FF>chksum：</font>%s" % packet[TCP].chksum)
        self.total.terminal.append(
            "<font color=#FF00FF>urgptr：</font>%s" % packet[TCP].urgptr)

    def startSniff(self):
        def sniffThread():
            self.sniffCount = int(self.sniffTimesLine.text())
            print(self.sniffCount)
            if self.sniffCount > 0:
                sniff(filter="tcp", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff, count=self.sniffCount)
                self.stopSniff()
            elif self.sniffCount == 0:
                sniff(filter="tcp", prn=self.ether_callback,
                      stop_filter=lambda x: self.isSniff)
            else:
                QMessageBox.warning(
                    self.ui, "警告", "捕获报文数量大于等于0", QMessageBox.Yes)
                self.stopSniff()

        if self.isSniff is True:
            self.sniffcallback.emit(
                "<font color=#FF0000>##########  开始捕获  <font color=#FF00FF>TCP</font>  报文  ##########</font>")
            self.isSniff = False
            t = threading.Thread(target=sniffThread, name='LoopThread')
            t.start()
            self.startSniffBtn.setEnabled(False)
            self.stopSniffBtn.setEnabled(True)

    def ether_callback(self, packet):
        if packet[TCP].dport == int(Tool.getText(self.sniffPortDstLine.text())) and packet[IP].dst == Tool.getText(self.sniffIpDstLine.text()):
            self.sniffCount -= 1
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')
            self.sniffcallback.emit('<font color=#C0C0C0>捕获到第%d个数据帧 </font>' %
                                    (int(self.sniffTimesLine.text()) - int(self.sniffCount)))
            self.sniffcallback.emit(
                "<font color=#0000FF>proto：</font>%s" % packet[IP].proto)
            self.sniffcallback.emit(
                "<font color=#0000FF>checksum：</font> %s" % packet[IP].chksum)
            self.sniffcallback.emit(
                "<font color=#0000FF>src：</font>%s" % packet[IP].src)
            self.sniffcallback.emit(
                "<font color=#0000FF>dst：</font>%s" % packet[IP].dst)
            self.sniffcallback.emit(
                "<font color=#FF00FF>sport：</font>%s" % packet[TCP].sport)
            self.sniffcallback.emit(
                "<font color=#FF00FF>dport：</font>%s" % packet[TCP].dport)
            self.sniffcallback.emit(
                "<font color=#FF00FF>seq：</font>%s" % packet[TCP].seq)
            self.sniffcallback.emit(
                "<font color=#FF00FF>ack：</font>%s" % packet[TCP].ack)
            self.sniffcallback.emit(
                "<font color=#FF00FF>dataofs：</font>%s" % packet[TCP].dataofs)
            self.sniffcallback.emit(
                "<font color=#FF00FF>reserved：</font>%s" % packet[TCP].reserved)
            self.sniffcallback.emit(
                "<font color=#FF00FF>flags：</font>%s" % packet[TCP].flags)
            self.sniffcallback.emit(
                "<font color=#FF00FF>window：</font>%s" % packet[TCP].window)
            self.sniffcallback.emit(
                "<font color=#FF00FF>chksum：</font>%s" % packet[TCP].chksum)
            self.sniffcallback.emit(
                "<font color=#FF00FF>urgptr：</font>%s" % packet[TCP].urgptr)
            self.sniffcallback.emit(
                '<font color=#C0C0C0>捕获时间为：%s</font>' % packet.time)
            self.sniffcallback.emit(
                '<font color=#000000>------------------</font>')

        time.sleep(1)

    def stopSniff(self):
        self.isSniff = True
        self.sniffCount = int(self.sniffTimesLine.text())
        self.startSniffBtn.setEnabled(True)
        self.stopSniffBtn.setEnabled(False)

    def sniffCallBack(self, str):
        self.total.terminal.append(str)

#报文嗅探窗口
class Receiver(QObject):
    sniffcallback = QtCore.pyqtSignal(str)
    additemcallback = QtCore.pyqtSignal(object)

    def __init__(self, total) -> None:
        super(Receiver, self).__init__()
        self.total = total
        self.ui = total.ui
        self.isSniff = True
        self.sniffCount = 0
        self.packetList = self.ui.findChild(QListWidget, "packetList")
        self.packetByteBrowser = self.ui.findChild(
            QTextEdit, "packetByteBrowser")
        self.startReceiveBtn = self.ui.findChild(
            QPushButton, "startReceiveBtn")
        self.stopReceiveBtn = self.ui.findChild(QPushButton, "stopReceiveBtn")

        self.startReceiveBtn.clicked.connect(lambda: self.startSniff())
        self.stopReceiveBtn.clicked.connect(lambda: self.stopSniff())
        self.sniffcallback.connect(self.sniffCallBack)
        self.additemcallback.connect(self.addItemCallBack)
        self.packetList.itemClicked.connect(lambda: self.selectItem())

        self.packetByteBrowser.setFocusPolicy(QtCore.Qt.NoFocus)

    def startSniff(self):
        def sniffThread():
            sniff(prn=(lambda x: self.ether_callback(x)),
                  stop_filter=lambda x: self.isSniff)
            self.stopSniff()

        if self.isSniff is True:
            self.sniffcallback.emit(
                "<font color=#FF0000>##########  开始捕获报文  ##########</font>")
            self.isSniff = False
            t = threading.Thread(target=sniffThread, name='LoopThread')
            t.start()
            self.startReceiveBtn.setEnabled(False)
            self.stopReceiveBtn.setEnabled(True)

    def ether_callback(self, pkt):
        self.sniffCount += 1
        self.additemcallback.emit(pkt)
        time.sleep(1)

    def stopSniff(self):
        self.isSniff = True
        self.sniffCount = 0
        self.startReceiveBtn.setEnabled(True)
        self.stopReceiveBtn.setEnabled(False)

    def sniffCallBack(self, str):
        self.total.terminal.append(str)

    def addItemCallBack(self, packet):
        item = Item(packet)  # 创建QListWidgetItem对象
        item.setSizeHint(QSize(200, 40))  # 设置QListWidgetItem大小
        widget = self.get_item_wight(packet)  # 调用上面的函数获取对应
        self.packetList.addItem(item)  # 添加item
        self.packetList.setItemWidget(item, widget)  # 为item设置widget

    def selectItem(self):
        self.packetByteBrowser.clear()
        item = self.packetList.selectedItems()[0]
        self.packetByteBrowser.append(hexdump(item.packet, dump=True))

        self.sniffcallback.emit(
            '<font color=#000000>------------------</font>')
        self.sniffcallback.emit(
            '<font color=#FF9933>目的MAC为：%s </font>' % item.packet[Ether].dst)
        self.sniffcallback.emit(
            '<font color=#FF9933>源MAC为：%s </font>' % item.packet[Ether].src)
        self.sniffcallback.emit(
            '<font color=#C0C0C0>捕获时间为：%s </font>' % item.packet.time)
        self.sniffcallback.emit(
            '<font color=#000000>------------------</font>')

    def get_item_wight(self, data):
        # 读取属性
        packet = data
        summary = str(packet.summary())
        # 总Widget
        widget = QWidget()
        # 总体横向布局

        nameLabel = QLabel(summary)
        layout_main = QHBoxLayout()
        layout_main.addWidget(nameLabel)  # 最左边的头像
        widget.setLayout(layout_main)  # 布局给wight
        return widget  # 返回wight
