import re
import idaapi
import idc
import ida_search
from PyQt5 import QtCore
from keystone import *
from capstone import *
from PyQt5.QtWidgets import QSizePolicy, QPushButton, QCheckBox, QApplication, QLineEdit, QRadioButton, QTextEdit, QVBoxLayout, QLabel, QHBoxLayout, QDialog, QTabWidget, QVBoxLayout, QWidget


PLUG_NAME = "Dejunk"


def replace_func0(match):
    return chr(int(match.group(1), 16))


def replace_func1(match):
    return match.group(1)+' '


def parse_bytes(s, parse_type):
    s = s.replace(" ", '')
    if parse_type == 0:
        if '0x' in s:
            return re.sub(r"0x([A-Fa-f0-9]{2})", replace_func0, s)
        else:
            return re.sub(r"([A-Fa-f0-9]{2})", replace_func0, s)
    elif parse_type == 1:
        if '0x' in s:
            return re.sub(r"0x([A-Fa-f0-9]{2})", replace_func1, s)
        else:
            return re.sub(r"([A-Fa-f0-9]{2})", replace_func1, s)


def nop(addr, endaddr):
    while (addr < endaddr):
        idc.patch_byte(addr, 0x90)
        addr += 1


class IDAtestForm(idaapi.PluginForm):
    def __init__(self):
        super().__init__()

        # disable timeout for scripts
        self.old_timeout = idaapi.set_script_timeout(0)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def RemoveTab(self, index):
        pass

    def PopulateForm(self):
        self.tabs = QTabWidget()
        self.tabs.setMovable(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.remove_tabs)
        self.tabs.addTab(Options(self), "Options")

        layout = QVBoxLayout()
        layout.addWidget(self.tabs)
        self.parent.setLayout(layout)

    def remove_tabs(self, index):
        if not isinstance(self.tabs.widget(index), Options):
            self.tabs.removeTab(index)

    def OnClose(self, form):
        idaapi.set_script_timeout(self.old_timeout)
        # print("[%s] Form closed." % PLUG_NAME)


class Options(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.name = "Options"
        self.create_gui()

    def create_gui(self):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        # self.addr = target_addr
        self.setWindowTitle('Dejunk')

        self.horizontalLayout_4 = QHBoxLayout()
        self.verticalLayout_2 = QVBoxLayout()
        self.matchingLayout = QHBoxLayout()
        self.matchingLayout.setContentsMargins(-1, -1, 300, -1)
        self.matchingLabel = QLabel("Matching mode")
        self.matchingLabel.setMargin(10)
        self.matchingLayout.addWidget(
            self.matchingLabel, 0, QtCore.Qt.AlignTop)

        self.option_types = [QRadioButton("All"), QRadioButton("Part")]
        self.option_types[0].setChecked(True)
        for qcheck in self.option_types:
            self.matchingLayout.addWidget(qcheck)

        self.verticalLayout_2.addLayout(self.matchingLayout)
        self.addrLayout = QHBoxLayout()
        self.addrLayout.setContentsMargins(-1, -1, 300, -1)
        self.addrLabel = QLabel("Address")
        self.addrLabel.setMargin(10)
        self.addrLayout.addWidget(
            self.addrLabel, 0, QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        self.startLabel = QLabel("Start:")
        self.startLabel.setMargin(10)
        self.addrLayout.addWidget(self.startLabel, 0, QtCore.Qt.AlignRight)
        seg = idaapi.get_segm_by_name(".text")
        # self.startLine = QLineEdit(hex(idc.get_inf_attr(19)))#起始地址
        self.startLine = QLineEdit(hex(seg.start_ea))
        self.addrLayout.addWidget(self.startLine)
        self.endLabel = QLabel("End:")
        self.endLabel.setMargin(10)
        self.addrLayout.addWidget(self.endLabel, 0, QtCore.Qt.AlignRight)
        # self.endLine = QLineEdit(hex(idc.BADADDR))#结束地址
        self.endLine = QLineEdit(hex(seg.end_ea))
        self.addrLayout.addWidget(self.endLine)
        self.verticalLayout_2.addLayout(self.addrLayout)
        self.convertLayout = QVBoxLayout()
        self.convertLabel = QLabel("Convert")
        self.convertLabel.setMargin(10)
        self.convertLayout.addWidget(self.convertLabel, 0, QtCore.Qt.AlignTop)
        self.bytesLabel = QLabel("Bytes:")
        self.bytesLabel.setMargin(10)
        self.convertLayout.addWidget(self.bytesLabel, 0, QtCore.Qt.AlignLeft)
        self.bytesEdit = QTextEdit()
        self.bytesEdit.focusInEvent = self.bytes_focusInEvent
        self.bytesEdit.focusOutEvent = self.bytes_focusOutEvent
        self.convertLayout.addWidget(self.bytesEdit)
        self.assemblyLabel = QLabel("Assembly:")
        self.assemblyLabel.setMargin(10)
        self.convertLayout.addWidget(
            self.assemblyLabel, 0, QtCore.Qt.AlignLeft)
        self.asmEdit = QTextEdit()
        self.asmEdit.focusInEvent = self.asm_focusInEvent
        self.asmEdit.focusOutEvent = self.asm_focusOutEvent
        self.convertLayout.addWidget(self.asmEdit)
        self.verticalLayout_2.addLayout(self.convertLayout)
        self.optionLayout = QHBoxLayout()
        self.redefineCheck = QCheckBox("Auto re-define functions")
        self.optionLayout.addWidget(self.redefineCheck, 0, QtCore.Qt.AlignTop)
        self.verticalLayout_2.addLayout(self.optionLayout)
        self.applyButton = QPushButton("Apply")
        self.verticalLayout_2.addWidget(
            self.applyButton, 0, QtCore.Qt.AlignHCenter)
        self.horizontalLayout_4.addLayout(self.verticalLayout_2)

        self.bytesEdit.textChanged.connect(self.bytes_to_asm)
        self.asmEdit.textChanged.connect(self.asm_to_bytes)
        self.applyButton.clicked.connect(self.apply_clicked)

        self.setLayout(self.horizontalLayout_4)

    # 获取焦点时断开连接 失去焦点时重新连接

    def bytes_focusInEvent(self, event):
        self.asmEdit.textChanged.disconnect(self.asm_to_bytes)
        super().focusInEvent(event)

    def bytes_focusOutEvent(self, event):
        self.asmEdit.textChanged.connect(self.asm_to_bytes)
        super().focusOutEvent(event)

    def asm_focusInEvent(self, event):
        self.bytesEdit.textChanged.disconnect(self.bytes_to_asm)
        super().focusInEvent(event)

    def asm_focusOutEvent(self, event):
        self.bytesEdit.textChanged.connect(self.bytes_to_asm)
        super().focusOutEvent(event)

    # 机器码转汇编
    def bytes_to_asm(self):
        try:
            self.text = parse_bytes(self.bytesEdit.toPlainText(), 1)[:-1]
            self.bytes_code = bytes.fromhex(self.text)
            # 使用ks_asm函数将字节转换为汇编代码
            asm = ''
            for item in self.cs.disasm(self.bytes_code, 0):
                # addr = int(bytes_code) + item.address
                asm += item.mnemonic + " " + item.op_str+'\n'

            self.asmEdit.setText(asm)
        except:
            pass

    # 汇编转机器码
    def asm_to_bytes(self):
        try:
            self.asm = self.asmEdit.toPlainText().encode()
            # 使用ks_asm函数将字节转换为汇编代码
            text = ''
            for line in list(filter(None, self.asm.split(b'\n'))):
                encoding, count = self.ks.asm(line, 0)
                text += " ".join([format(c, "02x") for c in encoding])

            self.bytesEdit.setText(text)
        except:
            pass

    def patch_bytes(self):
        start_addr = int(self.startLine.text(), 16)
        end_addr = int(self.endLine.text(), 16)

        if self.option_types[0].isChecked():
            searched_addr = ida_search.find_binary(start_addr,
                                                   end_addr, self.text, 16, ida_search.SEARCH_DOWN)
            while (searched_addr != 0xffffffff):
                textlen = len(self.text.split())
                print("[+] PATCHED "+hex(searched_addr) +
                      ' '+str(textlen)+' BYTES')
                nop(searched_addr, searched_addr+textlen)
                searched_addr = ida_search.find_binary(searched_addr+textlen,
                                                       end_addr, self.text, 16, ida_search.SEARCH_DOWN)
        elif self.option_types[1].isChecked():
            addr_range = end_addr-start_addr
            bytes_like_pattern = parse_bytes(
                self.bytesEdit.toPlainText(), 0).encode('latin1')
            current_bytes = idc.get_bytes(start_addr, addr_range)  # 可能导致卡死
            res = re.search(bytes_like_pattern, current_bytes, flags=0)
            while (res != None):
                searched_addr = start_addr+res.span()[0]  # 起始地址加上匹配到下标的偏移
                textlen = res.span()[1]-res.span()[0]
                nop(searched_addr, searched_addr+textlen)
                print("[+] PATCHED "+hex(searched_addr) +
                      ' '+str(textlen)+' BYTES')
                current_bytes = idc.get_bytes(start_addr, addr_range)
                res = re.search(bytes_like_pattern, current_bytes, flags=0)
                # searched_addr=''
        print("[+] PATCH END")

    def apply_clicked(self):
        '''
        TODO:
            # 部分匹配
            patch为指定指令(非nop)
            自动U+P重新识别函数
            选中花指令 右键打开插件界面
        '''
        self.patch_bytes()
        # self.redefine()


class DejunkPlug(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "Dejunk"
    comment = "Dejunk"
    help = "An ida plug-in that matches the bulk removal of junk instructions from the program"

    def init(self):
        # print("Dejunk initialized!")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        f = IDAtestForm()
        f.Show(PLUG_NAME)
        # MyWidget()

    def term(self):
        pass
        # print("Dejunk terminated!")


def PLUGIN_ENTRY():
    return DejunkPlug()
