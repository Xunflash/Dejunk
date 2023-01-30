import idaapi
import idc
import ida_search
from PyQt5 import QtCore
from keystone import *
from capstone import *
from PyQt5.QtWidgets import QPushButton,QCheckBox, QLineEdit, QRadioButton, QTextEdit, QVBoxLayout, QLabel, QHBoxLayout, QTabWidget, QVBoxLayout, QWidget


PLUG_NAME = "IDAtest"


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
        print("[%s] Form closed." % PLUG_NAME)


class Options(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.name = "Options"
        self.create_gui()

    def create_gui(self):
        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        # self.addr = target_addr
        self.setWindowTitle('Dejunk')
        
        self.horizontalLayout_4 = QHBoxLayout()
        self.verticalLayout_2 = QVBoxLayout()
        self.matchingLayout = QHBoxLayout()
        self.matchingLayout.setContentsMargins(-1, -1, 700, -1)
        self.matchingLabel = QLabel("Matching mode")
        self.matchingLabel.setMargin(10)
        self.matchingLayout.addWidget(self.matchingLabel, 0, QtCore.Qt.AlignTop)
        
        self.option_types = [QRadioButton("All"), QRadioButton("Part")]
        self.option_types[0].setChecked(True)
        for qcheck in self.option_types:
            self.matchingLayout.addWidget(qcheck)
        
        self.verticalLayout_2.addLayout(self.matchingLayout)
        self.addrLayout = QHBoxLayout()
        self.addrLayout.setContentsMargins(-1, -1, 700, -1)
        self.addrLabel = QLabel("Address")
        self.addrLabel.setMargin(10)
        self.addrLayout.addWidget(self.addrLabel, 0, QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.startLabel = QLabel("Start:")
        self.startLabel.setMargin(10)
        self.addrLayout.addWidget(self.startLabel, 0, QtCore.Qt.AlignRight)
        self.startLine = QLineEdit(hex(idc.get_inf_attr(19)))
        self.addrLayout.addWidget(self.startLine)
        self.endLabel = QLabel("End:")
        self.endLabel.setMargin(10)
        self.addrLayout.addWidget(self.endLabel, 0, QtCore.Qt.AlignRight)
        self.endLine = QLineEdit(hex(idc.BADADDR))
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
        self.convertLayout.addWidget(self.bytesEdit)
        self.assemblyLabel = QLabel("Assembly:")
        self.assemblyLabel.setMargin(10)
        self.convertLayout.addWidget(self.assemblyLabel, 0, QtCore.Qt.AlignLeft)
        self.asmEdit = QTextEdit()
        self.convertLayout.addWidget(self.asmEdit)
        self.verticalLayout_2.addLayout(self.convertLayout)
        self.optionLayout = QHBoxLayout()
        self.redefineCheck = QCheckBox("Auto re-define functions")
        self.optionLayout.addWidget(self.redefineCheck, 0, QtCore.Qt.AlignTop)
        self.verticalLayout_2.addLayout(self.optionLayout)
        self.applyButton = QPushButton("Apply")
        self.verticalLayout_2.addWidget(self.applyButton, 0, QtCore.Qt.AlignHCenter)
        self.horizontalLayout_4.addLayout(self.verticalLayout_2)
        
        self.bytesEdit.textChanged.connect(self.bytes_to_asm)
        self.applyButton.clicked.connect(self.apply_clicked)
        
        self.setLayout(self.horizontalLayout_4)

    def convert_hex_string(self, s):
        if '0x' in s:
            return " ".join([format(int(c, 16), "02x") for c in s.split()])
        elif ' ' in s:
            return s
        else:
            return " ".join([s[i:i+2] for i in range(0, len(s), 2)])

    def bytes_to_asm(self):
        try:
            self.text = self.convert_hex_string(self.bytesEdit.toPlainText())
            self.bytes_code = bytes.fromhex(self.text)
            # 使用ks_asm函数将字节转换为汇编代码
            asm = ''
            for item in self.cs.disasm(self.bytes_code, 0):
                # addr = int(bytes_code) + item.address
                asm += item.mnemonic + " " + item.op_str+'\n'
            
            self.asmEdit.setText(asm)
        except:
            pass
    
    def apply_clicked(self):
        '''
        TODO:
            部分匹配
            自动U+P重新识别函数
            指定地址
            选中花指令 右键打开插件界面
        '''
        start_addr=int(self.startLine.text(),16)
        end_addr=int(self.endLine.text(),16)
        searched_addr=ida_search.find_binary(start_addr,
                    end_addr, self.text, 16, ida_search.SEARCH_DOWN)
        while(searched_addr!=0xffffffff):
            textlen=len(self.text.split())
            print("[!] PATCHED "+hex(searched_addr)+' '+str(textlen)+' BYTES')
            self.nop(searched_addr,searched_addr+textlen)
            searched_addr=ida_search.find_binary(searched_addr+textlen,
                end_addr, self.text, 16, ida_search.SEARCH_DOWN)
        print("[!] PATCH END")
        
    def nop(self, addr, endaddr):
        while (addr < endaddr):
            idc.patch_byte(addr, 0x90)
            addr += 1

class MyPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "test"
    comment = "test"
    help = "Something helpful"

    def init(self):
        print("MyPlugin initialized!")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        f = IDAtestForm()
        f.Show(PLUG_NAME)
        # MyWidget()

    def term(self):
        print("MyPlugin terminated!")


def PLUGIN_ENTRY():
    return MyPlugin()
