import re
import time
import ida_hexrays
import idaapi
import ida_idp
import idc
import ida_search
import ida_funcs
import ida_auto
import idautils
import ida_ua
import ida_kernwin
from PyQt5 import QtCore
from keystone import *
from capstone import *
from unicorn import *
from unicorn.x86_const import *
from PyQt5.QtWidgets import QSizePolicy, QPushButton, QCheckBox, QApplication, QLineEdit, QRadioButton, QTextEdit, QVBoxLayout, QLabel, QHBoxLayout, QDialog, QTabWidget, QVBoxLayout, QWidget


PLUG_NAME = "Dejunk"


def get_arch_info():
    # Get information about the binary loaded in IDA
    inf = idaapi.get_inf_structure()

    is_64bit = inf.is_64bit()

    # IDA processor names to Unicorn, Capstone, and Keystone architecture and mode constants
    mapping = {
        'metapc': {
            'uc': (UC_ARCH_X86, UC_MODE_64) if is_64bit else (UC_ARCH_X86,  UC_MODE_32),
            'cs': (CS_ARCH_X86, CS_MODE_64) if is_64bit else (CS_ARCH_X86,  CS_MODE_32),
            'ks': (KS_ARCH_X86, KS_MODE_64) if is_64bit else (KS_ARCH_X86,  KS_MODE_32),
            'nop': 0x90
        },
        'ARM': {
            'uc': (UC_ARCH_ARM64, UC_MODE_ARM) if is_64bit else (UC_ARCH_ARM, UC_MODE_ARM),
            'cs': (CS_ARCH_ARM64, CS_MODE_ARM) if is_64bit else (CS_ARCH_ARM, CS_MODE_ARM),
            'ks': (KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN) if is_64bit else (KS_ARCH_ARM, KS_MODE_ARM),
            'nop': 0xd503201f if is_64bit else 0xe320f000
        },
        'mipsl': {
            'uc': (UC_ARCH_MIPS, UC_MODE_MIPS32),
            'cs': (CS_ARCH_MIPS, CS_MODE_MIPS32),
            'ks': (KS_ARCH_MIPS, KS_MODE_MIPS32),
            'nop': 0x00000000
        },
        'mipsb': {
            'uc': (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN),
            'cs': (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
            'ks': (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN),
            'nop': 0x00000000
        },
        # Add more architectures here...
    }

    arch_mode_map = mapping.get(inf.procname)
    if arch_mode_map is None:
        return None, None, None

    uc_arch, uc_mode = arch_mode_map['uc']
    cs_arch, cs_mode = arch_mode_map['cs']
    ks_arch, ks_mode = arch_mode_map['ks']
    nop_inst = arch_mode_map['nop']

    return (uc_arch, uc_mode), (cs_arch, cs_mode), (ks_arch, ks_mode), nop_inst


def match_func(match: re.Match):
    hex_value = match.group(2).lower()
    if len(hex_value) == 1:
        hex_value = "0" + hex_value
    return hex_value


def match_func1(match: re.Match):
    return chr(int(match.group(2), 16))


def parse_bytes(s: str = "", match_type: int = 0):
    pattern = r"(0x|\\x)([0-9a-fA-F]{1,2})"
    if re.findall(pattern, s):
        if match_type:
            return ' '.join([match_func(m) for m in re.finditer(pattern, s)])
        else:
            return re.sub(pattern, match_func1,s)
    return s


def nop(addr, endaddr, nop_inst):
    while (addr < endaddr):
        if (nop_inst == 0x90):
            idc.patch_byte(addr, nop_inst)
            addr += 1
        else:
            idc.patch_dword(addr, nop_inst)
            addr += 4


class DejunkForm(idaapi.PluginForm):
    def __init__(self, data: str = ""):
        super().__init__()
        self.data = data

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
        self.tabs.addTab(Options(self, self.data), "Options")

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
    def __init__(self, parent, data: str = ""):
        super().__init__()
        self.parent = parent
        self.text = data
        self.name = "Options"

        uc, cs, ks, self.nop_inst = get_arch_info()
        # print("Unicorn:", uc)
        # print("Capstone:", cs)
        # print("Keystone:", ks)
        print('Nop_inst:', hex(self.nop_inst))

        # Init capstone,keystone,unicorn
        self.cs = Cs(*cs)
        self.ks = Ks(*ks)
        self.uc = Uc(*uc)

        # bytecode
        self.bytes_code = b''

        # searched func list
        self.func_list = []

        # assembly
        self.asm = b''

        self.create_gui()
        


    def create_gui(self):
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
        self.startLine = QLineEdit(hex(seg.start_ea))
        self.addrLayout.addWidget(self.startLine)
        self.endLabel = QLabel("End:")
        self.endLabel.setMargin(10)
        self.addrLayout.addWidget(self.endLabel, 0, QtCore.Qt.AlignRight)
        self.endLine = QLineEdit(hex(seg.end_ea))
        self.addrLayout.addWidget(self.endLine)
        self.verticalLayout_2.addLayout(self.addrLayout)
        self.convertLayout = QHBoxLayout()  # 更改从 QVBoxLayout 到 QHBoxLayout
        self.convertLabel = QLabel("Convert")
        self.convertLabel.setMargin(10)
        self.bytesLabel = QLabel("Bytes:")
        self.bytesLabel.setMargin(10)
        self.bytesLayout = QVBoxLayout()
        self.bytesLayout.addWidget(self.bytesLabel)
        self.bytesEdit = QTextEdit()
        self.bytesEdit.focusInEvent = self.bytes_focusInEvent
        self.bytesEdit.focusOutEvent = self.bytes_focusOutEvent
        self.bytesLayout.addWidget(self.bytesEdit)
        
        if self.text:
            self.bytesEdit.setText(self.text)
        
        self.convertLayout.addLayout(self.bytesLayout)
        self.assemblyLabel = QLabel("Assembly:")
        self.assemblyLabel.setMargin(10)
        self.assemblyLayout = QVBoxLayout()
        self.assemblyLayout.addWidget(self.assemblyLabel)
        self.asmEdit = QTextEdit()
        self.asmEdit.focusInEvent = self.asm_focusInEvent
        self.asmEdit.focusOutEvent = self.asm_focusOutEvent
        self.assemblyLayout.addWidget(self.asmEdit)
        self.convertLayout.addLayout(self.assemblyLayout)
        self.verticalLayout_2.addLayout(self.convertLayout)
        self.optionLayout = QHBoxLayout()
        self.redefineCheck = QCheckBox("Auto re-define functions")
        self.optionLayout.addWidget(self.redefineCheck, 0, QtCore.Qt.AlignTop)
        self.verticalLayout_2.addLayout(self.optionLayout)
        self.applyButton = QPushButton("Apply")
        # self.testBtn = QPushButton("test")  # 测试按钮
        # self.verticalLayout_2.addWidget(self.testBtn)
        self.verticalLayout_2.addWidget(
            self.applyButton, 0, QtCore.Qt.AlignHCenter)
        self.horizontalLayout_4.addLayout(self.verticalLayout_2)
        self.bytesEdit.textChanged.connect(self.bytes_to_asm)
        self.asmEdit.textChanged.connect(self.asm_to_bytes)
        self.applyButton.clicked.connect(self.apply_clicked)
        # self.testBtn.clicked.connect(self.test)  # 测试按钮
        self.setLayout(self.horizontalLayout_4)
    
    # def test(self):
    #     pass
    
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
            self.text = parse_bytes(self.bytesEdit.toPlainText(), 1)
            self.bytes_code = bytes.fromhex(self.text)
            # 使用ks_asm函数将字节转换为汇编代码
            asm = ''
            for item in self.cs.disasm(self.bytes_code, 0):
                # addr = int(bytes_code) + item.address
                asm += item.mnemonic + " " + item.op_str+'\n'

            self.asmEdit.setText(asm)
        except Exception as e:
            # print(str(e))
            pass

    # 汇编转机器码
    def asm_to_bytes(self):
        try:
            self.asm = self.asmEdit.toPlainText().encode()
            # 使用ks_asm函数将字节转换为汇编代码
            text = ""
            for line in list(filter(None, self.asm.split(b'\n'))):
                encoding, count = self.ks.asm(line, 0)
                text += " ".join([format(c, "02x") for c in encoding])

            self.text = text
            self.bytesEdit.setText(text)
        except Exception as e:
            # print(str(e))
            pass

    def patch_bytes(self):
        start_addr = int(self.startLine.text(), 16)
        end_addr = int(self.endLine.text(), 16)

        if self.option_types[0].isChecked():
            searched_addr = ida_search.find_binary(start_addr,
                                                   end_addr, self.text, 16, ida_search.SEARCH_DOWN)
            while (searched_addr != idc.BADADDR):
                # try:
                #     self.func_list.append(idaapi.get_func(searched_addr).start_ea)
                # except:
                #     print("[!] AUTO RE-DEFINE: NOT FUNCTION AT "+hex(searched_addr))
                textlen = len(self.text.split())
                print("[+] PATCHED "+hex(searched_addr) +
                      ' '+str(textlen)+' BYTES')
                nop(searched_addr, searched_addr+textlen, self.nop_inst)
                searched_addr = ida_search.find_binary(searched_addr+textlen,
                                                       end_addr, self.text, 16, ida_search.SEARCH_DOWN)
        elif self.option_types[1].isChecked():

            bytes_like_pattern = parse_bytes(
                self.bytesEdit.toPlainText(), 0).encode('latin1')
            print(self.bytesEdit.toPlainText())
            addr_range = end_addr-start_addr
            current_bytes = idc.get_bytes(start_addr, addr_range)  # 可能导致卡死
            print(f"[!] bytes:{bytes_like_pattern}")
            res = re.search(bytes_like_pattern, current_bytes, flags=0)

            while (res != None):
                searched_addr = start_addr+res.span()[0]  # 起始地址加上匹配到下标的偏移
                # try:
                #     self.func_list.append(idaapi.get_func(searched_addr).start_ea)
                # except:
                #     print("[!] AUTO RE-DEFINE: NOT FUNCTION AT "+hex(searched_addr))
                textlen = res.span()[1]-res.span()[0]
                nop(searched_addr, searched_addr+textlen, self.nop_inst)
                print("[+] PATCHED "+hex(searched_addr) +
                      ' '+str(textlen)+' BYTES')
                start_addr = searched_addr+textlen
                addr_range = end_addr-start_addr
                current_bytes = idc.get_bytes(start_addr, addr_range)
                res = re.search(bytes_like_pattern, current_bytes, flags=0)

                # searched_addr=''
        print("[+] PATCH END")

    # def re_define(self):
    #     for func in self.func_list:
    #         print(hex(func))
    #         print(idaapi.del_func(func))
    #     for func in self.func_list:
    #         print(hex(func))
    #         print(idaapi.add_func(func))
    #         print(idaapi.mark_cfunc_dirty(func))

    def apply_clicked(self):
        '''
        TODO:
            # 部分匹配 (已完成)
            patch为指定指令 (非nop)
            # 自动U+P重新识别函数 (API有限,无法实现)
            # 选中花指令 右键打开插件界面 (已完成)
            unicorn修复跳转 (开发中)
        '''
        self.patch_bytes()
        # self.re_define()


class test_handler_t(idaapi.action_handler_t):
    def __init__(self, action):
        idaapi.action_handler_t.__init__(self)
        self.action = action

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    def activate(self, ctx):
        if self.action in "dejunk:open_window":
            f = DejunkForm()
            f.Show(PLUG_NAME)
        if self.action in "dejunk:send_code":
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1):
                start, end = t0.place(view).toea(), t1.place(view).toea()
                size = end - start
            data = idc.get_bytes(start, size)
            name = idc.get_name(start, idc.GN_VISIBLE)
            if not name:
                name = "data"
            if data:
                formated_data = " ".join("%02X" % b for b in data)
            f = DejunkForm(formated_data)
            f.Show(PLUG_NAME)


class UI_Hook(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE or idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(
                widget, popup, "dejunk:open_window", "Dejunk/")
            t0, t1, view = idaapi.twinpos_t(), idaapi.twinpos_t(), idaapi.get_current_viewer()
            if idaapi.read_selection(view, t0, t1) or idc.get_item_size(idc.get_screen_ea()) > 1:
                idaapi.attach_action_to_popup(
                    widget, popup, "dejunk:send_code", "Dejunk/")


class DejunkPlug(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    wanted_name = "Dejunk"
    comment = "Dejunk"
    help = "An ida plug-in that matches the bulk removal of junk instructions from the program"

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        print("Dejunk initialized!")
        self.registered_actions = []
        menu_actions = (idaapi.action_desc_t("dejunk:send_code", "Send Code to Dejunk", test_handler_t("dejunk:send_code"), None, None,
                                             9),
                        idaapi.action_desc_t("dejunk:open_window", "Open Dejunk Window", test_handler_t("dejunk:open_window"), None, None,
                                             9),)

        for action in menu_actions:
            idaapi.register_action(action)
            self.registered_actions.append(action.name)

        # Add ui hook
        self.ui_hook = UI_Hook()
        res = self.ui_hook.hook()
        print(res)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        f = DejunkForm()
        f.Show(PLUG_NAME)
        # MyWidget()

    def term(self):
        if hasattr(self, "ui_hook"):
            self.ui_hook.unhook()
        # Unregister actions
        for action in self.registered_actions:
            idaapi.unregister_action(action)
        pass
        # print("Dejunk terminated!")


def PLUGIN_ENTRY():
    return DejunkPlug()
