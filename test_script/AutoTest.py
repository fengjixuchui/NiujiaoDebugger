import os
import re
import niujiao

"""
提取手册中指令的描述表格
"""
prefix_str=["REX","REP","REPE","REPNE"]
def generateTable():
    aa = "<table"
    bb = "</table>"
    filename = ["2a", "2b", "2c"]
    table = open("table.txt", "w+", encoding="utf8")
    filter_str = ['style="', 'cellspacing="', 'class="', 'rowspan="', 'href="', 'colspan="']
    tables = 0
    opcodes = 0
    for x in filename:
        with open(x + ".html", "r", encoding="utf8") as file:
            content = file.read()
            for y in filter_str:
                pp0 = 0
                pp1 = 0
                while content.find(y) > 0:
                    pp0 = content.find(y)
                    pp1 = content.find('"', pp0 + len(y)) + 1
                    sss = content[pp0:pp1]
                    content = content.replace(sss, "")
            pos1 = 0
            pos2 = 0
            while True:
                pos1 = content.find(aa, pos2)
                if pos1 < 1:
                    break
                pos2 = content.find(bb, pos1)
                tables = tables + 1
                tmp = content[pos1:pos2]
                # 过滤非指令解释的表格
                if tmp.find(">Opcode") > 0 and tmp.find(">Description") > 0 and tmp.find(">64") > 0 or tmp.find("<td ><p  >EVEX.256") > 0 or \
                        tmp.find("<td ><p  >EVEX.NDS") > 0 or tmp.find("<td ><p  >VEX.NDS") > 0 or tmp.find("<td ><p  >VEX.NDS") > 0 \
                        or tmp.find("<td ><p  >EVEX.NDD") > 0 or tmp.find("<tr ><td  ><p  >VPTERNLOGD") > 0:  # or tmp.find("table  ><tr ><td ><p  >Opcode")>0:
                    table.write(tmp)  # .replace("<td","\n\t\t<td"))
                    table.write("\n")
                    opcodes = opcodes + 1
def Get64BitSupportedMode(str):
    MapStr={"Valid":True,
            "Valid*": True,
            "V": True,
            "V1": True, #没看到有介绍
            "V2": True, #没看到有介绍
            "Invalid":False,
            "Inv.":False,
            "Invalid*":False,
            "NE":"SUPPORT64_BIT_NE",
            "N.E.":"SUPPORT64_BIT_NE",
            "N. E.":"SUPPORT64_BIT_NE",
            "Valid":"SUPPORT64_BIT_NP",
            "Valid":"SUPPORT64_BIT_NI",
            "N.S.":"SUPPORT64_BIT_NS",}
    return MapStr[str]
def Get32BitSupportedMode(str):
    MapStr={"Valid":True,
            "Valid*": True,
            "V": True,
            "V2": True,
            "I":False,
            "I2":False,
            "Invalid":False,
            "Invalid*":False,
            "N. E.":"SUPPORT32_BIT_NE",
            "NE":"SUPPORT32_BIT_NE",
            "N.E.2":"SUPPORT32_BIT_NE",
            "N.E1.":"SUPPORT32_BIT_NE",
            "N.E.1":"SUPPORT32_BIT_NE",
            "N.E.":"SUPPORT32_BIT_NE",
            "N.E":"SUPPORT32_BIT_NE",
            "Valid":"SUPPORT32_BIT_NP",
            "Valid":"SUPPORT32_BIT_NI",
            "N.S.":"SUPPORT32_BIT_NS",}
    return MapStr[str]
def GetCLSupportedMode(str):
    MapStr={"Valid":True,
            "Valid*": True,
            "OSPKE":"0",
            "Invalid":False,
            "N. E.":"SUPPORT_CL_NE",
            "N.E.":"SUPPORT_CL_NE",}
    return MapStr[str]
def cutItem(tableStr):
    Mnemonic=re.compile(r" [A-Z\d]{3,}[^.][ ]?")
    if tableStr.find(">Opcode") < 0:
        return
    pos1=0
    pos2=0
    mode = 0
    while tableStr.find("<tr", pos2) > 0:
        pos1 = tableStr.find("<tr", pos2)
        pos2 = tableStr.find("</tr", pos1)
        pos2 = tableStr.find(">", pos2) + 1
        tmp = tableStr[pos1:pos2]
        count = tmp.count("<td")
        if tmp.find(">Opcode") > 0:
            if count == 5:
                if tmp.find(">Instruction") > 0:
                    mode = 111
                elif tmp.find(">CPUID<") > 0:
                    mode = 222
                elif tmp.find(">Compat") > 0:
                    mode = 333
        else:
            item_count = -1
            opcode = 0
            instruct = ""
            mode64bit = "0"
            mode32bit = "0"
            modeCLbit = "0"
            parameter = "PACK_OPERAND(ZERO_OPERAND,0,0,0,0,0,0,0,0)"
            GroupPos = -1
            CpuMemo = ""
            Prefix = 0
            AsmFunc = "CAsm::Asm_None"
            while tmp.find("<td") > 0:
                item_count = item_count + 1
                pp0 = 0
                pp1 = 0
                pp0 = tmp.find("<td", pp1) + len("<td")
                pp1 = tmp.find("</td>", pp0)
                #删除一些格式文本
                cc = tmp[pp0:pp1].replace("<p  >", "").replace("<i>", "").replace("</i>", "")
                cc = cc.replace("<span >", "").replace("</span>", "").replace("&lt;", "").replace("&gt;", "")
                cc = cc.replace("<p >", "").replace("<br/>", "").replace("&lt;", "").replace("&gt;", "").replace("amp;","").replace(" >", "").replace("  >", "")
                tmp = tmp[pp1:]
                if count == 5:
                    sep_count = cc.count("</p>")
                    if sep_count > 0:
                        cc = cc.replace("</p>", " ", sep_count - 1).replace("</p>", "").replace("VPCMPUW"," VPCMPUW").replace("ibVPERMILPS", "ib VPERMILPS")  # 两个特例
                    if item_count == 0:
                        if mode == 111:
                            opcode = cc
                        else:
                            instruct_array = Mnemonic.findall(cc)
                            if len(instruct_array) > 0:
                                for x in instruct_array:
                                    if x.strip() not in prefix_str:
                                        instruct = x.replace(" ", "")
                                        break
                                OpcodePos = cc.find(instruct)
                                opcode=cc[:OpcodePos]
                                parameter=cc[OpcodePos:]
                    elif item_count == 1:
                        if mode == 111:
                            cc = cc.replace("*", "")  # 部分浮点指令后接着*号
                            instruct_array = cc.split(" ", maxsplit=1)
                            if len(instruct_array) > 1:
                                instruct = instruct_array[0]
                                parameter=instruct_array[1]
                            else:
                                instruct = cc
                    elif item_count == 2:
                        if cc == "":
                            continue
                        if cc == "VV":
                            mode64bit = Get64BitSupportedMode(cc[0])
                            mode32bit = Get32BitSupportedMode(cc[1])
                        else:
                            mode_array = cc.split("/")
                            if len(mode_array) == 1:
                                mode64bit = Get64BitSupportedMode(cc)
                            else:
                                mode64bit = Get64BitSupportedMode(mode_array[0])
                                mode32bit = Get32BitSupportedMode(mode_array[1])
                    elif item_count == 3:
                        try:
                            modeCLbit = GetCLSupportedMode(cc)
                        except:
                            CpuMemo = cc
                elif count == 6:  # Opcode # Instruction # Op/En # 64-bitMode # Compat/Leg Mode # Description
                    orig = cc.replace("</p>", " ")
                    cc = cc.replace("</p>", "")
                    if item_count == 0:
                        opcode = orig
                    elif item_count == 1:
                        instruct = cc
                    elif item_count == 3:
                        posd = 0
                        if cc.find("/") > 0:
                            posd = cc.find("/")
                        if posd > 0:
                            mode64bit = Get64BitSupportedMode(cc[:posd])
                            mode32bit = Get32BitSupportedMode(cc[posd + 1:])
                        elif cc == "VV":
                            mode64bit = Get64BitSupportedMode(cc[0])
                            mode32bit = Get32BitSupportedMode(cc[1])
                        else:
                            mode64bit = Get64BitSupportedMode(cc)
                    elif item_count == 4:
                        try:
                            modeCLbit = GetCLSupportedMode(cc)
                        except:
                            CpuMemo = cc
            if count==6:
                #print(opcode,"\t|\t",instruct,mode64bit,modeCLbit)
                RunTest(opcode,instruct,modeCLbit,mode64bit)

def RunTest(Opcode,Instruct,Supported32,Supported64):
    print("开始测试指令:机器码'{0}',助记符'{1}',支持32位'{2}',支持64位'{3}' ".format(Opcode,Instruct,Supported32,Supported64))
    if type(Supported32)!=bool or type(Supported64)!=bool:
        #print("\t\t参数格式不正确 跳过此条测试")
        return
    OpcodeList=Opcode.split(' ')
    InstructList=Instruct.split(' ')
    if len(InstructList)==1:
        asm=niujiao.asmfromstr(InstructList[0].lower())
        OpcodeStr=Opcode.replace(' ','')
        tmp=asm["Result"]
        result="X"
        if tmp==OpcodeStr:
            result=""
        print("{2}\t\t第一次汇编测试结果{0},原机器码{1}".format(tmp,OpcodeStr,result))
        disasm=niujiao.disasmfromstr(OpcodeStr,0)
        result="X"
        tmp=disasm["Result"]
        if tmp.replace(" ","")==InstructList[0].lower():
            result=""
        print("{2}\t\t第一次反汇编测试结果{0},原助记符{1}".format(tmp,InstructList[0].lower(),result))
    print("\n")
if __name__=="__main__":
    if not os.path.exists("table.txt"):
        print("开始整理 table")
        generateTable()
        print("整理 table 完成")
    with open("table.txt","r", encoding="utf8") as fd:
        while True:
            tableStr=fd.readline()
            if tableStr=="":
                break
            cutItem(tableStr)