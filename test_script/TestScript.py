import random
import niujiao

test_set=["lods"]
def RunDisasmTest(Opcode,Instruct,platform):
    disasm = niujiao.disasmfromstr(Opcode, platform)
    if disasm is None:
        print("{2}\t{3}位反汇编参数'{4}' ，结果为 None，原助记符'{1}'\t\t".format("", Instruct, "X",16*pow(2,platform-1),Opcode))
        return
    tmp = disasm["Result"]
    if tmp.strip(" ") != Instruct:
        print("{2}\t{3}位反汇编参数'{4}' ，结果'{0}'，原助记符'{1}'\t\t".format(tmp, Instruct, "X",16*pow(2,platform-1),Opcode))
    else:
        #print("{2}\t\t{3}位反汇编测试'{0}',原助记符'{1}'\t\t\t".format(tmp, Instruct, " ",16*pow(2,platform-1)))
        pass

def RunAsmTest(Opcode,Instruct,platform):
    asm = niujiao.asmfromstr(Instruct, platform)
    if asm ==None:
        print("{2}\t{3}位汇编参数'{4} ，结果为 None，原机器码'{1}'\t\t".format("", Opcode, "X",16*pow(2,platform-1),Instruct))
        return
    tmp = asm["Result"]
    if tmp != Opcode:
        print("{2}\t{3}位汇编参数'{4} ，结果'{0}'，原机器码'{1}'\t\t".format(tmp, Opcode, "X",16*pow(2,platform-1),Instruct))
    else:
        #print("{2}\t\t{3}位汇编测试结果'{0}',原机器码'{1}'\t\t\t".format(tmp, Opcode,  " ",16*pow(2,platform-1)))
        pass

if __name__=="__main__":
    for x in test_set:
        with open(".//test_data//{0}.txt".format(x),"r") as fd:
            data=fd.readlines()
            for y in data:
                if y=="\n" or y[0]==';': #忽略空行和注释
                    continue
                yy=y.replace("\n","").split("|")
                RunDisasmTest(yy[0],yy[1],int(yy[2]))
                RunAsmTest(yy[0],yy[1],int(yy[2]))