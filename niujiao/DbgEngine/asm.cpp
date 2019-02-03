/*
实现汇编引擎
*/
#include "stdafx.h"
#include "asm.h"
#include "asm_general_struct.h"
#include <string.h>
#include <Shlwapi.h>
#include "Disasm_three_3a.h"

CStrTrie* CAsm::m_strTrie = nullptr;
CAsm::CAsm()
{
	//初始化前缀树 
	if (m_strTrie == nullptr)
	{
		m_strTrie = new CStrTrie();
		for (int i = 0; i < (sizeof(gAsmGeneralInstruct) / sizeof(SAsmInstruct)); i++)
		{
			m_strTrie->TrieAddStr(gAsmGeneralInstruct[i].m_Mnemonic, UINT64(gAsmGeneralInstruct[i].m_Operand), 0);
		}
	}
}

int CAsm::AsmFromStr(LPCTSTR asmStr,int platForm, SAsmResultSet* asmResultSet)
{
	if (asmResultSet == nullptr) return -1;
	char AsmStr[1024] = { 0 };
	//首先转成多字节  前缀树用的是多字节字符保存
	WideCharToMultiByte(CP_ACP, 0, asmStr, lstrlen(asmStr), AsmStr, 1024,nullptr,nullptr);

	if (strlen(AsmStr) == 0) return false;

	//分解汇编字符串 前缀->助记符->操作数0...4
	SAsmStr StructAsmStr = { 0 };
	if (SplitStr(AsmStr, &StructAsmStr) == false) return false ;

	//获取已定义的助记符信息
	UINT64 Addr = 0;
	m_strTrie->GetDataInTrie(StructAsmStr.m_Instruct, &Addr, nullptr);

	SInstructFmt *InstructFmt = reinterpret_cast<SInstructFmt*>(Addr);
	for(int i=0;i< MAX_INSTRUCT_NUM;i++) //逐个检查相关结构
	{
		bool ProcessResult = false;
		if ((InstructFmt + i)->AsmFunc !=0)
		{
			asmResultSet->m_TotalRecord += 1;
			SAsmResult TmpResult = { 0 };
			TmpResult.m_PlatForm = platForm;
			if ((InstructFmt + i)->m_GroupPos == -1) //不属于分组指令
			{
				//检查操作数数量是否匹配
				UINT64 Operand =(InstructFmt + i)->Operand;
				if (GET_OPERAND_NUM(Operand) != StructAsmStr.m_OperandNum)
				{
					(asmResultSet->m_AsmResult + i)->m_ErrorCode = ASM_ERROR_INCORRECT_OPERANDNUM;
					(asmResultSet->m_AsmResult + i)->m_TotalLength = 0;
					asmResultSet->m_FailRecord += 1;
					continue;
				}
				//如果是0个操作数的就不需要继续处理了
				if (StructAsmStr.m_OperandNum == 0)
					ProcessResult = true;
			}
			if(ProcessResult == false)
			{
				ProcessResult=(InstructFmt + i)->AsmFunc(&StructAsmStr, &TmpResult, InstructFmt + i);
			}
			//合并定义的操作码，前缀和处理结果
			if (ProcessResult == false)
			{
				(asmResultSet->m_AsmResult + i)->m_TotalLength = 0;
				asmResultSet->m_FailRecord += 1;
			}
			else
			{
				//拷贝前缀
				int pos = 0;
				if((UINT)(StructAsmStr.Prefix)>0)
				{
					// 添加 asmstr 里面的前缀
					for (int j = 0; j < MAX_PREFIX_NUM; j++)
					{
						if (StructAsmStr.Prefix[j])
							TmpResult.Prefix[j] = StructAsmStr.Prefix[j];
						if (TmpResult.Prefix[j])
						{
							(asmResultSet->m_AsmResult + i)->m_Result[pos] = TmpResult.Prefix[j];
							pos++;
							(asmResultSet->m_AsmResult + i)->m_PrefixLength++;
							(asmResultSet->m_AsmResult + i)->m_TotalLength++;
						}
					}
				}
				//拷贝操作码
				if((InstructFmt + i)->m_Opcode<=0xFF)
				{
					(asmResultSet->m_AsmResult + i)->m_Result[pos] = (InstructFmt + i)->m_Opcode;
					(asmResultSet->m_AsmResult + i)->m_OpcodeLength++;
					pos++;
					(asmResultSet->m_AsmResult + i)->m_TotalLength++;
				}
				else 
				{
					char* TmpOpcode = (char*)&((InstructFmt + i)->m_Opcode);
					if ((InstructFmt + i)->m_Opcode <= 0xFFFF)
					{
						(asmResultSet->m_AsmResult + i)->m_Result[pos] = TmpOpcode[1];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+1] = TmpOpcode[0];
						(asmResultSet->m_AsmResult + i)->m_OpcodeLength += 2;
						pos += 2;
						(asmResultSet->m_AsmResult + i)->m_TotalLength+=2;
					}
					else if ((InstructFmt + i)->m_Opcode <= 0xFFFFFF)
					{
						(asmResultSet->m_AsmResult + i)->m_Result[pos+0] = TmpOpcode[2];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+1] = TmpOpcode[1];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+2] = TmpOpcode[0];
						(asmResultSet->m_AsmResult + i)->m_OpcodeLength += 3;
						pos += 3;
						(asmResultSet->m_AsmResult + i)->m_TotalLength += 3;
					}
					else if ((InstructFmt + i)->m_Opcode <= 0xFFFFFFFF)
					{
						(asmResultSet->m_AsmResult + i)->m_Result[pos+0] = TmpOpcode[3];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+1] = TmpOpcode[2];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+2] = TmpOpcode[1];
						(asmResultSet->m_AsmResult + i)->m_Result[pos+3] = TmpOpcode[0];
						(asmResultSet->m_AsmResult + i)->m_OpcodeLength += 4;
						pos += 4;
						(asmResultSet->m_AsmResult + i)->m_TotalLength += 4;
					}
				}
				//拷贝操作数
				for(int kkk=0; kkk<TmpResult.m_OperandLength;kkk++)
				{
					(asmResultSet->m_AsmResult + i)->m_Result[pos] = TmpResult.m_Result[kkk];
					pos++;
				}

				(asmResultSet->m_AsmResult + i)->m_TotalLength = pos;
				asmResultSet->m_SuccessRecord += 1;
			}
		}
		else break; //条目都是按序排布的 没有则终止后续循环
	}
	return 0;
}

bool CAsm::StripStr(char * str) 
{
	int len = strlen(str);
	int pos1 = 0, pos2 = len-1;
	if (len == 0) return true;
	for (int i = 0; i < len; i++,pos1++)
	{
		if (*(str+pos1) != ' ' && *(str + pos1) != '\t' && *(str + pos1) != '\n')
			break;
	}
	for (int i = len-1; i>-1; i--, pos2--)
	{
		if (*(str + pos2) != ' '&& *(str + pos2) != '\t' &&*(str + pos2) != '\n')
			break;
	}
	if (len == (pos2 - pos1)) return true;
	strncpy(str, str+pos1, pos2 - pos1 +1);
	*(str + pos2 - pos1 + 1) = 0x00;
	return true;
}

bool CAsm::RemoveSpace(char * str)
{
	int len = strlen(str);
	int NonSpace = 0;
	for(int i=0;i<len;i++)
	{
		if(*(str+i)!=' ')
		{
			*(str + NonSpace) = *(str + i);
			NonSpace++;
		}
	}
	return true;
}

bool CAsm::SplitStr(char* str, SAsmStr* StructAsmStr)
{
	char TmpStr[1024] = { 0 };
	strcpy_s(TmpStr, str);
	char * Tmp1 = nullptr;
	bool Flag = true;
	StripStr(TmpStr);
	int Len = strlen(TmpStr);
	//切割助记符
	bool HasEmptiedSpace = false;
	for(int i=0;i<Len;i++) //第一遍先将不需要的字符清掉
	{
		if (TmpStr[i] == '\t' || TmpStr[i] == '\n' ||  TmpStr[i] == ',')
		{
			TmpStr[i] = 0x00;
			continue;
		}
		if (TmpStr[i] == ' ' && HasEmptiedSpace == false)
		{
			TmpStr[i] = 0x00;
			HasEmptiedSpace = true;
			continue;
		}
	}

	for(int i=0;i<Len;i++) //第二遍拷贝字符
	{
		if(TmpStr[i]==0x00)
		{
			Flag = true;
			continue;
		}
		if(Flag)
		{
			StructAsmStr->m_OperandNum++;
			if (*(StructAsmStr->m_Instruct) == 0x00)
			{
				if (strncmp(StructAsmStr->m_Instruct, "lock", 4) == 0)
					StructAsmStr->Prefix[1] = ASM_PREFIX_Lock_F0;
				else if (strncmp(StructAsmStr->m_Instruct, "repe", 4) == 0)
				{
					if (StructAsmStr->Prefix[2]) return false; //互斥
					else  StructAsmStr->Prefix[2] = ASM_PREFIX_Repe_F3;
				}
				else if (strncmp(StructAsmStr->m_Instruct, "repne", 5) == 0)
				{
					if (StructAsmStr->Prefix[2]) return false; //互斥
					else  StructAsmStr->Prefix[2] = ASM_PREFIX_Repne_F2;
				}
				else
					strcpy(StructAsmStr->m_Instruct, TmpStr + i);
			}
			else if (*(StructAsmStr->m_First) == 0x00) strcpy(StructAsmStr->m_First,TmpStr + i);
			else if (*(StructAsmStr->m_Second) == 0x00) strcpy(StructAsmStr->m_Second, TmpStr + i);
			else if (*(StructAsmStr->m_Third) == 0x00) strcpy(StructAsmStr->m_Third,TmpStr + i);
			else if (*(StructAsmStr->m_Forth) == 0x00) strcpy(StructAsmStr->m_Forth,TmpStr + i);
			Flag = false;
		}
	}
	StripStr(StructAsmStr->m_Instruct);
	StripStr(StructAsmStr->m_First);
	StripStr(StructAsmStr->m_Second);
	StripStr(StructAsmStr->m_Third);
	StripStr(StructAsmStr->m_Forth);
	StructAsmStr->m_OperandNum--; //减去指令中多余的一次
	return true;
}

bool CAsm::GetImmValue(char * tmpStr, int * immValue)
{
	char ImmStr[16] = { 0 };
	int len = strlen(tmpStr);
	if (len > 15)
		return false;
	strncpy(ImmStr, tmpStr, len);
	RemoveSpace(ImmStr);
	int Value = 0;
	if (*ImmStr == '0' && (*(ImmStr + 1) == 'x' || *(ImmStr + 1) == 'X')) //十六进制格式		 
	{
		if (StrToIntExA(ImmStr, STIF_SUPPORT_HEX, &Value) == false)
			return false;
	}
	else if(*ImmStr > '0'&&*ImmStr <= '9')//十进制格式
	{
		if (StrToIntExA(ImmStr, STIF_DEFAULT, &Value) == false)
			return false;	
	}
	else
		return false;

	if (immValue != NULL)
		*immValue = Value;
	return true;
}

bool CAsm::GetReg(char * tmpStr, int * Reg)
{
	if (tmpStr == nullptr)
		return false;
	for (int base = 0; base < 4; base++)
	{
		for (int i = 0; i < RG__MAX; i++)
		{
			if (strcmp(gRegister[RG__MAX * base+i], tmpStr) == 0)
			{
				if (Reg) *Reg = RG__MAX * base+i;
				return true;
			}
		}
	}
	return false;
}

bool CAsm::GetMemAddressInfo(char * tmpStr,S_MEM_ADDRESS* MemAddr)
{
	int StartFlag = 0;
	int EndFlag = 0;
	int CurPos=0;
	int len = strlen(tmpStr);
	for (int i = 0; i < len; i++)
	{
		if (*(tmpStr + i) == '[') StartFlag = i;
		else if (*(tmpStr + i) == ']') EndFlag = i;
	}
	if (EndFlag <= StartFlag)
		return false;
	//确定操作数宽度
	if (strncmp(tmpStr, "byte", 4) == 0)
		MemAddr->m_OperSize = 0;
	else if (strncmp(tmpStr, "word", 4) == 0)
		MemAddr->m_OperSize = 1;
	else if (strncmp(tmpStr, "dword", 5) == 0)
		MemAddr->m_OperSize = 2;
	else if (strncmp(tmpStr, "qword", 5) == 0)
		MemAddr->m_OperSize = 3;
	//确定段寄存器
	if (StartFlag > 2)
	{
		if (*(tmpStr + StartFlag - 1) == ':'&&*(tmpStr + StartFlag - 2) == 's') //存在段寄存器描述的情况
		{
			switch (*(tmpStr + StartFlag - 3))
			{
			case 'e':MemAddr->m_SegReg = ASM_PREFIX_Seg_ES_26; break;
			case 'c':MemAddr->m_SegReg = ASM_PREFIX_Seg_CS_2E; break;
			case 's':MemAddr->m_SegReg = ASM_PREFIX_Seg_SS_36; break;
			case 'd':MemAddr->m_SegReg = ASM_PREFIX_Seg_DS_3E; break;
			case 'f':MemAddr->m_SegReg = ASM_PREFIX_Seg_FS_64; break;
			case 'g':MemAddr->m_SegReg = ASM_PREFIX_Seg_GS_65; break;
			default:
				return false;
			}
		}
		else
		{
			//默认为 ds
			MemAddr->m_SegReg = ASM_PREFIX_Seg_DS_3E;
		}
	}
	//确定地址类型
	char tmpAddrStr[16] = { 0 };
	StartFlag++; //跳过 '[' 符号
	strncpy(tmpAddrStr, (tmpStr + StartFlag ), EndFlag - StartFlag);
	StripStr(tmpAddrStr); //清理多余的空格

	//检查是否有 + 号
	int PlusFlag = false;
	for (int i = 0; *(tmpAddrStr + i); i++)
	{
		if (*(tmpAddrStr + i) == '+' || *(tmpAddrStr + i) == '-' || *(tmpAddrStr + i) == '*')
		{
			PlusFlag = true;
			break;
		}
	}
	if (PlusFlag)
	{
		MemAddr->m_Type = 2;
		strcpy((char*)MemAddr->m_Addrtype.s_ModRm.m_ModRmStr, tmpAddrStr);
		return true;
	}
	else
	{
		//判断当前部分是否为立即数
		int TmpValue = 0;
		if (GetImmValue(tmpAddrStr, &TmpValue) == true)
		{
			MemAddr->m_Type = 0;
			MemAddr->m_Addrtype.s_Imm.m_ImmValue = (UINT64)TmpValue;
			strcpy((char*)MemAddr->m_Addrtype.s_Imm.m_ImmStr, tmpAddrStr);
		}
		else if(GetReg(tmpAddrStr, &TmpValue))
		{
			MemAddr->m_Type = 1;
			MemAddr->m_Addrtype.s_Reg.m_RegNum = TmpValue;
			strcpy((char*)MemAddr->m_Addrtype.s_Reg.m_RegStr,tmpAddrStr);
		}
		else
			return false;
	}
	//检查后续是否有偏移
	return true;
}

UINT64 CAsm::GetOpcode(UINT Opcode)
{
	if((Opcode&0xFF0000) ==0x0F0000)
	{
		if((Opcode&0xFF00)==0x3800)
			return ThreeByteCodeMap38[Opcode & 0xFF].Operand;
		else
			return ThreeByteCodeMap3A[Opcode & 0xFF].Operand;
	}
	else
	{
		if((Opcode&0xFF00)==0x0F00)
			return TwoByteCodeMap[Opcode & 0xFF].Operand;
		else
			return gOneByteCodeMap[Opcode & 0xFF].Operand;		
	}
}

bool CAsm::Asm_None(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

int CAsm::Asm_SIB(char * AsmStr, char ** SIBByte)
{
	//清除字符串内的空格
	
	RemoveSpace(AsmStr);
	int Reg[8] = { 0 }; //保存寄存器的数量 eax ecx edx ebx ebp esi edi
	int ImmValue = -1; //立即数的值
	int SS = 0b00;
	int Index = -1;
	bool IsNonNoneReg = false; //SS部分是否存在寄存器
	int PlusNum = 0;
	int len = strlen(AsmStr);
	for(int i=0;i<len;i++) //统计 + 号数量 
		if (*(AsmStr + i) == '+') PlusNum += 1;
	if (PlusNum < 0 || PlusNum>2) 
		return 0;
	PlusNum += 1; //一个加号分割前后两部分  依次类推
	for(int i=0;i<PlusNum;i++)  //循环处理被 + 号分割 的各个部分
	{
		int StartPos = 0;
		int EndPos = 0;
		for(int j=EndPos;j<len;j++)
		{
			if (*(AsmStr + j) == '+'|| j == len)
			{
				EndPos = j;
				break;
			}		
		}
		//判断当前部分是否为立即数
		if(*(AsmStr+StartPos)=='0'&&(*(AsmStr + StartPos+1) == 'x'|| *(AsmStr + StartPos+1) == 'X') //十六进制格式
			||(*(AsmStr + StartPos)>'0'&&*(AsmStr+StartPos)<='9') ) //十进制格式
		{
			char tmpStr[32] = { 0 };
			strncpy(tmpStr, AsmStr + StartPos, EndPos - StartPos);
			if (StrToIntExA(tmpStr + i, STIF_SUPPORT_HEX, &ImmValue) == false)
				return 0;
			Index = 0b100;
		}
		else
		{
			bool ScaleFlag = false;
			//判断当前寄存器是否带有缩放因子
			for (int j = StartPos; j < EndPos; j++)
			{
				if (*(AsmStr + j) == '*')
				{
					ScaleFlag = true;
					break;
				}
			}
			//判断当前是否为基本寄存器
			int* SSReg = NULL;
			if (strncmp(AsmStr + StartPos, "eax", 3) == 0) SSReg = &Reg[e_Eax];
			else if (strncmp(AsmStr + StartPos, "ecx", 3) == 0) SSReg = &Reg[e_Ecx];
			else if (strncmp(AsmStr + StartPos, "edx", 3) == 0) SSReg = &Reg[e_Edx];
			else if (strncmp(AsmStr + StartPos, "ebx", 3) == 0) SSReg = &Reg[e_Ebx];
			else if (strncmp(AsmStr + StartPos, "ebp", 3) == 0) SSReg = &Reg[e_Ebp];
			else if (strncmp(AsmStr + StartPos, "esi", 3) == 0) SSReg = &Reg[e_Esi];
			else if (strncmp(AsmStr + StartPos, "edi", 3) == 0) SSReg = &Reg[e_Edi];
			else return 0;
			if (ScaleFlag)
			{
				//检查因子是否正确
				char tmpScale = *(AsmStr + StartPos + 1);
				switch(tmpScale)
				{
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '8':
				case '9':
					*SSReg += *(AsmStr + StartPos + 1) - '0';
					break;
				default:
					return 0;
				}
			}
			else
				*SSReg += 1;
			
		}
		StartPos = EndPos + 1;
	}
	//整理合并各部分的结果
	//查找最大数量的寄存器
	int MaxReg = 4;
	int MediuReg = 4;
	int MinReg = 4; //最多只能同时存在两种寄存器 使用这个作为判断 sib 字符串的合法性
	for(int i=0;i< 8;i++)
	{
		if (Reg[i] >= Reg[MaxReg])
		{
			MinReg = MediuReg;
			MediuReg = MaxReg;
			MaxReg = i;
		}
	}
	if (MinReg > 0 || MediuReg > 2) return 0;
	//获取 index 部分的值
	Index = MaxReg;
	//获取 SS r32 部分的值
	switch(Reg[MaxReg])
	{
	case 0:
		if (ImmValue == -1)
			return 0;
		*SIBByte[0] = 0x25;
		*SIBByte[4] = (ImmValue >> 24);
		*SIBByte[3] = (ImmValue >> 16);
		*SIBByte[2] = (ImmValue >> 8);
		*SIBByte[1] = (ImmValue & 0xFF);
		return 5;
	case 1:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (MediuReg != 4)
		{
			*SIBByte[0] = (MaxReg << 3) + MediuReg;
			return 1;
		}		
		else
		{
			*SIBByte[0] = (MaxReg << 3) + 0b101;
			*SIBByte[4] = (ImmValue >> 24);
			*SIBByte[3] = (ImmValue >> 16);
			*SIBByte[2] = (ImmValue >> 8);
			*SIBByte[1] = (ImmValue & 0xFF);
			return 5;
		}
	case 2:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			*SIBByte[0] =(0b01<<6)+ (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MediuReg != e_Ebp||ImmValue>0xFF) 
				return 0;
			*SIBByte[0] = (0b01 << 6) + (MaxReg << 3) + 0b101;
			*SIBByte[1] = (ImmValue & 0xFF);
			return 2;
		}
	case 3: 
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			if (MediuReg == e_Ebp)
				return 0;
			*SIBByte[0] = (0b10 << 6) + (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MaxReg != e_Ebp || MediuReg != e_Ebp || ImmValue > 0xFFFFFFFF)
				return 0;
			*SIBByte[0] = (0b01 << 6) + (MaxReg << 3) + 0b101;
			*SIBByte[1] = (ImmValue & 0xFF);
			return 2;
		}
	case 4:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			*SIBByte[0] = (0b10 << 6) + (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MediuReg != e_Ebp || ImmValue > 0xFF)
				return 0;
			*SIBByte[0] = (0b10 << 6 )+ (MaxReg << 3) + 0b101;
			*SIBByte[4] = (ImmValue >> 24);
			*SIBByte[3] = (ImmValue >> 16);
			*SIBByte[2] = (ImmValue >> 8);
			*SIBByte[1] = (ImmValue & 0xFF);
			return 5;
		}
	case 5:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			if (MediuReg == e_Ebp)
				return 0;
			*SIBByte[0] = (0b10 << 6) + (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MaxReg != e_Ebp || MediuReg != e_Ebp || ImmValue > 0xFFFFFFFF)
				return 0;
			*SIBByte[0] = (0b10 << 6) + (MaxReg << 3) + 0b101;
			*SIBByte[4] = (ImmValue >> 24);
			*SIBByte[3] = (ImmValue >> 16);
			*SIBByte[2] = (ImmValue >> 8);
			*SIBByte[1] = (ImmValue & 0xFF);
			return 5;
		}
	case 8:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			*SIBByte[0] = (0b11 << 6) + (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MediuReg != e_Ebp || ImmValue > 0xFF)
				return 0;
			*SIBByte[0] = (0b11 << 6) + (MaxReg << 3) + 0b101;
			*SIBByte[4] = (ImmValue >> 24);
			*SIBByte[3] = (ImmValue >> 16);
			*SIBByte[2] = (ImmValue >> 8);
			*SIBByte[1] = (ImmValue & 0xFF);
			return 5;
		}
	case 9:
		if ((MediuReg == 4 && ImmValue == -1) || (MediuReg != 4 && ImmValue != -1)) return 0;
		if (ImmValue == -1)
		{
			if (MediuReg == e_Ebp)
				return 0;
			*SIBByte[0] = (0b11 << 6) + (MaxReg << 3) + MediuReg;
			return 1;
		}
		else
		{
			if (MaxReg != e_Ebp || MediuReg != e_Ebp || ImmValue > 0xFFFFFFFF)
				return 0;
			*SIBByte[0] = (0b11 << 6) + (MaxReg << 3) + 0b101;
			*SIBByte[4] = (ImmValue >> 24);
			*SIBByte[3] = (ImmValue >> 16);
			*SIBByte[2] = (ImmValue >> 8);
			*SIBByte[1] = (ImmValue & 0xFF);
			return 5;
		}
	default:
		return 0;
	}
	return 0;
}

int CAsm::Asm_ModRm(char* AsmStr, char ** ModeRmByte, int base)
{
	//dword ptr 和 ds: 这两部分可选
	char tmpStr[MAX_ASM_STR_LENGTH] = { 0 };
	int len = strlen(tmpStr);
	int SegReg = RG__DS; //默认为ds段寄存器
	bool IsSibByte = false;
	strncpy(tmpStr, AsmStr, len);
	int OffsetLen = -1; //0:无偏移 1:8位偏移 2: 32位偏移
	int ModByte = 0b00;
	int RmByte = -1;
	for(int i=0;i<len;i++)
	{
		if (*(tmpStr + i) == ' ')
		{
			*(tmpStr + i) = 0x00;
			break;
		}
	}
	int pos = 0;
	int endPos = 0;
	//检查 两端操作数位数是否相等
	if (strcmp(tmpStr, "dword") == 0)
	{
		if (base != 2) return 0;
		pos += 5;
	}
	else if(strcmp(tmpStr,"word")==0)
	{
		if (base != 1)return 0;
		pos += 5;
	}
	else if(strcmp(tmpStr,"byte")==0)
	{
		if (base != 0) return 0;
		pos += 5;
	}
	for(int i=pos;*(tmpStr+i);i++)
	{
		if(*(tmpStr+i)=='p'&&*(tmpStr + i + 1) == 't'&&*(tmpStr + i + 1) == 'r')//查找后续的 ptr 字符  汇编字符串可以没有此标记
		{
			i += 2;
		}
		else if(*(tmpStr + i) == '[')
		{
			pos = i;
			break;
		}
		else if (*(tmpStr + i) == 'd'&&*(tmpStr + i + 1) == 's'&&*(tmpStr + i + 2) == ':') //检查段寄存器
		{
			SegReg = RG__DS;
			i += 2;
		}
		else if (*(tmpStr + i) == 'e'&&*(tmpStr + i + 1) == 's'&&*(tmpStr + i + 2) == ':')
		{
			SegReg = RG__ES;
			i += 2;
		}
		else if (*(tmpStr + i) == 's'&&*(tmpStr + i + 1) == 's'&&*(tmpStr + i + 2) == ':')
		{
			SegReg = RG__SS;
			i += 2;
		}
		else if (*(tmpStr + i) == 'g'&&*(tmpStr + i + 1) == 's'&&*(tmpStr + i + 2) == ':')
		{
			SegReg = RG__GS;
			i += 2;
		}
		else if (*(tmpStr + i) == 'f'&&*(tmpStr + i + 1) == 's'&&*(tmpStr + i + 2) == ':')
		{
			SegReg = RG__FS;
			i += 2;
		}
	}
	//检查结尾的 ] 
	for(int i=pos;i<len;i++)
	{
		if(*(tmpStr+i)==']')
		{
			endPos = i;
			break;
		}
		else if(*(tmpStr+i)=='+' || *(tmpStr + i) == '*')
		{
			IsSibByte = true; //中括号内存在 + 或者 * 号 则解释为sib字节
		}
		else if(*(tmpStr + i) == 0x00) //没有匹配的 ] 符号
		{
			return false;
		}
	}
	//检查后续是否存在立即数偏移
	bool PlusFlag = false; //加号标志
	int ImmOperand = 0;
	for(int i=(endPos+1);i<len;i++)
	{
		if (*(tmpStr + i) == '+') PlusFlag = true;
		if(PlusFlag&&*(tmpStr+i)=='0'&&(*(tmpStr+i)=='x'|| *(tmpStr + i) == 'X'))
		{
			if (StrToIntExA(tmpStr + i, STIF_SUPPORT_HEX, &ImmOperand) == false)
				return false;			
		}
	}
	if(PlusFlag==false) //没有偏移的情况
	{
		ModByte = 0b00;
	}
	else
	{
		if ((UINT)ImmOperand > 0xFF) //32位偏移
			ModByte = 0b10;
		else
			ModByte = 0b01;
	}
	char tmpModRm[32] = { 0 };
	strncpy(tmpModRm, AsmStr + pos, endPos - pos);
	StripStr(tmpModRm);
	if(IsSibByte) //解析中括号内的内容
	{
		RmByte = 0b100;
		char SibByte[14] = { 0 };
		if (Asm_SIB(tmpModRm, (char**)&SibByte) == 0)
			return 0;
	}
	else
	{
		if (strcmp(tmpModRm, "eax") == 0) RmByte=0b000;
		else if (strcmp(tmpModRm, "ecx") == 0) RmByte=0b001;
		else if (strcmp(tmpModRm, "edx") == 0) RmByte=0b010;
		else if (strcmp(tmpModRm, "ebx") == 0) RmByte=0b011;
		else if (strcmp(tmpModRm, "esi") == 0) RmByte=0b110;
		else if (strcmp(tmpModRm, "edi") == 0) RmByte=0b111;
		else if ((ModByte == 0b01 || ModByte == 0b10) && (strcmp(tmpModRm, "ebp") == 0)) RmByte = 0b101;
		else if (ModByte=0b00&& StrToIntExA(tmpModRm, STIF_SUPPORT_HEX, &ImmOperand)) RmByte = 0b101;
		else //异常情况
		{
			return false;
		}
	}
	return 0;
}

bool CAsm::Asm_Imm(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	//只处理只有一个操作数并且为立即数的情况
	int ImmOperand = 0;	
	if (GetImmValue(asmStr->m_First, &ImmOperand) == false)
		return false;
	//检查操作数大小是否相符
	switch(GET_OPERAND_TYPE(format->Operand,0))
	{
	case OT__b:
		if (ImmOperand > 0xFF) 
			return false;
		asmResult->m_Result[0] = ImmOperand;
		asmResult->m_TotalLength = 1;
		return true;
	case OT__w:
		if (ImmOperand > 0xFFFF) 
			return false;
		asmResult->m_Result[0] = (ImmOperand >> 8);
		asmResult->m_Result[1] = (ImmOperand &0xFF);
		asmResult->m_TotalLength = 2;
		return true;
	case OT__d:
		if (ImmOperand > 0xFFFFFFFF) 
			return false;
		asmResult->m_Result[3] = (ImmOperand >> 24);
		asmResult->m_Result[2] = (ImmOperand >> 16);
		asmResult->m_Result[1] = (ImmOperand >> 8);
		asmResult->m_Result[0] = (ImmOperand & 0xFF);
		asmResult->m_TotalLength = 4;
		return true;
	case OT__q:break;
	}
	return true;
}

bool CAsm::Asm_al_ib(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	int reg = 0;
	int imm = 0;
	//确保是这两种操作数的组合
	if (!((GET_ADDRES_TYPE(format->Operand, 0) == AT__REG8 && GET_ADDRES_TYPE(format->Operand, 1) == AT__I)
		|| (GET_ADDRES_TYPE(format->Operand, 0) == AT__I || GET_ADDRES_TYPE(format->Operand, 1) == AT__REG8)))
		return false;

	//获取寄存器内容
	if (GetReg(asmStr->m_First, &reg) == false || GetImmValue(asmStr->m_Second, &imm) == false)
		return false;

	for (int i = 0; i < 2; i++)
	{
		switch (GET_ADDRES_TYPE(format->Operand, i))
		{
		case AT__REG8:
			//检查第一个操作数是不是指定寄存器
			if (GET_ADDRES_TYPE(format->Operand, 0) != AT__REG8 || GET_OPERAND_TYPE(format->Operand, 0) != reg)
				return false;
			break;
		case AT__I:
			//检查第二个操作数的宽度
			if (UINT(imm) > 0xFF) return false;
			break;
		}
	}
	//不受前缀影响
	asmResult->m_Result[0] = imm;
	asmResult->m_OperandLength = 1;
	return true;
}

bool CAsm::Asm_axx_dx(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	int reg[2] = { 0 };
	//确保是这几种操作数的组合
	if (!((GET_ADDRES_TYPE(format->Operand, 0) == AT__REG8 && GET_ADDRES_TYPE(format->Operand, 1) == AT_XX)
		|| (GET_ADDRES_TYPE(format->Operand, 0) == AT_XX && GET_ADDRES_TYPE(format->Operand, 1) == AT__REG8)
		||(GET_ADDRES_TYPE(format->Operand, 0) == AT_XX && GET_ADDRES_TYPE(format->Operand, 1) == AT_XX)
		||( GET_ADDRES_TYPE(format->Operand, 0) == AT_eXX && GET_ADDRES_TYPE(format->Operand, 1) == AT_XX)
		|| (GET_ADDRES_TYPE(format->Operand, 0) == AT_XX && GET_ADDRES_TYPE(format->Operand, 1) == AT_eXX)))
		return false;

	//获取寄存器内容
	if (GetReg(asmStr->m_First, &reg[0]) == false || GetReg(asmStr->m_Second, &reg[1]) == false)
		return false;

	for (int i = 0; i < 2; i++)
	{
		switch (GET_ADDRES_TYPE(format->Operand, i))
		{
		case AT__REG8:
			if (GET_OPERAND_TYPE(format->Operand, i) != reg[i])
				return false;
			break;
		case AT_XX: //DX AX
			//检查是否指定寄存器
			if (GET_OPERAND_TYPE(format->Operand, i) == RG__DX)
			{
				if(reg[i]!=(RG__DX + RG__MAX * 1))
					return false;
			}
			else if (GET_OPERAND_TYPE(format->Operand, i) == RG__AX)
			{
				if (reg[i] != (RG__AX + RG__MAX * 1))
					return false;
				if (asmResult->m_PlatForm == PLATFORM_16BIT)
				{
				}
				else if (asmResult->m_PlatForm == PLATFORM_32BIT || asmResult->m_PlatForm == PLATFORM_64BIT)
					asmResult->Prefix[3] = 0x66;
				else
					return false;
			}
			else
				return false;
			break;
		case AT_eXX: //eax
			if (GET_OPERAND_TYPE(format->Operand, i) == RG__AX)
			{
				if (reg[i] != (RG__AX + +RG__MAX * 2))
					return false;

				if (asmResult->m_PlatForm == PLATFORM_16BIT)
					asmResult->Prefix[3] = 0x66;
				else if (asmResult->m_PlatForm == PLATFORM_32BIT || asmResult->m_PlatForm == PLATFORM_64BIT)
				{ }
				else
					return false;
			}
			break;
		default:
			return false;
		}
	}	
	return true;
}

bool CAsm::Asm_eax_id(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	int Reg = 0;
	int Imm = 0;
	//获取寄存器内容
	if (GetReg(asmStr->m_First, &Reg) == false || GetImmValue(asmStr->m_Second, &Imm) == false)
		return false;
	if (Reg&RG__AX == 0)  //检查第一个参数是否eax 或者 ax 或者 rax
		return false;
	if (Reg & 16) // AX
	{
		if ((UINT)Imm > 0xFFFF)
			return false;
		if (asmResult->m_PlatForm == PLATFORM_16BIT)
		{}
		else if (asmResult->m_PlatForm == PLATFORM_32BIT)
			asmResult->Prefix[3] = 0x66;
		else if (asmResult->m_PlatForm == PLATFORM_64BIT)
		{
			asmResult->Prefix[0] = 0x48;
			asmResult->Prefix[3] = 0x66;
		}
		else
			return false;
		asmResult->m_Result[1] = Imm & 0xFF;
		asmResult->m_Result[0] = (Imm >> 8) & 0xFF;
		asmResult->m_OperandLength = 2;
		return true;

	}
	else if (Reg & 32) // EAX
	{
		if ((UINT)Imm > 0xFFFFFFFF)
			return false;
		if (asmResult->m_PlatForm == PLATFORM_32BIT || asmResult->m_PlatForm == PLATFORM_64BIT)
		{}
		else if (asmResult->m_PlatForm == PLATFORM_16BIT)
			asmResult->Prefix[3] = 0x66;
		else 
			return false;
		asmResult->m_Result[3] = Imm & 0xFF;
		asmResult->m_Result[2] = (Imm >> 8) & 0xFF;
		asmResult->m_Result[1] = (Imm >> 16) & 0xFF;
		asmResult->m_Result[0] = (Imm >> 24) & 0xFF;
		asmResult->m_OperandLength = 4;
		return true;
	}
	else if (Reg & 48)// RAX
	{
		if (asmResult->m_PlatForm != PLATFORM_64BIT)
			return false;
		if ((UINT)Imm > 0xFFFFFFFF)
			return false;
		asmResult->Prefix[0] = 0x48;
		
		asmResult->m_Result[3] = Imm & 0xFF;
		asmResult->m_Result[2] = (Imm>>8) & 0xFF;
		asmResult->m_Result[1] = (Imm>>16) & 0xFF;
		asmResult->m_Result[0] = (Imm>>24) & 0xFF;
		asmResult->m_OperandLength = 4;
		return true;
	}
	else
		return false;
}


bool CAsm::Asm_Grp_80_81_82_83(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	char Mnemonic[][4] = { "add","or","adc","sbb","and","sub","xor","cmp" };
	char RegByte =  - 1;
	char ModRmByte[32] = { 0 };
	char MnemonicByte = -1;
	int base = 0;
	switch(format->m_Opcode)
	{
	case 0x80: base = 0; break;
	case 0x81: base = 2; break;
	case 0x82: base = 0; break;
	case 0x83: base = 2; break;
	}
	for (int i = 0; i < 8; i++) //检查第一个操作数是否为寄存器
	{
		if (strcmp(gRegister[i+base*16], asmStr->m_First) == 0)
		{
			RegByte = i;
			break;
		}
		if (i == 7)
		{
			return false; //检查第一个操作数是否为内存
		}
	}
	for (int i = 0; i < 8; i++)
	{
		if (strcmp(Mnemonic[i], asmStr->m_Instruct) == 0)
		{
			MnemonicByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	int ImmOperand = 0;
	if (asmStr->m_Second[0] == '0' && (asmStr->m_Second[1] == 'x' || asmStr->m_Second[1] == 'X'))
	{
		if (StrToIntExA(asmStr->m_Second, STIF_SUPPORT_HEX, &ImmOperand) == false)
			return false;
	}
	else
	{
		if (StrToIntExA(asmStr->m_Second, STIF_DEFAULT, &ImmOperand) == false)
			return false;
	}
	asmResult->m_Result[0] = 0b11000000 + (MnemonicByte << 3) + RegByte;
	switch(format->m_Opcode)
	{
	case 0x80:
	case 0x82:
	case 0x83:
		if (ImmOperand > 0xFF)
			return false;
		asmResult->m_Result[1] = ImmOperand & 0xFF;
		asmResult->m_TotalLength = 2;
		return true;
	case 0x81:
		if (ImmOperand > 0xFFFFFFFF)
			return false;
		asmResult->m_Result[4] = (ImmOperand >> 24);
		asmResult->m_Result[3] = (ImmOperand >> 16);
		asmResult->m_Result[2] = (ImmOperand >> 8);
		asmResult->m_Result[1] = (ImmOperand & 0xFF);
		asmResult->m_TotalLength = 5;
		return true;
	}
	return false;
}

bool CAsm::Asm_Grp_8F(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	//这个分组只有pop指令在用
	char RegByte = -1;
	for (int i = 0; i < 8; i++)
	{
		if (strcmp(gRegister[i + 2 * 16], asmStr->m_First) == 0)
		{
			RegByte = i;
			break;
		}
		if (i == 7) return false;
	}
	asmResult->m_Result[0] = 0b11000000  + RegByte;
	asmResult->m_TotalLength = 1;
	return true;
}

bool CAsm::Asm_Grp_C0_C1_D0_D1_D2_D3(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	char Mnemonic[][4] = { "rol","ror","rcl","rcr","shl","shr","","sar" };
	char RegByte = -1;
	char MnemonicByte = -1;
	int base = 0;
	switch (format->m_Opcode)
	{
	case 0xc0:
	case 0xd0:
	case 0xd2:
		base = 0; break;
	case 0xc1:
	case 0xd1:
	case 0xd3:
		base = 2; break;
	}
	for (int i = 0; i < 8; i++) //查找第一个操作数
	{
		if (strcmp(gRegister[i + base * 16], asmStr->m_First) == 0)
		{
			RegByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	for (int i = 0; i < 8; i++) //查找助记符
	{
		if (strcmp(Mnemonic[i], asmStr->m_Instruct) == 0)
		{
			MnemonicByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	//检查第二个操作数
	int ImmOperand = 0;
	if(format->m_Opcode==0xd2 || format->m_Opcode==0xd3) //第二个操作数为寄存器 cl
	{
		if (strcmp(asmStr->m_Second, "cl") != 0)
			return false;
	}
	else
	{
		if (asmStr->m_Second[0] == '0' && (asmStr->m_Second[1] == 'x' || asmStr->m_Second[1] == 'X'))
		{
			if (StrToIntExA(asmStr->m_Second, STIF_SUPPORT_HEX, &ImmOperand) == false)
				return false;
		}
		else
		{
			if (StrToIntExA(asmStr->m_Second, STIF_DEFAULT, &ImmOperand) == false)
				return false;
		}		
	}
	if(format->m_Opcode==0xd0 || format->m_Opcode==0xd1) //第二个操作数为立即数 1
	{
		if (ImmOperand != 1)
			return false;
	}
	asmResult->m_Result[0] = 0b11000000 + (MnemonicByte << 3) + RegByte;
	asmResult->m_TotalLength = 1;
	if (format->m_Opcode == 0xc0 || format->m_Opcode == 0xc1) //第二个操作数为一个字节的立即数 
	{
		if (ImmOperand > 0xFF)
			return false;
		asmResult->m_Result[1] = ImmOperand & 0xFF;
		asmResult->m_TotalLength = 2;
	}
	return true;
}


bool CAsm::Asm_Grp_C6(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_C7(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_F6_F7(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	char Mnemonic[][8] = { "test","","not","neg","mul","imul","div","idiv" };
	char RegByte = -1;
	char MnemonicByte = -1;
	int base = 0;
	switch (format->m_Opcode)
	{
	case 0xF6: base = 0; break;
	case 0xF7: base = 2; break;
	}
	for (int i = 0; i < 8; i++) //查找第一个操作数
	{
		if (strcmp(gRegister[i + base * 16], asmStr->m_First) == 0)
		{
			RegByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	for (int i = 0; i < 8; i++) //查找助记符
	{
		if (strcmp(Mnemonic[i], asmStr->m_Instruct) == 0)
		{
			MnemonicByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	//检查第二个操作数
	asmResult->m_Result[0] = 0b11000000 + (MnemonicByte << 3) + RegByte;
	asmResult->m_TotalLength = 1;
	//这两个助记符没有第二个操作数
	if (MnemonicByte == 2 || MnemonicByte == 3) return true;
	//这四个助记符的第二个操作数指定为寄存器 al 或者 rAX
	if (MnemonicByte == 4 || MnemonicByte == 5 || MnemonicByte == 6 || MnemonicByte == 7) 
	{
		return strcmp(asmStr->m_Second, gRegister[0 + base * 16]) == 0;
	}
	//这个助记符的第二个操作数为立即数
	if(MnemonicByte==0)
	{
		int ImmOperand = 0;
		if (asmStr->m_Second[0] == '0' && (asmStr->m_Second[1] == 'x' || asmStr->m_Second[1] == 'X'))
		{
			if (StrToIntExA(asmStr->m_Second, STIF_SUPPORT_HEX, &ImmOperand) == false)
				return false;
		}
		else
		{
			if (StrToIntExA(asmStr->m_Second, STIF_DEFAULT, &ImmOperand) == false)
				return false;
		}
		if(base==0)
		{
			if (ImmOperand > 0xFF)
				return false;
			asmResult->m_Result[1] = ImmOperand & 0xFF;
			asmResult->m_TotalLength = 2;
			return true;
		}
		else if(base==2)
		{
			if (ImmOperand > 0xFFFFFFFF)
				return false;
			asmResult->m_Result[4] = (ImmOperand >> 24);
			asmResult->m_Result[3] = (ImmOperand >> 16);
			asmResult->m_Result[2] = (ImmOperand >> 8);
			asmResult->m_Result[1] = (ImmOperand & 0xFF);
			asmResult->m_TotalLength = 5;
			return true;		
		}
	}
	return false;
}

bool CAsm::Asm_Grp_FE(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	char Mnemonic[][8] = { "inc","dec","","","","","","" };
	char RegByte = -1;
	char MnemonicByte = -1;
	for (int i = 0; i < 8; i++) //查找第一个操作数
	{
		if (strcmp(gRegister[i], asmStr->m_First) == 0)
		{
			RegByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	for (int i = 0; i < 8; i++) //查找助记符
	{
		if (strcmp(Mnemonic[i], asmStr->m_Instruct) == 0)
		{
			MnemonicByte = i;
			break;
		}
		if (i == 7)
		{
			return false;
		}
	}
	//检查第二个操作数
	asmResult->m_Result[0] = 0b11000000 + (MnemonicByte << 3) + RegByte;
	asmResult->m_TotalLength = 1;
	return true;
}

bool CAsm::Asm_Grp_FF(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F00(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F01(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F18(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F71(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F72(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0F73(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0FAE(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0FB9(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0FBA(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_Grp_0FC7(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt* format)
{
	return false;
}

bool CAsm::Asm_ac(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	S_MEM_ADDRESS MemAddress = { 0 };
	//获取内存寻址信息
	if (GetMemAddressInfo(asmStr->m_First, &MemAddress) == false)
		return false;
	//检查目的地址是不是 (e)si 寄存器
	if(MemAddress.m_Type!=1||(MemAddress.m_Addrtype.s_Reg.m_RegNum&RG__SI)==0) 
		return false;
	if ((MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4) != asmResult->m_PlatForm) //32 si  64 esi
	{
		if ((asmResult->m_PlatForm == PLATFORM_32BIT && (MemAddress.m_Addrtype.s_Reg.m_RegNum>>4 == 1))
			|| (asmResult->m_PlatForm == PLATFORM_64BIT && (MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4 == 2)))
			asmResult->Prefix[4] = ASM_PREFIX_Address_Size_67;
	}
	if (MemAddress.m_OperSize == 0) // byte ptr
	{
		return true;
	}
	else
		return false;
}

bool CAsm::Asm_ad(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	S_MEM_ADDRESS MemAddress = { 0 };
	//获取内存寻址信息
	if (GetMemAddressInfo(asmStr->m_First, &MemAddress) == false)
		return false;
	//检查目的地址是不是 (e)si 寄存器
	if (MemAddress.m_Type != 1 || (MemAddress.m_Addrtype.s_Reg.m_RegNum&RG__SI) == 0)
		return false;

	// TODO  把下面的分支抽象起来
	if (asmResult->m_PlatForm == PLATFORM_32BIT)
	{
		if (MemAddress.m_OperSize == PLATFORM_16BIT)
			asmResult->Prefix[3] = ASM_PREFIX_Oprand_Size_66;
		else if (MemAddress.m_OperSize != PLATFORM_32BIT)
			return false;

		if((MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4)== PLATFORM_16BIT)
			asmResult->Prefix[4] = ASM_PREFIX_Address_Size_67;
		else if ((MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4) != PLATFORM_32BIT) 
			return false;
	}
	else if (asmResult->m_PlatForm == PLATFORM_64BIT) 
	{
		if (MemAddress.m_OperSize== PLATFORM_16BIT)
			asmResult->Prefix[3] = ASM_PREFIX_Oprand_Size_66;
		else if (MemAddress.m_OperSize == PLATFORM_64BIT)
			asmResult->Prefix[0] = ASM_PREFIX_REX_W;
		else if (MemAddress.m_OperSize != PLATFORM_32BIT)
			return false;

		if ((MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4) == PLATFORM_32BIT)
			asmResult->Prefix[4] = ASM_PREFIX_Address_Size_67;
		else if ((MemAddress.m_Addrtype.s_Reg.m_RegNum >> 4) != PLATFORM_64BIT)
			return false;
	}
	else
		return false;
	return true;
}

bool CAsm::Asm_a4(SAsmStr * asmStr, SAsmResult * asmResult, SInstructFmt * format)
{
	S_MEM_ADDRESS FirstMemAddress = { 0 };
	S_MEM_ADDRESS SecondMemAddress = { 0 };
	//获取内存寻址信息
	if (GetMemAddressInfo(asmStr->m_First, &FirstMemAddress) == false
		|| GetMemAddressInfo(asmStr->m_Second, &SecondMemAddress) == false)
		return false;
	//检查目的地址是不是 (e)si 寄存器
	if (FirstMemAddress.m_Type != 1 || (FirstMemAddress.m_Addrtype.s_Reg.m_RegNum&RG__SI) == 0
		|| SecondMemAddress.m_Type != 1 || (SecondMemAddress.m_Addrtype.s_Reg.m_RegNum&RG__DI) == 0)
		return false;

	if ((FirstMemAddress.m_Addrtype.s_Reg.m_RegNum >> 4) != asmResult->m_PlatForm) //32 si  64 esi
	{
		if ((asmResult->m_PlatForm == PLATFORM_32BIT && (FirstMemAddress.m_Addrtype.s_Reg.m_RegNum >> 4 == 1))
			|| (asmResult->m_PlatForm == PLATFORM_64BIT && (FirstMemAddress.m_Addrtype.s_Reg.m_RegNum >> 4 == 2)))
			asmResult->Prefix[4] = ASM_PREFIX_Address_Size_67;
	}
	if (FirstMemAddress.m_OperSize == 0) // byte ptr
	{
		return true;
	}
	else
		return false;

}

