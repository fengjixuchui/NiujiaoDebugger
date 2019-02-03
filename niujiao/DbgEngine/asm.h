#pragma once
/*
定义汇编引擎的相关处理函数
*/
#include <Windows.h>
#include "define.h"
#include "PubLib/StrTrie.h"

#define MAX_ASM_STR_LENGTH 16


enum asm_error_code
{
	ASM_ERROR_INCORRECT_OPERANDNUM,
};
// intel 580页
// V :支持   
// I :不支持  
// NE :指令的语法在64位模式下不能解码，可能会提供64位模式下的新解码方式  
// NP :64位模式下的REX前缀不影响传统指令 
// NI :64位模式下会被视为新的指令  
// NS : 
enum e_opcode_supported_mode
{
	E_64__V,
	E_32__V,
	E_64__I,
	E_32__I,
	E_64__NE,
	E_32__NE,
	E_64__NP,
	E_32__NP,
	E_64__NI,
	E_32__NI,
	E_64__NS,
	E_32__NS,
};
typedef struct s_mem_address
{
	UCHAR m_OperSize;
	UCHAR m_SegReg;
	UCHAR m_Type;  // 0 立即数 1 寄存器 2 sib
	union 
	{
		struct 
		{
			UCHAR m_ImmStr[16];
			UINT64 m_ImmValue;
		}s_Imm;
		struct 
		{
			UINT m_RegNum; //gRegister 定义的序号
			UCHAR m_RegStr[32];
		}s_Reg;
		struct 
		{
			UCHAR m_ModRmStr[32];
		}s_ModRm;
	}m_Addrtype;
}S_MEM_ADDRESS;

// 1125页  LZCNT 三条记录
// 2328页 VREDUCESD 
// 2332页 VREDUCESS 
class CAsm
{
	static CStrTrie *m_strTrie;
public:
	CAsm();
	static int AsmFromStr(LPCTSTR asmStr,int platForm, SAsmResultSet* asmResultSet);
	static bool StripStr(char* str); //去除字符串首尾的空白字符
	static bool RemoveSpace(char* str); //去除字符串首尾的空白字符
	static bool SplitStr(char*, SAsmStr*); //分割汇编语句的助记符和各个操作数
	static bool GetImmValue(char* tmpStr, int* immValue=NULL); //判断字符串是否为立即数  ****
	static bool GetReg(char* tmpStr, int* Reg=NULL); //判断字符串是否为寄存器
	static bool GetMemAddressInfo(char* tmpStr, S_MEM_ADDRESS* MemAddr); //判断字符串是否为内存寻址
	static UINT64 GetOpcode(UINT Opcode);


	static bool Asm_None(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static int Asm_SIB(char* AsmStr, char** SIBByte); //解析 SIB 字节
	static int Asm_ModRm(char* AsmStr,char** ModeRmByte,int base); //解析ModRM字节 返回解析后的长度
	static bool Asm_Imm(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //汇编操作数为立即数的汇编语句  ****
	static bool Asm_al_ib(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //汇编操作数为8位寄存器和8位立即数  ****
	static bool Asm_axx_dx(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //汇编操作数为al ax eax和dx寄存器  ****
	static bool Asm_eax_id(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //汇编操作数为 eax和立即数  ****

	static bool Asm_Grp_80_81_82_83(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format); //汇编操作码为 0x80 81 82 83 的分组指令
	static bool Asm_Grp_8F(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_C0_C1_D0_D1_D2_D3(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_C6(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_C7(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_F6_F7(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_FE(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_FF(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F00(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F01(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F18(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F71(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F72(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0F73(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0FAE(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0FB9(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0FBA(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_Grp_0FC7(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_ac(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_ad(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static bool Asm_a4(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
};