#pragma once
/*
�������������ش�����
*/
#include <Windows.h>
#include "define.h"
#include "PubLib/StrTrie.h"

#define MAX_ASM_STR_LENGTH 16


enum asm_error_code
{
	ASM_ERROR_INCORRECT_OPERANDNUM,
};
// intel 580ҳ
// V :֧��   
// I :��֧��  
// NE :ָ����﷨��64λģʽ�²��ܽ��룬���ܻ��ṩ64λģʽ�µ��½��뷽ʽ  
// NP :64λģʽ�µ�REXǰ׺��Ӱ�촫ͳָ�� 
// NI :64λģʽ�»ᱻ��Ϊ�µ�ָ��  
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
	UCHAR m_Type;  // 0 ������ 1 �Ĵ��� 2 sib
	union 
	{
		struct 
		{
			UCHAR m_ImmStr[16];
			UINT64 m_ImmValue;
		}s_Imm;
		struct 
		{
			UINT m_RegNum; //gRegister ��������
			UCHAR m_RegStr[32];
		}s_Reg;
		struct 
		{
			UCHAR m_ModRmStr[32];
		}s_ModRm;
	}m_Addrtype;
}S_MEM_ADDRESS;

// 1125ҳ  LZCNT ������¼
// 2328ҳ VREDUCESD 
// 2332ҳ VREDUCESS 
class CAsm
{
	static CStrTrie *m_strTrie;
public:
	CAsm();
	static int AsmFromStr(LPCTSTR asmStr,int platForm, SAsmResultSet* asmResultSet);
	static bool StripStr(char* str); //ȥ���ַ�����β�Ŀհ��ַ�
	static bool RemoveSpace(char* str); //ȥ���ַ�����β�Ŀհ��ַ�
	static bool SplitStr(char*, SAsmStr*); //�ָ����������Ƿ��͸���������
	static bool GetImmValue(char* tmpStr, int* immValue=NULL); //�ж��ַ����Ƿ�Ϊ������  ****
	static bool GetReg(char* tmpStr, int* Reg=NULL); //�ж��ַ����Ƿ�Ϊ�Ĵ���
	static bool GetMemAddressInfo(char* tmpStr, S_MEM_ADDRESS* MemAddr); //�ж��ַ����Ƿ�Ϊ�ڴ�Ѱַ
	static UINT64 GetOpcode(UINT Opcode);


	static bool Asm_None(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);
	static int Asm_SIB(char* AsmStr, char** SIBByte); //���� SIB �ֽ�
	static int Asm_ModRm(char* AsmStr,char** ModeRmByte,int base); //����ModRM�ֽ� ���ؽ�����ĳ���
	static bool Asm_Imm(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //��������Ϊ�������Ļ�����  ****
	static bool Asm_al_ib(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //��������Ϊ8λ�Ĵ�����8λ������  ****
	static bool Asm_axx_dx(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //��������Ϊal ax eax��dx�Ĵ���  ****
	static bool Asm_eax_id(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format);  //��������Ϊ eax��������  ****

	static bool Asm_Grp_80_81_82_83(SAsmStr* asmStr, SAsmResult* asmResult, SInstructFmt* format); //��������Ϊ 0x80 81 82 83 �ķ���ָ��
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