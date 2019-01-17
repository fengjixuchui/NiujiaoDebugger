#pragma once
/*
定义汇编引擎和反汇编引擎公用的相关结构
*/
//反汇编时使用的前缀表达枚举  方便异或
enum {
	PREFIX_REX = 1 << 0,  //REX
	PREFIX_REX_B = 1 << 1,  //REX
	PREFIX_REX_X = 1 << 2,  //REX
	PREFIX_REX_XB = 1 << 3,  //REX
	PREFIX_REX_R = 1 << 4,  //REX
	PREFIX_REX_RB = 1 << 5,  //REX
	PREFIX_REX_RX = 1 << 6,  //REX
	PREFIX_REX_RXB = 1 << 7,  //REX
	PREFIX_REX_W = 1 << 8,  //REX
	PREFIX_REX_WB = 1 << 9,  //REX
	PREFIX_REX_WX = 1 << 10,  //REX
	PREFIX_REX_WXB = 1 << 11,  //REX
	PREFIX_REX_WR = 1 << 12,  //REX
	PREFIX_REX_WRB = 1 << 13,  //REX
	PREFIX_REX_WRX = 1 << 14,  //REX
	PREFIX_REX_WRXB = 1 << 15,  //REX
	PREFIX_Seg_ES_26 = 1 << 16,  //SEG-ES
	PREFIX_Seg_CS_2E = 1 << 17,  //SEG-CS
	PREFIX_Seg_SS_36 = 1 << 18,  //SEG-SS
	PREFIX_Seg_DS_3E = 1 << 19,  //SEG-DS
	PREFIX_Seg_FS_64 = 1 << 20,  //SEG-FS
	PREFIX_Seg_GS_65 = 1 << 21,  //SEG-GS
	PREFIX_Oprand_Size_66 = 1 << 22,  //Operand-size
	PREFIX_Address_Size_67 = 1 << 23,  //Address-size
	PREFIX_Lock_F0 = 1 << 24,  //lock
	PREFIX_Repne_F2 = 1 << 25,  //REPNE XACQURE
	PREFIX_Repe_F3 = 1 << 26,  //REP/REPE XRELEASE
};   //前缀类型枚举

//汇编时使用的前缀表达枚举  方便赋值
enum {
	ASM_PREFIX_Seg_ES_26=0x26,  
	ASM_PREFIX_Seg_CS_2E = 0x2E,  
	ASM_PREFIX_Seg_SS_36 = 0x36,  
	ASM_PREFIX_Seg_DS_3E = 0x3E, 
	ASM_PREFIX_REX = 0x40,  
	ASM_PREFIX_REX_B,  
	ASM_PREFIX_REX_X ,  
	ASM_PREFIX_REX_XB , 
	ASM_PREFIX_REX_R ,  
	ASM_PREFIX_REX_RB, 
	ASM_PREFIX_REX_RX, 
	ASM_PREFIX_REX_RXB,  
	ASM_PREFIX_REX_W, 
	ASM_PREFIX_REX_WB,  
	ASM_PREFIX_REX_WX,  
	ASM_PREFIX_REX_WXB,  
	ASM_PREFIX_REX_WR,  
	ASM_PREFIX_REX_WRB, 
	ASM_PREFIX_REX_WRX , 
	ASM_PREFIX_REX_WRXB,  
	ASM_PREFIX_Seg_FS_64 = 0x64,  
	ASM_PREFIX_Seg_GS_65 = 0x65,  
	ASM_PREFIX_Oprand_Size_66 = 0x66,  
	ASM_PREFIX_Address_Size_67 = 0x67,  
	ASM_PREFIX_Lock_F0 = 0xF0,  
	ASM_PREFIX_Repne_F2 = 0xF2,  
	ASM_PREFIX_Repe_F3 = 0xF3,  
};   //前缀类型枚举


enum {ZERO_OPERAND, ONE_OPERAND, TWO_OPERAND, THREE_OPERAND, FOUR_OPERAND};

//操作数内容打包成一个整数 a占前三位 其余占5位
#define PACK_OPERAND(a,b,c,d,e,f,g,h,i) ((UINT64)a+((UINT64)b<<3)+((UINT64)c<<8)+((UINT64)d<<13)+((UINT64)e<<18)+((UINT64)f<<23)+((UINT64)g<<28)+((UINT64)h<<33)+((UINT64)i<<38))
//获取操作数数量
#define GET_OPERAND_NUM(x)  (x&3)
#define GET_ADDRES_TYPE(x,i) ((x>>(3+10*i))&0x1F)
#define GET_OPERAND_TYPE(x,i) ((x>>(8+10*i))&0x1F)


//寻址模式  intel手册 2512
enum EAddressType {
	AT__A, AT__B, AT__C, AT__D, AT__E, AT__F, AT__G, AT__H, AT__I, AT__J, AT__L, AT__M, AT__N, AT__O, AT__P, AT__Q, AT__R, AT__S, AT__U, AT__V, AT__W, AT__X, AT__Y,
	AT__REG8 = 28,  //8位寄存器
	AT_XX, //16位
	AT_eXX, //16位 或者 32位
	AT_rXX, //16位 或者 32位 或者 64位
};//寄存器类型 只和寄存器操作数匹配

//操作数类型 intel手册 2512
enum EOperandType {
	OT__a, OT__b, OT__c, OT__d, OT__dq, OT__p, OT__pd, OT__pi, OT__ps, OT__q, OT__qq, OT__s, OT__sd, OT__ss, OT__si, OT__v, OT__w, OT__x, OT__y, OT__z,OT_zero,OT_one
};

enum ERegister8
{
	RG8__AL, RG8__CL, RG8__DL, RG8__BL, RG8__AH, RG8__CH, RG8__DH, RG8__BH
};
enum EOperandBits
{
	OPERAND_BYTE, OPERAND_WORD, OPERAND_DOUBLE_WORD, OPERAND_QUAD_WORD, OPERAND_DOUBLE_QUAD_WORD, OPERAND_QUAD_QUAD_WORD
};
enum ERegisterType
{
	RG__AX, RG__CX, RG__DX, RG__BX, RG__SP, RG__BP, RG__SI, RG__DI, RG__ES, RG__SS, RG__CS, RG__DS, RG__GS, RG__FS,RG__MAX = 16
};

#define MAX_PREFIX_NUM 5
typedef struct s_asm_str
{
	char m_Instruct[16];
	char m_First[64];
	char m_Second[64];
	char m_Third[64];
	char m_Forth[64];
	USHORT m_OperandNum;
	UCHAR Prefix[MAX_PREFIX_NUM];  //0: REX前缀 1: lock 2:repe repne 3 operandsize 4 addrsize
}SAsmStr;

typedef struct s_asm_result
{
	UCHAR m_Result[14];
	UCHAR Prefix[MAX_PREFIX_NUM];  //0: REX前缀 1: lock 2:repe repne 3 operandsize 4 addrsize
	UINT m_PrefixLength : 8;
	UINT m_OpcodeLength : 8;
	UINT m_OperandLength : 8;
	UINT m_PlatForm : 8;
	INT m_TotalLength : 8;//没有结果为0 其余大于0的情况为指令长度 -1为指令出错
	int m_ErrorCode;  //每条的匹配结果
}SAsmResult;

#define MAX_INSTRUCT_NUM 64

typedef struct s_asm_result_set
{
	USHORT m_TotalRecord;
	USHORT m_SuccessRecord;
	USHORT m_FailRecord;
	SAsmResult m_AsmResult[MAX_INSTRUCT_NUM];
}SAsmResultSet;
typedef struct s_instruct_fmt
{
	UINT m_Opcode;
	DWORD64 Operand;
	USHORT m_Support64Bit;
	USHORT m_Support32Bit;
	SHORT m_GroupPos;
	bool(*AsmFunc)(SAsmStr* asmStr, SAsmResult* asmResult, struct s_instruct_fmt* format); //汇编函数
}SInstructFmt;
typedef  struct s_asm_instruct
{
	char m_Mnemonic[32];
	SInstructFmt m_Operand[MAX_INSTRUCT_NUM];
}SAsmInstruct;
enum
{
	e_Eax, e_Ecx, e_Edx, e_Ebx, e_Ebp = 5, e_Esi, e_Edi
};

//反汇编结果结构体
enum {
	PLATFORM_8BIT,
	PLATFORM_16BIT,
	PLATFORM_32BIT,
	PLATFORM_64BIT
};
typedef struct disasm_result
{
	LPVOID CodeMap;
	UINT64 CurFileOffset;
	BYTE  MachineCode[16];
	bool IsData; //可能是数据
	UINT SIB_Prefix;
	DWORD PrefixState;
	char Opcode[15];
	UINT CurrentLen;
	UINT OperandNum;
	char PreStr[8];
	char Operand[4][64];
	char  Memo[32];

}DISASM_RESULT;

typedef struct disasm_addr_queue
{
	LPVOID Addr;
	struct disasm_addr_queue* next;
} DISASM_ADDR_QUEUE;

