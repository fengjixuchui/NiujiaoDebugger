/*
ʵ�ַ��������
*/
#include "stdafx.h"
#include "Disasm.h"
#include "Disasm_three_3a.h"
DISASM_ADDR_QUEUE *gFuncPoolHead = nullptr;

Disasm::Disasm()
{
	DisasmResult = nullptr;
	DisasmPoint = nullptr;
	DisasmResultBySeq = nullptr;
	gFuncPoolHead = nullptr;
	ImageInfo = nullptr;
}

Disasm::~Disasm()
{
	if (DisasmResult)
	{
		for (UINT i = 0; i < DisasmPoint->LenOfCode; i++)
		{
			if (*(DisasmResult + i)!=0)
				delete *(DisasmResult + i);
		}
		delete[] DisasmResult;
	}
	if (DisasmPoint)
		delete DisasmPoint;
	//if (DisasmResultBySeq)
	//	delete[] DisasmResultBySeq;
	if (ImageInfo)
		delete ImageInfo;
}

DISASM_RESULT * Disasm::GetDisasmResult(DWORD addr) const
{
	return *DisasmResult + addr - DisasmPoint->VirtualAddress;
}

DISASM_RESULT * Disasm::GetDisasmResult() const
{
	return *DisasmResult;
}

LPVOID * Disasm::GetDisasmResultBySeq() const
{
	return DisasmResultBySeq;
}

CImageInfo * Disasm::GetImageInfo() const
{
	return ImageInfo;
}
DWORD Disasm::GetTotalDisasmRecord() const
{
	return DisasmPoint->TotalDisasmRecord;
}
void Disasm::IndexResultBySeq(DISASM_POINT* DisasmPoint)
{
	if (DisasmResultBySeq)
		delete[] DisasmResultBySeq;
	DisasmResultBySeq = new LPVOID[DisasmPoint->TotalDisasmRecord];
	ZeroMemory(DisasmResultBySeq, sizeof(DWORD)*DisasmPoint->TotalDisasmRecord);
	int record = 0;
	for (unsigned int i = 0; i < DisasmPoint->LenOfCode; i++)
	{
		if ((*(DWORD*)(DisasmResult + i)) != NULL)
		{
			*(DisasmResultBySeq + record) = (LPVOID)(DisasmResult + i);
			record++;
		}
	}
}
bool Disasm::PushDisasmFuncAddr(LPVOID Addr)
{
	DISASM_ADDR_QUEUE *tmp = gFuncPoolHead;
	if (gFuncPoolHead == nullptr)
	{
		gFuncPoolHead = new DISASM_ADDR_QUEUE;
		tmp = gFuncPoolHead;
	}
	else
	{
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new DISASM_ADDR_QUEUE;
		tmp = tmp->next;
	}
	tmp->Addr = Addr;
	tmp->next = nullptr;
	return true;
}
LPVOID Disasm::PopDisasmFuncAddr()
{
	LPVOID data = 0;
	if (gFuncPoolHead)
	{
		data = gFuncPoolHead->Addr;
		if (gFuncPoolHead->next)
		{
			DISASM_ADDR_QUEUE *tmp = gFuncPoolHead;
			gFuncPoolHead = gFuncPoolHead->next;
			delete tmp;
		}
		else
		{
			delete gFuncPoolHead;
			gFuncPoolHead = nullptr;
		}
	}
	return data;
}
int Disasm::GetDisasmFuncAddrCount()
{
	DISASM_ADDR_QUEUE *tmp = gFuncPoolHead;
	int size = 0;
	if (tmp)
	{
		size++;
		while (tmp->next)
		{
			size++;
			tmp = tmp->next;
		}
	}
	return size;
}
bool Disasm::DisasmFromHandle(HANDLE hFile)
{
	HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (hMap == INVALID_HANDLE_VALUE)
		return false;
	LPVOID MapFileAddr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (MapFileAddr == 0)
	{
		CloseHandle(hMap);
		return false;
	}
	ImageInfo = new CImageInfo();
	if (ImageInfo->ReadImageFromMem(MapFileAddr) == false)
	{
		CloseHandle(hMap);
		UnmapViewOfFile(MapFileAddr);
		delete ImageInfo;
		return false;
	}
	DisasmResult = (DISASM_RESULT**)new LPVOID[ImageInfo->GetSizeOfCode()];  //TODO 1�� �ĳ��н�����������ݿ��Խ�ʡ�ڴ� 2���ĳ��ڴ��д���ε��ܼ�¼��
	DisasmPoint = new DISASM_POINT;
	ZeroMemory(DisasmResult, sizeof(LPVOID)*ImageInfo->GetSizeOfCode());
	ZeroMemory(DisasmPoint, sizeof(DISASM_POINT));

	char str[64] = { 0 };
	sprintf_s(str, "��ʼ�����ڴ�,��ʼλ�� %x ���� %d  ��С %d\n", (int)DisasmResult, ImageInfo->GetSizeOfCode(), sizeof(DISASM_RESULT));
	//printf(str);

	DisasmResultBySeq = nullptr;
	gFuncPoolHead = nullptr;

	DisasmPoint->ImageInfo = ImageInfo;
	DisasmPoint->MapFileAddr = MapFileAddr;
	DisasmPoint->FileStartOfCode = (UINT64)MapFileAddr + ImageInfo->GetBaseOfCodeInFile();
	DisasmPoint->FileEndOfCode = DisasmPoint->FileStartOfCode + ImageInfo->GetMemSizeOfCode();
	PushDisasmFuncAddr((LPVOID)DisasmPoint->ImageInfo->GetAddressOfEntryPoint());

	DisasmPoint->BaseOfImage = ImageInfo->GetImageBase();
	DisasmPoint->VirtualAddress = ImageInfo->GetVirtualAddress();
	DisasmPoint->LenOfCode = ImageInfo->GetSizeOfCode();
	DisasmPoint->BaseOfCodeInFile = ImageInfo->GetBaseOfCodeInFile();
	if (ImageInfo->Is32Image())
		DisasmPoint->PlatForm = PLATFORM_32BIT;
	else
		DisasmPoint->PlatForm = PLATFORM_64BIT;

	/*��һ�� ������������*/
	DisasmFile();
	/*�ڶ��� �����©����*/
	/*������ ���������*/

	UnmapViewOfFile(MapFileAddr);
	CloseHandle(hMap);
	return true;
}
bool Disasm::DisasmFromFile(LPCTSTR * FileName)
{
	return false;
}
bool Disasm::DisasmFromFile(char * FileName)
{
	return false;
}
bool Disasm::DisasmFromStr(char * Str, int platForm, int length, DISASM_RESULT * DisasmResult)
{
	if (DisasmResult == nullptr)
		return false;

	DisasmResult->CodeMap = (LPVOID)gOneByteCodeMap;
	UINT64 StartDisasmAddr = (UINT64)Str;	
	DISASM_POINT DisasmPoint;
	ZeroMemory(&DisasmPoint, sizeof(DISASM_POINT));
	DisasmPoint.PlatForm = platForm;
	DisasmPoint.CurMemAddr = (UINT64)Str;
	int SegmentIsFinished = 0;
	while (true) //ѭ������һ��ָ�����������ǰ׺����������
	{
		UCHAR code = *(UCHAR*)(DisasmPoint.CurMemAddr);
		//�ȿ������Ƿ�  ����ָ���ں��������޸����Ƿ�
		if (gOneByteCodeMap[code].OpStr)
			strcpy_s(DisasmResult->Opcode, gOneByteCodeMap[code].OpStr);
		DisasmResult->CurrentLen = 0;
		if (gOneByteCodeMap[code].DisasmFunc(DisasmResult, &DisasmPoint, &SegmentIsFinished))
		{
			if (DisasmResult->CurrentLen == 0)
				DisasmResult->CurrentLen = UINT(DisasmPoint.CurMemAddr - StartDisasmAddr);//����ָ���
			memcpy(DisasmResult->MachineCode, (LPVOID)(StartDisasmAddr), DisasmResult->CurrentLen);//����������
			DisasmPoint.TotalDisasmRecord += 1;
			if (code != 0x0f)  //�˴�ֻ������һ�ֽڲ�����Ĳ�����  �����ֽڲ���������ʵ�ֲ����޸�
			{
				if (DisasmResult->OperandNum == 0)
					DisasmResult->OperandNum = GET_OPERAND_NUM((gOneByteCodeMap[code].Operand)); //����ָ���ں������޸Ĵ˲���
			}
			return true;
		}
	}
	return false;
}
bool IsGernerl = false;
bool Disasm::DisasmFile()
{
	int i = 0;
	char str[256];
	while (GetDisasmFuncAddrCount())
	{
		int SegmentIsFinished = 0;
		LPVOID aa = PopDisasmFuncAddr();
		DisasmPoint->CurMemAddr = (UINT64)DisasmPoint->MapFileAddr + (UINT64)aa - DisasmPoint->VirtualAddress + DisasmPoint->BaseOfCodeInFile;//ӳ���ַ+��ַ-�ڴ��ַ+�ļ���ַ

		//sprintf_s(str, "------------��ʼ�����׵�ַ%X\n", DisasmPoint->CurMemAddr);
		//printf(str);
		while (!SegmentIsFinished) //ѭ������һ��ָ��
		{
			DISASM_RESULT * DisasmResultTmp = new DISASM_RESULT;
			ZeroMemory(DisasmResultTmp, sizeof(DISASM_RESULT));
			*(DisasmResult + DisasmPoint->CurMemAddr - (UINT64)DisasmPoint->MapFileAddr - DisasmPoint->BaseOfCodeInFile)= DisasmResultTmp;
			if (DisasmResultTmp->CurFileOffset != 0) break; //�Ѿ���������

			DisasmResultTmp->CodeMap = (LPVOID)gOneByteCodeMap;
			DisasmResultTmp->CurFileOffset = DisasmPoint->CurMemAddr - DisasmPoint->FileStartOfCode + DisasmPoint->VirtualAddress;
			UINT64 StartDisasmAddr = DisasmPoint->CurMemAddr;

			//sprintf_s(str, "��ʼ����ָ���ַ%X\t", DisasmResultTmp->CurrentAddr);
			//printf(str);
			while (true) //ѭ������һ��ָ�����������ǰ׺����������
			{
				UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
				//�ȿ������Ƿ�  ����ָ���ں��������޸����Ƿ�
				if (gOneByteCodeMap[code].OpStr)
					strcpy_s(DisasmResultTmp->Opcode, gOneByteCodeMap[code].OpStr);
				DisasmResultTmp->CurrentLen = 0;
				if (gOneByteCodeMap[code].DisasmFunc(DisasmResultTmp, DisasmPoint, &SegmentIsFinished))
				{
					if (DisasmResultTmp->CurrentLen == 0)
						DisasmResultTmp->CurrentLen = UINT(DisasmPoint->CurMemAddr - StartDisasmAddr);//����ָ���
					memcpy(DisasmResultTmp->MachineCode, (LPVOID)(StartDisasmAddr), DisasmResultTmp->CurrentLen);//����������
					if (DisasmPoint->CurMemAddr == DisasmPoint->FileEndOfCode) //����Ƿ��ļ���β
					{
						SegmentIsFinished = 1;
					}
					DisasmPoint->TotalDisasmRecord += 1;
					if (code != 0x0f)  //�˴�ֻ������һ�ֽڲ�����Ĳ�����  �����ֽڲ���������ʵ�ֲ����޸�
					{
						if (DisasmResultTmp->OperandNum == 0)
							DisasmResultTmp->OperandNum = GET_OPERAND_NUM((gOneByteCodeMap[code].Operand)); //����ָ���ں������޸Ĵ˲���
					}
					if (IsGernerl)
					{
						TestPrintToFile();
						exit(0);
					}
					break; //��ǰָ��������
				}
			}
			if (SegmentIsFinished)
			{
				//TestPrintToFile();
				//exit(0);
			}
		}
	}
	IndexResultBySeq(DisasmPoint);
	//printf("������� \n");
	return true;
}
bool Disasm::TestPrintToFile() const
{

	FILE *fp = fopen("D:\\python\\DisasmTools\\NJ_disasm.txt", "w+");
	char PrintData[256] = { 0 };
	char tmp[256] = { 0 };
	for (UINT i = 0; i < DisasmPoint->LenOfCode; i++)
	{
		if (*(DisasmResult + i) == nullptr)
			continue;
		DISASM_RESULT* TmpResult = *(DisasmResult + i);
		if (TmpResult == nullptr || TmpResult->CurFileOffset == 0)
			continue;
		sprintf_s(PrintData, "%08llX", TmpResult->CurFileOffset + DisasmPoint->BaseOfImage);
		strcat_s(PrintData, "|");
		//��ǰ׺
		UINT count = 0;
		int x = TmpResult->PrefixState;
		while (x)
		{
			count++;
			x &= (x - 1);
		}
		memset(tmp, 0x00, sizeof(tmp));
		for (UINT j = 0; j < (TmpResult->CurrentLen); j++)
		{
			char HexData[4] = { 0 };
			sprintf(HexData, "%02X", *(BYTE*)((BYTE*)TmpResult->MachineCode + j));
			strcat(tmp, HexData);
			if ((count > 0) && (j < count))
				strcat(tmp, ":");
		}
		strcat(PrintData, tmp);
		strcat(PrintData, "|");
		//ǰ׺
		if (TmpResult->PrefixState&PREFIX_Lock_F0)
			strcat(PrintData, "lock ");
		else if (TmpResult->PrefixState&PREFIX_Repne_F2)
			strcat(PrintData, "repne ");
		else if (TmpResult->PrefixState&PREFIX_Repe_F3)
			strcat(PrintData, "repe ");
		if (TmpResult->OperandNum == 0)
			sprintf(tmp, "%s", TmpResult->Opcode);
		else if (TmpResult->OperandNum == 1)
			sprintf(tmp, "%s %s", TmpResult->Opcode, TmpResult->Operand[0]);
		else if (TmpResult->OperandNum == 2)
			sprintf(tmp, "%s %s,%s", TmpResult->Opcode, TmpResult->Operand[0], TmpResult->Operand[1]);
		else if (TmpResult->OperandNum == 3)
			sprintf(tmp, "%s %s,%s,%s", TmpResult->Opcode, TmpResult->Operand[0],
				TmpResult->Operand[1], TmpResult->Operand[2]);
		strcat(PrintData, tmp);
		strcat(PrintData, "\n");
		fwrite(PrintData, strlen(PrintData), 1, fp);
	}
	fclose(fp);
	return false;
}
bool Disasm::SetDataType(DISASM_POINT* DisasmPoint, DWORD addr, int size)
{

	return true;
}


bool Disasm::GernelDisasm(DISASM_RESULT * DisasmResult, DISASM_POINT*  DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	code = 0x00;
	IsGernerl = true;
	return true;
}
char NumbericTypeResult[16];
char * Disasm::GetNumbericType(DISASM_RESULT * DisasmResult, int base, int seg)
{
	ZeroMemory(NumbericTypeResult, sizeof(NumbericTypeResult));
	if (DisasmResult->PrefixState&PREFIX_Seg_ES_26 || DisasmResult->SIB_Prefix & PREFIX_Seg_ES_26||seg& PREFIX_Seg_ES_26)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "es");
	else if (DisasmResult->PrefixState&PREFIX_Seg_CS_2E || DisasmResult->SIB_Prefix & PREFIX_Seg_CS_2E || seg & PREFIX_Seg_CS_2E)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "cs");
	else if (DisasmResult->PrefixState&PREFIX_Seg_SS_36 || DisasmResult->SIB_Prefix & PREFIX_Seg_SS_36 || seg & PREFIX_Seg_SS_36)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "ss");
	else if (DisasmResult->PrefixState&PREFIX_Seg_DS_3E || DisasmResult->SIB_Prefix & PREFIX_Seg_DS_3E || seg & PREFIX_Seg_DS_3E)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "ds");
	else if (DisasmResult->PrefixState&PREFIX_Seg_FS_64 || DisasmResult->SIB_Prefix & PREFIX_Seg_FS_64 || seg & PREFIX_Seg_FS_64)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "fs");
	else if (DisasmResult->PrefixState&PREFIX_Seg_GS_65 || DisasmResult->SIB_Prefix & PREFIX_Seg_GS_65 || seg & PREFIX_Seg_GS_65)
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "gs");
	else  //Ĭ��Ϊds
		sprintf(NumbericTypeResult, "%s %s:", gNumbericType[base], "ds");
	return NumbericTypeResult;
}

int Disasm::GetOperAndAddrSize2(int platFrom, UINT64 Prefix, int * addrSize, int * OperandSize)
{
	//intel 82ҳ
	int tmpAddrSize = 0;
	int tmpOperandSize = 0;
	switch (platFrom)
	{
	case PLATFORM_16BIT:
		tmpOperandSize = PLATFORM_16BIT;
		tmpAddrSize = PLATFORM_16BIT;
		if (Prefix&PREFIX_Oprand_Size_66)
			tmpOperandSize = PLATFORM_32BIT;
		if (Prefix&PREFIX_Address_Size_67)
			tmpAddrSize = PLATFORM_32BIT;
		break;
	case PLATFORM_32BIT:
		tmpOperandSize = PLATFORM_32BIT;
		tmpAddrSize = PLATFORM_32BIT;
		if (Prefix&PREFIX_Oprand_Size_66)
			tmpOperandSize = PLATFORM_16BIT;
		if (Prefix&PREFIX_Address_Size_67)
			tmpAddrSize = PLATFORM_16BIT;
		break;
	case PLATFORM_64BIT:
		if (Prefix&PREFIX_REX_W)
			tmpOperandSize = PLATFORM_64BIT;
		else
		{
			if (Prefix&PREFIX_Oprand_Size_66)
				tmpOperandSize = PLATFORM_16BIT;
			else
				tmpOperandSize = PLATFORM_32BIT;
		}
		if (Prefix&PREFIX_Address_Size_67)
			tmpAddrSize = PLATFORM_32BIT;
		else
			tmpAddrSize = PLATFORM_64BIT;
	}
	if (addrSize) *addrSize = tmpAddrSize;
	if (OperandSize) *OperandSize = tmpOperandSize;
	return 0;
}


int Disasm::GetOperAndAddrSize(int platFrom, UINT64 Prefix, UINT64 OperandInt, int* addrSize, int* OperandSize)
{
	//���ȼ��������Ŀ��
	if (addrSize)
	{
		for (int i = 0; i < GET_OPERAND_NUM(OperandInt); i++)
		{
			switch (GET_OPERAND_TYPE(OperandInt, i)) //���ܻ����bug
			{
			case OT__b:
				*addrSize = PLATFORM_8BIT;
				break;
			case OT__w:
				*addrSize = PLATFORM_16BIT;
				break;
			case OT__v:
			case OT__z:
			case OT__d:
				*addrSize = PLATFORM_32BIT;
				break;
			}

		}
		if (Prefix&PREFIX_Oprand_Size_66)
			*addrSize += 1;
		if (Prefix&PREFIX_REX_W)
		{
			*addrSize = PLATFORM_64BIT;
		}
	}
	if (OperandSize)
	{
		switch (platFrom)
		{
		case PLATFORM_8BIT:
			*OperandSize = PLATFORM_8BIT;
			break;
		case PLATFORM_16BIT:
			if(Prefix&PREFIX_Oprand_Size_66)
				*OperandSize = PLATFORM_32BIT;
			else
				*OperandSize = PLATFORM_16BIT;
			break;
		case PLATFORM_32BIT:
			if (Prefix&PREFIX_Oprand_Size_66)
				*OperandSize = PLATFORM_16BIT;
			else
				*OperandSize = PLATFORM_32BIT;
			break;
		case PLATFORM_64BIT:
			*OperandSize = PLATFORM_32BIT;
			break;
		}
	}
	return 0;
}



int Disasm::GetSegReg(UINT64 OperandInt, int DefReg)
{
	if ((OperandInt&(PREFIX_Seg_ES_26 | PREFIX_Seg_CS_2E | PREFIX_Seg_SS_36 | PREFIX_Seg_DS_3E | PREFIX_Seg_FS_64 | PREFIX_Seg_GS_65)) == 0)
		return DefReg;
	if (OperandInt&PREFIX_Seg_ES_26)
		return 0;
	if (OperandInt&PREFIX_Seg_CS_2E)
		return 1;
	if (OperandInt&PREFIX_Seg_SS_36)
		return 2;
	if (OperandInt&PREFIX_Seg_DS_3E)
		return 3;
	if (OperandInt&PREFIX_Seg_FS_64)
		return 4;
	if (OperandInt&PREFIX_Seg_GS_65)
		return 5;
}

bool Disasm::Disasm_GetEachOperand(DISASM_RESULT*DisasmResult, DISASM_POINT*  DisasmPoint, int* IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	DWORD64 OperandInt = ((str_map_code*)DisasmResult->CodeMap + code)->Operand;

	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = GET_OPERAND_NUM(OperandInt);

	for (int i = 0; i < GET_OPERAND_NUM(OperandInt); i++)
	{
		switch (GET_ADDRES_TYPE(OperandInt, i))
		{
		case AT__I:
			Disasm_GetImm(i, GET_OPERAND_TYPE(OperandInt, i),DisasmResult, DisasmPoint);
			break;
		}
	}

	return true;
}

bool Disasm::Disasm_GetImm(int pos,int type,DISASM_RESULT*DisasmResult, DISASM_POINT*  DisasmPoint)
{
	switch (type)
	{
	case OT__b:
		sprintf(DisasmResult->Operand[pos], "0x%X", *(UCHAR*)DisasmPoint->CurMemAddr);
		DisasmPoint->CurMemAddr += 1; //��ǰ������
		break;
	}
	return false;
}

bool Disasm::Disasm_no_operand(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_d4_d5(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*((UCHAR*)(DisasmPoint->CurMemAddr) + 1) == 0x0A)
	{
		DisasmPoint->CurMemAddr += 2;
		DisasmResult->OperandNum = 0;
		return true;
	}
	return Disasm_GetEachOperand(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_a6_a7(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr)  == 0xa6)
	{
		strcpy_s(DisasmResult->Opcode, "cmpsb");
	}
	else
	{
		if(DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "cmpsq");
		else if(DisasmPoint->PlatForm==PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "cmpsw");
		else
			strcpy_s(DisasmResult->Opcode, "cmpsd");
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_6c_6d(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0x6c)
	{
		strcpy_s(DisasmResult->Opcode, "insb");
	}
	else
	{
		if(DisasmPoint->PlatForm==PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "insw");
		else
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "insw");
			else
				strcpy_s(DisasmResult->Opcode, "insd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_cc(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	strcpy_s(DisasmResult->Opcode, "int3");
	return true;
}

bool Disasm::Disasm_cf(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	switch (DisasmPoint->PlatForm)
	{
	case PLATFORM_16BIT:strcpy_s(DisasmResult->Opcode, "iret"); break;
	case PLATFORM_32BIT:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			strcpy_s(DisasmResult->Opcode, "iret");
		else
			strcpy_s(DisasmResult->Opcode, "iretd");
		break;
	case PLATFORM_64BIT:
		if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "iretq");
		else
			strcpy_s(DisasmResult->Opcode, "iretd");
		break;
	}
	return true;
}

bool Disasm::Disasm_ac_ad(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0xac)
	{
		strcpy_s(DisasmResult->Opcode, "lodsb");
	}
	else
	{
		char Opcode[][8] = { "lodsw","lodsd","lodsq" };
		if(DisasmPoint->PlatForm==PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, Opcode[0]);
		else if (DisasmResult->PrefixState&PREFIX_REX_W)
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, Opcode[0]);
			else
				strcpy_s(DisasmResult->Opcode, Opcode[2]);
		}
			strcpy_s(DisasmResult->Opcode, Opcode[2]);
		// 32λ ad  lodsd      //lods dword ptr [esi]
		// 32λ 67 ad  lodsd      lods dword ptr [si]
		// 32λ 66 ad  lodsw      //lods word ptr [esi]
		// 32λ 66 67 ad  lodsw   lods word ptr [si]
		// 64λ ad  lodsd 
		// 64λ 66 ad  lodsw 
		// 64λ 67 ad  lodsd     lods dword ptr [esi]
		// 64λ 66 67 ad  lods     lods word ptr [esi]
		// 64λ REX.W ad  lodsq 
		// 64λ REX.W 66 ad  lodsw 
		// 64λ REX.W 66 67 ad  lodsw  lods word ptr [si]
		if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "lodsw");
		else if(DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "lodsq");
		else 
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "lodsw");
			else
				strcpy_s(DisasmResult->Opcode, "lodsd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_a4_a5(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0xa4)
	{
		strcpy_s(DisasmResult->Opcode, "movsb");
	}
	else
	{
		if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "movsw");
		else if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "movsq");
		else
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "movsw");
			else
				strcpy_s(DisasmResult->Opcode, "movsd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_6e_6f(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0x6e)
	{
		strcpy_s(DisasmResult->Opcode, "outsb");
	}
	else
	{
		if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "outsw");
		else if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "outsq");
		else
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "outsw");
			else
				strcpy_s(DisasmResult->Opcode, "outsd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_aa_ab(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0xaa)
	{
		strcpy_s(DisasmResult->Opcode, "stosb");
	}
	else
	{
		if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "stosw");
		else if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "stosq");
		else
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "stosw");
			else
				strcpy_s(DisasmResult->Opcode, "stosd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_ae_af(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0xae)
	{
		strcpy_s(DisasmResult->Opcode, "scasb");
	}
	else
	{
		if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Opcode, "scasw");
		else if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "scasq");
		else
		{
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				strcpy_s(DisasmResult->Opcode, "scasw");
			else
				strcpy_s(DisasmResult->Opcode, "scasd");
		}
	}
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 0;
	return true;
}

bool Disasm::Disasm_set_prefix(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	DisasmResult->PrefixState |= gOneByteCodeMap[code].Operand;
	DisasmPoint->CurMemAddr += 1;
	if (DisasmResult->PreStr[0])
	{
		strcpy_s(DisasmResult->Opcode, "illegal instruction");
		return true;
	}
	switch (code)
	{
	case 0xF0:strcpy_s(DisasmResult->PreStr, "lock"); break;
	case 0xF2:strcpy_s(DisasmResult->PreStr, "repne"); break;
	case 0xF3:strcpy_s(DisasmResult->PreStr, "rep"); break;
	}
	return false;
}
bool Disasm::Disasm_ac_a4_6e_9d_aa_ae(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	DisasmResult->OperandNum = 1;
	int regSize = DisasmPoint->PlatForm;
	int OperandSize = 0;
	if (DisasmResult->PrefixState&PREFIX_Address_Size_67) //�Ĵ����������
		if(DisasmPoint->PlatForm!=PLATFORM_16BIT)
			regSize -= 1;
		else
			regSize += 1;
	sprintf(DisasmResult->Operand[0], "%s %s[%s]", gNumbericType[OperandSize],gSegRegStr[GetSegReg(DisasmResult->PrefixState,3)], gRegister[regSize*RG__MAX+6]);
	return true;
}








bool Disasm::Disasm_reg_or_imm(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	DWORD64 OperandInt = ((str_map_code*)DisasmResult->CodeMap + code)->Operand;
	int base = 0;
	DisasmPoint->CurMemAddr += 1; //OpCode �ֽ�
	int addrSize = 0;
	int operandSize = 0;
	GetOperAndAddrSize(DisasmPoint->PlatForm,DisasmResult->PrefixState, OperandInt, &addrSize, &operandSize);
	for (int i = 0; i < GET_OPERAND_NUM(OperandInt); i++)
	{
		switch (GET_OPERAND_TYPE(OperandInt, i)) //���ܻ����bug
		{
		case OT__b:
			base = 0;
			break;
		case OT__w:
			base = 1;
			break;
		case OT__v:
		case OT__z:
		case OT__d:
			base = 2;
			break;
		}
		switch (GET_ADDRES_TYPE(OperandInt, i))
		{
		case AT__X:  //DS:rSI Ѱַ
			sprintf(DisasmResult->Operand[i], "%s[%s]", GetNumbericType(DisasmResult, addrSize), gRegister[RG__SI + operandSize * RG__MAX]);
			break;
		case AT__Y:  //ES:rDI Ѱַ
			sprintf(DisasmResult->Operand[i], "%s[%s]", GetNumbericType(DisasmResult, addrSize, PREFIX_Seg_ES_26), gRegister[RG__DI + operandSize * RG__MAX]);
			break;
		case AT__REG8:
			sprintf(DisasmResult->Operand[i], "%s", gRegister[GET_OPERAND_TYPE(OperandInt, i)]);
			break;
		case AT_XX:
			sprintf(DisasmResult->Operand[i], "%s", gRegister[GET_OPERAND_TYPE(OperandInt, i) + RG__MAX]);
			break;
		case AT_eXX:
		case AT_rXX:
			base = 2;
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
				sprintf(DisasmResult->Operand[i], "%s", gRegister[GET_OPERAND_TYPE(OperandInt, i) + (base - 1) * RG__MAX]);
			else
				sprintf(DisasmResult->Operand[i], "%s", gRegister[GET_OPERAND_TYPE(OperandInt, i) + base * RG__MAX]);
			break;
		case AT__I:
			switch (GET_OPERAND_TYPE(OperandInt, i))
			{
			case OT__b:
				if(*(UCHAR*)DisasmPoint->CurMemAddr&0x80)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(UCHAR*)DisasmPoint->CurMemAddr^0xFF)+1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(UCHAR*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 1; //��ǰ������
				break;
			case OT__w:
			OPERAND_TWO:
				if(*(USHORT*)DisasmPoint->CurMemAddr&0x8000)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(USHORT*)DisasmPoint->CurMemAddr^0xFFFF)+1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(USHORT*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 2; //��ǰ������
				break;
			case OT__d:
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
					goto OPERAND_TWO;

			OPERAND_FOUR:
				if(*(DWORD32*)DisasmPoint->CurMemAddr&0x80000000)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(DWORD32*)DisasmPoint->CurMemAddr ^ 0xFFFFFFFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(DWORD32*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4; //��ǰ������
				break;
			case OT__q:
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
					goto OPERAND_FOUR;
			OPERAND_EIGHT:
				if (*(DWORD64*)DisasmPoint->CurMemAddr & 0x8000000000000000)
					sprintf(DisasmResult->Operand[i], "-0x%llX", (*(DWORD64*)DisasmPoint->CurMemAddr ^ 0xFFFFFFFFFFFFFFFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%llX", *(DWORD64*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 8; //��ǰ������
				break;
			case OT__z:
			case OT__v:
				int IntSize = 4;
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
					IntSize /= 2;
				if (IntSize == 2) goto OPERAND_TWO;
				if (IntSize == 4) goto OPERAND_FOUR;
				if (IntSize == 8) goto OPERAND_EIGHT;
				break;
			}
			break;
		case AT__J: //���λ��
		case AT__A:  //ֱ�ӵ�ַ
		{
			DWORD64 Offset = 0;
			//�����з��ź��޷���
			switch (GET_OPERAND_TYPE(OperandInt, i))
			{
			case OT__b:
			INT_1:
				Offset = *(BYTE*)DisasmPoint->CurMemAddr;
				if ((Offset & 0x80) && (GET_ADDRES_TYPE(OperandInt, i) == AT__J))
					Offset = ((Offset ^ 0xFF) + 1)*-1;
				DisasmPoint->CurMemAddr = DisasmPoint->CurMemAddr + sizeof(BYTE);  //����������
				break;
			case OT__w:
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66) goto INT_1;
			INT_2:
				Offset = *(short*)DisasmPoint->CurMemAddr;
				if ((Offset & 0x8000) && (GET_ADDRES_TYPE(OperandInt, i) == AT__J))
					Offset = ((Offset ^ 0xFFFF) + 1)*-1;
				DisasmPoint->CurMemAddr = DisasmPoint->CurMemAddr + sizeof(short);  //����������
				break;
			case OT__d:
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66) goto INT_2;
			INT_4:
				Offset = *(DWORD32*)DisasmPoint->CurMemAddr;
				if ((Offset & 0x80000000) && (GET_ADDRES_TYPE(OperandInt, i) == AT__J))
					Offset = ((Offset ^ 0xFFFFFFFF) + 1)*-1;
				DisasmPoint->CurMemAddr = DisasmPoint->CurMemAddr + sizeof(DWORD32);  //����������
				break;
			case OT__q:
				if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66) goto INT_4;
			INT_8:
				Offset = *(DWORD64*)DisasmPoint->CurMemAddr;
				if ((Offset & 0x8000000000000000) && (GET_ADDRES_TYPE(OperandInt, i) == AT__J))
					Offset = ((Offset ^ 0xFFFFFFFFFFFFFFFF) + 1)*-1;
				DisasmPoint->CurMemAddr = DisasmPoint->CurMemAddr + sizeof(DWORD64);  //����������
				break;
			case OT__z:
			case OT__v:
				if (base == 1) goto INT_2;
				if (base == 2) goto INT_4;
				if (base == 3) goto INT_8;
				break;
			}
			//TODO �˴�ֻ�ʺϹ̶���ַ��������ض�λ��ʱ����Ҫ�޸�
			UINT64 CurrentAddr = DisasmPoint->CurMemAddr - DisasmPoint->FileStartOfCode + DisasmPoint->VirtualAddress + DisasmPoint->BaseOfImage;
			switch (DisasmPoint->PlatForm)
			{
			case PLATFORM_16BIT:
				sprintf(DisasmResult->Operand[i], "%04X", (USHORT)(CurrentAddr + Offset));
				break;
			case PLATFORM_32BIT:
				sprintf(DisasmResult->Operand[i], "%08X", (UINT)(CurrentAddr + Offset));
				break;
			case PLATFORM_64BIT:
				sprintf(DisasmResult->Operand[i], "%016llX", CurrentAddr + Offset);
				break;
			}
			//����ǰ��ַ�����������ַ��
			if (code == 0xe8 || code == 0xe9 || code == 0xeb || (code & 0x70) == 0x70)
			{
				PushDisasmFuncAddr((LPVOID)(CurrentAddr + Offset - DisasmPoint->BaseOfImage));
				char str[64] = { 0 };
				//sprintf(str, "%x %X\n", code, CurrentAddr + Offset - DisasmPoint->BaseOfImage);
				//printf(str);
			}
			break;
		}
		case AT__O:
			//�������ֻ�� mov ��ʹ��   �����64λ�����ַ��Ҫ�ĳ�64λ��С
			if (DisasmPoint->PlatForm == PLATFORM_32BIT)
			{
				sprintf(DisasmResult->Operand[i], "%s[0x%X]", GetNumbericType(DisasmResult, base), *(UINT*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4; //��ǰ������
			}
			else //64λ
			{
				sprintf(DisasmResult->Operand[i], "%s[0x%X]", GetNumbericType(DisasmResult, base), *(UINT64*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 8; //��ǰ������
			}
			break;
		}
	}
	return true;
}

bool Disasm::Disasm_ModRM(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{

	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	DisasmPoint->CurMemAddr += 1; //Opcode �ֽ�

	int base = 0;
		//����ModRM�ֽ�
	UCHAR ModRMByte = *(UCHAR*)DisasmPoint->CurMemAddr;
	DisasmPoint->CurMemAddr += 1;  //ModRm �ֽ�
	char SibStr[64] = { 0 };
	UCHAR SIBByte = *(UCHAR*)DisasmPoint->CurMemAddr;
	DWORD len = 0;

	//���ö�ǰ׺
	switch (ModRMByte & 0b111)
	{
	case 0b101:
		if((ModRMByte&0b11000000)!=0)
			DisasmResult->SIB_Prefix |= PREFIX_Seg_SS_36;
		break;
	}

	for (unsigned int i = 0; i < GET_OPERAND_NUM(((str_map_code*)DisasmResult->CodeMap + code)->Operand); i++)
	{
		//���ֵ�ַ���͹̶��˲�������ַ��ȣ���ʱ�����ٸ��ݲ������������жϲ�������ַ�����
		switch (GET_ADDRES_TYPE(((str_map_code*)DisasmResult->CodeMap + code)->Operand, i))
		{
		case AT__C:
			break;
		}
		//ȷ�����������
		switch (GET_OPERAND_TYPE(((str_map_code*)DisasmResult->CodeMap + code)->Operand, i))
		{
		case OT__b: 
			base = OPERAND_BYTE; 
			goto LOOP_OUT;
		case OT__w:
			base = OPERAND_WORD;
			goto LOOP_OUT;
		case OT__d:
			base = OPERAND_DOUBLE_WORD;
			goto LOOP_OUT;
		case OT__dq:
			base = OPERAND_DOUBLE_QUAD_WORD;
			goto LOOP_OUT;
		case OT__q:
			base = OPERAND_QUAD_WORD;
			goto LOOP_OUT;
		case OT__qq:
			base = OPERAND_QUAD_QUAD_WORD;
			goto LOOP_OUT;
		case OT__v: 
			base = OPERAND_DOUBLE_WORD; 
			break;
		case OT__z:
			if (sizeof(LPVOID) == 2) base = OPERAND_WORD;
			else base = OPERAND_DOUBLE_WORD;
			break;
		case OT__ss:break;
		case OT__x:break;
		case OT__ps:break;
		case OT__y:break;
		case OT__pd:break;
		case OT__p:break;
		case OT__pi:break;
		case OT__a:break;
		case OT__sd:break;
		}
	}
LOOP_OUT:
	for (unsigned int i = 0; i < GET_OPERAND_NUM(((str_map_code*)DisasmResult->CodeMap + code)->Operand); i++)
	{
		
		//��������Сǰ׺
		int OperandPrefix = 0;
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)OperandPrefix = -1;
		else if(DisasmResult->PrefixState&PREFIX_REX_W) OperandPrefix = 1;

		//��ȷ��ǰ��Ҫ��ȡ���� MomRm��Ϣ ���� REG ��Ϣ
		switch (GET_ADDRES_TYPE(((str_map_code*)DisasmResult->CodeMap + code)->Operand, i))
		{
		case AT__G: //reg:ͨ�üĴ���
				sprintf(DisasmResult->Operand[i], "%s", gRegister[((ModRMByte & 0b111000) >> 3) + (base + OperandPrefix) * RG__MAX]);
				break;
		case AT__I:  //������
			switch (base)
			{
			case 0:
BBB_0:
				if (*(UCHAR*)DisasmPoint->CurMemAddr & 0x80)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(UCHAR*)DisasmPoint->CurMemAddr ^ 0xFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(UCHAR*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 1;
				break;
			case 1:
				if (OperandPrefix<0) goto BBB_0;
BBB_1:
				if (*(USHORT*)DisasmPoint->CurMemAddr & 0x8000)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(USHORT*)DisasmPoint->CurMemAddr ^ 0xFFFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(USHORT*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 2;
				break;
			case 2:
				if (OperandPrefix < 0) goto BBB_1;
BBB_2:
				if (*(DWORD32*)DisasmPoint->CurMemAddr & 0x80000000)
					sprintf(DisasmResult->Operand[i], "-0x%X", (*(DWORD32*)DisasmPoint->CurMemAddr ^ 0xFFFFFFFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%X", *(DWORD32*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4;
				break;
			case 3:
				if (OperandPrefix < 0) goto BBB_2;
BBB_3:
				if (*(DWORD64*)DisasmPoint->CurMemAddr & 0x8000000000000000)
					sprintf(DisasmResult->Operand[i], "-0x%llX", (*(DWORD64*)DisasmPoint->CurMemAddr ^ 0xFFFFFFFFFFFFFFFF) + 1);
				else
					sprintf(DisasmResult->Operand[i], "0x%llX", *(DWORD64*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 8;
				break;
			}
			break;
		case AT__E:  //�Ĵ��� ���� sib�ڴ�
		case AT__M:  //�ڴ�
			switch (ModRMByte & 0b11000000)
			{
			case 0b00000000:
				switch (ModRMByte & 0b111)
				{
				case 0b100://SIB
					Disasm_SIB(DisasmResult, DisasmPoint, &len, SibStr);
					sprintf((char*)*(DisasmResult->Operand + i), "%s[%s]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr);
					DisasmPoint->CurMemAddr += len;
					break;
				case 0b101:
					sprintf((char*)*(DisasmResult->Operand + i), "%s[0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), *(DWORD32*)DisasmPoint->CurMemAddr);
					DisasmPoint->CurMemAddr += 4;  //32λƫ���ֽ�
					break;
				default:
					sprintf((char*)*(DisasmResult->Operand + i), "%s[%s]", GetNumbericType(DisasmResult, base + OperandPrefix), gRegister[(ModRMByte & 0x7) + DisasmPoint->PlatForm * RG__MAX]);
				}
				break;
			case 0b01000000:
				switch (ModRMByte & 0x7)
				{
				case 0x4://SIB
					Disasm_SIB(DisasmResult, DisasmPoint, &len, SibStr);
					DisasmPoint->CurMemAddr += len;
					if ((SIBByte & 0b111) == 0b0101) //SIB�ֽڰ���ƫ���� �˴�����Ҫ��ƫ��
						sprintf((char*)*(DisasmResult->Operand + i), "%s[%s]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr);
					else
						if(*(UCHAR*)DisasmPoint->CurMemAddr&0x80)
							sprintf((char*)*(DisasmResult->Operand + i), "%s[%s-0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, (*(UCHAR*)DisasmPoint->CurMemAddr^0xFF)+1);
						else
							sprintf((char*)*(DisasmResult->Operand + i), "%s[%s+0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, *(UCHAR*)DisasmPoint->CurMemAddr);
						DisasmPoint->CurMemAddr += 1;
					break;
				default:
					if (*(UCHAR*)DisasmPoint->CurMemAddr & 0x80)
						sprintf((char*)*(DisasmResult->Operand + i), "%s[%s-0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), gRegister[(ModRMByte & 0x7) + DisasmPoint->PlatForm  * RG__MAX], (*(UCHAR*)DisasmPoint->CurMemAddr ^ 0xFF) + 1);
					else
						sprintf((char*)*(DisasmResult->Operand + i), "%s[%s+0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), gRegister[(ModRMByte & 0x7) + DisasmPoint->PlatForm  * RG__MAX], *(UCHAR*)DisasmPoint->CurMemAddr);
					DisasmPoint->CurMemAddr += 1;// 8λƫ���ֽ�
				}
				break;
			case 0b10000000:
				switch (ModRMByte & 0x7)
				{
				case 0x4: //SIB
					Disasm_SIB(DisasmResult, DisasmPoint, &len, SibStr);
					DisasmPoint->CurMemAddr += len;
					if ((SIBByte & 0b111) == 0b0101) //SIB�ֽڰ���ƫ���� �˴�����Ҫ��ƫ��
						sprintf((char*)*(DisasmResult->Operand + i), "%s[%s]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr);
					else
						if(base==0)
						{
							if(*(UCHAR*)DisasmPoint->CurMemAddr&0xFF)
								sprintf((char*)*(DisasmResult->Operand + i), "%s[%s-0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, (0xFF^*(UCHAR*)DisasmPoint->CurMemAddr)+1);
							else
								sprintf((char*)*(DisasmResult->Operand + i), "%s[%s+0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, *(UCHAR*)DisasmPoint->CurMemAddr);
							DisasmPoint->CurMemAddr += 1;
						}
						else if(base==2)
						{
							if (*(DWORD32*)DisasmPoint->CurMemAddr & 0x80000000)
								sprintf((char*)*(DisasmResult->Operand + i), "%s[%s-0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, (0xFFFFFFFF^*(DWORD32*)DisasmPoint->CurMemAddr)+1);
							else
								sprintf((char*)*(DisasmResult->Operand + i), "%s[%s+0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), SibStr, *(DWORD32*)DisasmPoint->CurMemAddr);
							DisasmPoint->CurMemAddr += 4;
						}
					break;
				default:
					if (*(DWORD32*)DisasmPoint->CurMemAddr & 0x80000000)
						sprintf((char*)*(DisasmResult->Operand + i), "%s[%s-0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), gRegister[(ModRMByte & 0x7) + DisasmPoint->PlatForm  * RG__MAX],(0xFFFFFFFF^ *(DWORD32*)DisasmPoint->CurMemAddr)+1);
					else
					sprintf((char*)*(DisasmResult->Operand + i), "%s[%s+0x%X]", GetNumbericType(DisasmResult, base + OperandPrefix), gRegister[(ModRMByte & 0x7) + DisasmPoint->PlatForm  * RG__MAX], *(DWORD32*)DisasmPoint->CurMemAddr);
					DisasmPoint->CurMemAddr += 4;  //32λƫ���ֽ�
				}
				break;
			case 0b11000000:
				sprintf((char*)*(DisasmResult->Operand + i), "%s", gRegister[(ModRMByte & 0x7) + (base + OperandPrefix) * RG__MAX]);
				break;
			}
			break;
		case AT__V: break; //reg:xmm ymm
		case AT__W: break; //xmm ymm sib�ڴ�
		case AT__U: break; //rm:xmm ymm
		case AT__R: break; //rm:ͨ�üĴ���
			sprintf(DisasmResult->Operand[i], "%s", gRegister[(ModRMByte & 0b111) + (base + OperandPrefix) * RG__MAX]);
			break;
		case AT__Q: break; // xmm ymm sib�ڴ�
		case AT__C: break; //reg:���ƼĴ���
			//intel �ֲ� 1166ҳ ���ƹ���
			switch (ModRMByte & 0b111)
			{
			case 1:
			case 5:
			case 6:
			case 7:
				//TODO �Ƿ�����
				break;
			default:
				sprintf(DisasmResult->Operand[i], "cr%d", ModRMByte & 0b111);
				break;
			}
			break;
		case AT__D: break; //reg:���ԼĴ���
			sprintf(DisasmResult->Operand[i], "dr%d", ModRMByte & 0b111);
			break;
		case AT__N: break; //rm:xmm ymm
		case AT__P: break; //reg: xmm ymm
		case AT__S: break; //reg �μĴ���
			sprintf(DisasmResult->Operand[i], "%s", gSegmentRegister[ModRMByte & 0b111]);
			break;
		}

	}
	return true;
}

bool Disasm::Disasm_SIB(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, PDWORD Len, char* SIBStr)
{
	UCHAR SIB_Byte = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR Mom_Byte = *(UCHAR*)(DisasmPoint->CurMemAddr - 1);

	UCHAR Scale[][4] = { "","*2","*4","*8" };
	DisasmPoint->CurMemAddr += 1; //SIB �ֽ�
	if ((SIB_Byte & 0b111000) == 0b100000)  //index Ϊ none
	{
		if ((SIB_Byte & 0b111) == 0b101) //base ����ƫ��
		{
			switch (Mom_Byte & 0b11000000)
			{
			case 0b00000000:  //32λƫ��
				sprintf(SIBStr, "0x%X", *(DWORD*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4;
				break;
			case 0b01000000: // 8λƫ��+ebp
				if(*(UCHAR*)DisasmPoint->CurMemAddr&0x80)
					sprintf(SIBStr, "ebp-0x%X", (0xFF^*(UCHAR*)DisasmPoint->CurMemAddr)+1);
				else
					sprintf(SIBStr, "ebp+0x%X", *(UCHAR*)DisasmPoint->CurMemAddr);
				DisasmResult->SIB_Prefix = PREFIX_Seg_SS_36;
				DisasmPoint->CurMemAddr += 1;
				break;
			case 0b10000000:// 32λƫ��+ebp
				if (*(DWORD32*)DisasmPoint->CurMemAddr & 0x80000000)
					sprintf(SIBStr, "ebp-0x%X", (0xFFFFFFFF^*(DWORD32*)DisasmPoint->CurMemAddr)+1);
				else
					sprintf(SIBStr, "ebp+0x%X", *(DWORD32*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4;
				DisasmResult->SIB_Prefix = PREFIX_Seg_SS_36;
				break;
			}
		}
		else
		{
			sprintf(SIBStr, "%s", gRegister[(SIB_Byte & 0b111) + DisasmPoint->PlatForm*RG__MAX]);
		}
	}
	else //index ��Ϊ none
	{
		if ((SIB_Byte & 0b111) == 0b101) //base ����ƫ��
		{
			switch (Mom_Byte & 0b11000000)
			{
			case 0b00000000:  //32λƫ��
				if(*(DWORD*)DisasmPoint->CurMemAddr&0x80000000)
					sprintf(SIBStr, "%s%s-0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], (0xFFFFFFFF^*(DWORD*)DisasmPoint->CurMemAddr)+1);
				else
					sprintf(SIBStr, "%s%s+0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], *(DWORD*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4;
				break;
			case 0b01000000: // 8λƫ��+ebp
				if(*(UCHAR*)DisasmPoint->CurMemAddr&0x80)
					sprintf(SIBStr, "ebp+%s%s-0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], (0xFF^*(UCHAR*)DisasmPoint->CurMemAddr)+1);
				else
					sprintf(SIBStr, "ebp+%s%s+0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], *(UCHAR*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 1;
				DisasmResult->SIB_Prefix = PREFIX_Seg_SS_36;
				break;
			case 0b10000000:// 32λƫ��+ebp
				if (*(DWORD*)DisasmPoint->CurMemAddr & 0x80000000)
					sprintf(SIBStr, "ebp+%s%s-0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], (0xFFFFFFFF ^ *(DWORD*)DisasmPoint->CurMemAddr) + 1);
				else
				sprintf(SIBStr, "ebp+%s%s+0x%X", gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6], *(DWORD*)DisasmPoint->CurMemAddr);
				DisasmPoint->CurMemAddr += 4;
				DisasmResult->SIB_Prefix = PREFIX_Seg_SS_36;
				break;
			}
		}
		else
		{
			sprintf(SIBStr, "%s+%s%s", gRegister[(SIB_Byte & 0b111) + DisasmPoint->PlatForm*RG__MAX], gRegister[((SIB_Byte >> 3) & 0b111) + DisasmPoint->PlatForm*RG__MAX], Scale[SIB_Byte >> 6]);
		}
	}
	//����ǰ׺
	switch (SIB_Byte & 0b111)
	{
	case 0b100:
		DisasmResult->SIB_Prefix |= PREFIX_Seg_SS_36;
		break;
	}
	return true;
}
bool Disasm::Disasm_grp_80_83(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	//TODO 82 64λ��δ����
	char Opcode[][4] = { "add","or","adc","sbb","and","sub","xor","cmp" };
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}
bool Disasm::Disasm_grp_ff(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	//TODO 82 64λ��δ����
	char Opcode[][8] = { "inc","dec","call","call","jmp","jmp","push","" };
	UINT64 StartDisasmAddr = DisasmPoint->CurMemAddr;
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	UINT64 TmpAddr = DisasmPoint->CurMemAddr + 1;
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	DisasmResult->OperandNum = 1;
	switch ((ModRmByte >> 3) & 7)
	{
	case 0:
	case 1:
	case 2:
	case 4:
	case 6:
		gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__E, OT__v, 0, 0, 0, 0, 0, 0);
		break;
	case 3:
		gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__E, OT__p, 0, 0, 0, 0, 0, 0);
		break;
	case 5:
		gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__p, 0, 0, 0, 0, 0, 0);
		break;
	}
	//������һ��������
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	//����֧��ת
	TmpAddr += 1;
	UCHAR SIB_Byte = *(BYTE*)TmpAddr;
	if ((ModRmByte & 0b111000) == 0b100000) //near jmp
	{
		if ((ModRmByte & 0b111) == 0b101) //32λƫ��
		{
			//NONE_INDEX:

						//��鵼�뺯��
		}
		else if ((ModRmByte & 0b111) == 0b100) //SIB
		{
			if ((ModRmByte & 0b11000000) == 0) //ֻ��SIB
			{
				if ((SIB_Byte & 0b111) == 0b101) //��ƫ�Ƶ�ַ
				{
					if ((SIB_Byte & 0b111000) == 0b100000) //����Ϊ�յ����  ֻ��һ��32λƫ��
					{
						TmpAddr += 1; //����һ��SIB�ֽ�
						//goto NONE_INDEX;
					}
					else if ((SIB_Byte & 0b11000000) == 0b10000000) //�ı�����+ 32λƫ��
					{
						if (DisasmPoint->PlatForm == PLATFORM_32BIT)
						{
							TmpAddr += 1; //����һ��SIB�ֽ�
							DWORD JmpAddr = *(DWORD*)TmpAddr;
							DisasmResult->CurrentLen = UINT(DisasmPoint->CurMemAddr - StartDisasmAddr);
							for (UINT i = 0; i < (JmpAddr - DisasmResult->CurFileOffset - DisasmPoint->BaseOfImage - DisasmResult->CurrentLen); i++) //��֧��
							{
								DISASM_RESULT *DisasmReusltTmp = (DisasmResult + i + DisasmResult->CurrentLen);

							}
							UINT64 base = DisasmPoint->CurMemAddr;
							for (int i = 0;; i++) //��ת��
							{
								DWORD Addr = *(DWORD*)DisasmPoint->CurMemAddr;
								if (Addr<(DisasmPoint->BaseOfImage + DisasmPoint->VirtualAddress) || Addr>(DisasmPoint->BaseOfImage + DisasmPoint->LenOfCode))
									break;
								DISASM_RESULT *DisasmReusltTmp = (DisasmResult + i + DisasmResult->CurrentLen + (JmpAddr - DisasmResult->CurFileOffset - DisasmPoint->BaseOfImage));
								DisasmReusltTmp->IsData = true;
								DisasmReusltTmp->CurFileOffset = JmpAddr + i * sizeof(DWORD) - DisasmPoint->BaseOfImage;
								memcpy(DisasmReusltTmp->MachineCode, (LPVOID)DisasmPoint->CurMemAddr, sizeof(DWORD));
								DisasmPoint->CurMemAddr += sizeof(DWORD);
								DisasmReusltTmp->CurrentLen = sizeof(DWORD);
								DisasmReusltTmp->OperandNum = 0;

							}
						}
					}
				}
			}
		}
	}
	return true;
}
bool Disasm::Disasm_RexPrefix(DISASM_RESULT * DisasmResult, DISASM_POINT*  DisasmPoint, int * IsFinished)
{
	if (DisasmPoint->PlatForm != PLATFORM_64BIT)
	{
		UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
		DWORD64 OperandInt = gOneByteCodeMap[code].Operand;
		sprintf(DisasmResult->Operand[0], "%s", gRegister[GET_OPERAND_TYPE(OperandInt, 0) + DisasmPoint->PlatForm*RG__MAX]);
		DisasmPoint->CurMemAddr += 1;
		return true;
	}
	else
	{
		UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
		DisasmResult->PrefixState |= 1 << (code - 0x40);
		DisasmPoint->CurMemAddr += 1;
		DisasmResult->Opcode[0] = 0x00;
		return false;
	}
}

bool Disasm::Disasm_ret(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (GET_OPERAND_NUM(gOneByteCodeMap[code].Operand) > 0)
	{
		Disasm_reg_or_imm(DisasmResult, DisasmPoint, IsFinished);
	}
	else
	{
		DisasmPoint->CurMemAddr += 1;
	}
	*IsFinished = 1;
	return true;
}


bool Disasm::Disasm_grp_c6_c7(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	switch (ModRmByte & 0b00111000)
	{
	case 0b000000:
		strcpy_s(DisasmResult->Opcode, "mov");
		if (code == 0xc6)
		{
			gOneByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__b, AT__I, OT__b, 0, 0, 0, 0);
		}
		else
		{
			gOneByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__v, AT__I, OT__z, 0, 0, 0, 0);
		}
		break;
	case 0b111000:
		if ((ModRmByte & 0b11000000) == 0b11000000)
		{
			if (code == 0xc6)
			{
				strcpy_s(DisasmResult->Opcode, "xabort");
				gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__I, OT__b, 0, 0, 0, 0, 0, 0);
			}
			else
			{
				strcpy_s(DisasmResult->Opcode, "xbegin");
				gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__J, OT__z, 0, 0, 0, 0, 0, 0);
			}
		}
		break;
	}
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_grp_shift(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][4] = { "rol","ror","rcl","rcr","shl","shr","","sar" };
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf_s(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	DisasmResult->OperandNum = 2;
	switch (code)
	{
		//reg imm
	case 0xc0:
	case 0xd0:
	case 0xd2:
		gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__E, OT__b, 0, 0, 0, 0, 0, 0);
		break;

	case 0xc1:
	case 0xd1:
	case 0xd3:
		gOneByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__E, OT__v, 0, 0, 0, 0, 0, 0);
		break;
	}
	DWORD64 OperandInt = gOneByteCodeMap[code].Operand;
	//������һ��������
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	//�����ڶ���������
	switch (code)
	{
		//reg imm
	case 0xc0:
	case 0xc1:
		if (*(UCHAR*)DisasmPoint->CurMemAddr & 0x80)
			sprintf_s(DisasmResult->Operand[1], "-0x%X", (*(UCHAR*)DisasmPoint->CurMemAddr ^ 0xFF) + 1);
		else
			sprintf_s(DisasmResult->Operand[1], "0x%X", *(UCHAR*)DisasmPoint->CurMemAddr);
		DisasmPoint->CurMemAddr += 1;
		break;
		//reg 1
	case 0xd0:
	case 0xd1:
		sprintf_s(DisasmResult->Operand[1], "1");
		break;
		//reg cl
	case 0xd2:
	case 0xd3:
		sprintf_s(DisasmResult->Operand[1], "%s", gRegister[RG8__CL]);
		break;
	}
	return true;
}


bool Disasm::Disasm_pusha(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	if (DisasmPoint->PlatForm > PLATFORM_16BIT)
		strcpy_s(DisasmResult->Opcode, "pusha");
	else
		strcpy_s(DisasmResult->Opcode, "pushad");
	return true;
}

bool Disasm::Disasm_0xd5_0xd6(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*((UCHAR*)(DisasmPoint->CurMemAddr) + 1) == 0x0A)
	{
		DisasmPoint->CurMemAddr += 2;
		return true;
	}
	else
		return Disasm_reg_or_imm(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_popa(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	if (DisasmPoint->PlatForm > PLATFORM_16BIT)
		strcpy_s(DisasmResult->Opcode, "popa");
	else
		strcpy_s(DisasmResult->Opcode, "popad");
	return true;
}

bool Disasm::Disasm_pushf(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][7] = { "","pushf","pushfd","pushfq" };
	strcpy_s(DisasmResult->Opcode, Opcode[DisasmPoint->PlatForm]);
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_popf(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][7] = { "","popf","popfd","popfq" };
	strcpy_s(DisasmResult->Opcode, Opcode[DisasmPoint->PlatForm]);
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_grp_f6_f7(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][7] = { "test","","not","neg","mul","imul","div","idiv" };
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	DWORD64 OperandInt = gOneByteCodeMap[code].Operand;
	//�����ڶ���������
	switch ((ModRmByte >> 3) & 7)
	{
	case 0:
		DisasmResult->OperandNum = 2;
		if (code == 0xf6)//BYTE
		{
			char c = *(char*)DisasmPoint->CurMemAddr;
			sprintf(DisasmResult->Operand[1], "0x%X", c); //TODO �����Ż�
			DisasmPoint->CurMemAddr += 1;
		}
		else
		{
			sprintf(DisasmResult->Operand[1], "0x%X", *(int*)DisasmPoint->CurMemAddr);
			DisasmPoint->CurMemAddr += 4;
		}
		break;
	case 1:
		break;
	case 2:
	case 3:
		break;
	case 4:
	case 5:
	case 6:
	case 7:
		DisasmResult->OperandNum = 2;
		if (code == 0xF6)
		{
			strcpy_s(DisasmResult->Operand[1], (char*)gRegister[RG8__AL]);
		}
		else
		{
			strcpy_s(DisasmResult->Operand[1], (char*)gRegister[RG__AX + DisasmPoint->PlatForm*RG__MAX]);
		}
		break;
	}
	return true;
}

bool Disasm::Disasm_grp_fe(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{//TODO 82 64λ��δ����
	char Opcode[][8] = { "inc","dec","","","","","","" };
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	DisasmResult->OperandNum = 1;
	//������һ��������
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_int(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{

	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (code == 0xcc)
	{
		sprintf(DisasmResult->Operand[0], "0x03");
		DisasmPoint->CurMemAddr += 1;
		DisasmResult->OperandNum = 1;
	}
	else
	{
		Disasm_reg_or_imm(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_reserve(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	strcpy_s(DisasmResult->Opcode, "reserve opcode");
	return true;
}

bool Disasm::Disasm_bound(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	//������һ��������
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_0x63(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmPoint->PlatForm == PLATFORM_64BIT)
	{
		strcpy_s(DisasmResult->Opcode, "arpl");
		gOneByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__w, AT__G, OT__w, 0, 0, 0, 0);
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "movsxd");
		gOneByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__v, AT__E, OT__v, 0, 0, 0, 0);
	}
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_imul(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	DWORD64 OperandInt = gOneByteCodeMap[code].Operand;

	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}


bool Disasm::Disasm_grp_8f(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][4] = { "pop","","","","","","","" };
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_0x90(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	if (DisasmResult->PrefixState&PREFIX_Repe_F3)
		strcpy_s(DisasmResult->Opcode, "pause");
	else
		strcpy_s(DisasmResult->Opcode, "nop");

	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_ESC_0xd8(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	char OpCode[][8] = { "fadd" , "fmul" , "fcom" , "fcomp" , "fsub" , "fsubr" , "fdiv" , "fdivr" , };
	if (ModRmByte > 0xBF)
	{
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
		strcpy_s(DisasmResult->Operand[0], "st");
		char tmp[8] = { 0 };
		sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
		strcpy_s(DisasmResult->Operand[1], tmp);
		DisasmPoint->CurMemAddr += 2;
		DisasmResult->OperandNum = 2;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xd9(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	char OpCode[][8] = { "fld" , "" , "fst" , "fstp" , "fldenv" , "fldcw" , "fstenv" , "fstcw" , };
	if (ModRmByte > 0xBF)
	{
		DisasmResult->OperandNum = 0;
		switch (ModRmByte)
		{
		case 0xc0:case 0xc1:case 0xc2:case 0xc3:case 0xc4:case 0xc5:case 0xc6:case 0xc7:
		case 0xc8:case 0xc9:case 0xca:case 0xcb:case 0xcc:case 0xcd:case 0xce:case 0xcf:
		{
			strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
			strcpy_s(DisasmResult->Operand[0], "st");
			char tmp[8] = { 0 };
			sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
			strcpy_s(DisasmResult->Operand[1], tmp);
			DisasmResult->OperandNum = 2;
			break;
		}
		case 0xd0:
			strcpy_s(DisasmResult->Opcode, "fnop");
			break;
		case 0xe0:
			strcpy_s(DisasmResult->Opcode, "fchs");
			break;
		case 0xe1:
			strcpy_s(DisasmResult->Opcode, "fabs");
			break;
		case 0xe4:
			strcpy_s(DisasmResult->Opcode, "ftst");
			break;
		case 0xe5:
			strcpy_s(DisasmResult->Opcode, "fxam");
			break;
		case 0xe8:
			strcpy_s(DisasmResult->Opcode, "fld1");
			break;
		case 0xe9:
			strcpy_s(DisasmResult->Opcode, "fldl2t");
			break;
		case 0xea:
			strcpy_s(DisasmResult->Opcode, "fldl2e");
			break;
		case 0xeb:
			strcpy_s(DisasmResult->Opcode, "fldpi");
			break;
		case 0xec:
			strcpy_s(DisasmResult->Opcode, "fldlg2");
			break;
		case 0xed:
			strcpy_s(DisasmResult->Opcode, "fldln2");
			break;
		case 0xee:
			strcpy_s(DisasmResult->Opcode, "fldz");
			break;
		case 0xf0:
			strcpy_s(DisasmResult->Opcode, "F2XM1");
			break;
		case 0xf1:
			strcpy_s(DisasmResult->Opcode, "FYL2X");
			break;
		case 0xf2:
			strcpy_s(DisasmResult->Opcode, "FPTAN");
			break;
		case 0xf3:
			strcpy_s(DisasmResult->Opcode, "FPATAN");
			break;
		case 0xf4:
			strcpy_s(DisasmResult->Opcode, "FXTRACT");
			break;
		case 0xf5:
			strcpy_s(DisasmResult->Opcode, "FPREM1");
			break;
		case 0xf6:
			strcpy_s(DisasmResult->Opcode, "FDECSTP");
			break;
		case 0xf7:
			strcpy_s(DisasmResult->Opcode, "FINCSTP");
			break;
		case 0xf8:
			strcpy_s(DisasmResult->Opcode, "FPREM");
			break;
		case 0xf9:
			strcpy_s(DisasmResult->Opcode, "FYL2XP1");
			break;
		case 0xfa:
			strcpy_s(DisasmResult->Opcode, "FSQRT");
			break;
		case 0xfb:
			strcpy_s(DisasmResult->Opcode, "FSINCOS");
			break;
		case 0xfc:
			strcpy_s(DisasmResult->Opcode, "FRNDINT");
			break;
		case 0xfd:
			strcpy_s(DisasmResult->Opcode, "FSCALE");
			break;
		case 0xfe:
			strcpy_s(DisasmResult->Opcode, "FSIN");
			break;
		case 0xff:
			strcpy_s(DisasmResult->Opcode, "FCOS");
			break;

		}
		DisasmPoint->CurMemAddr += 2;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xda(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		char OpCode[][10] = { "fcmovb" , "fcmovbe" , "fcmove" , "fcmovu" };
		if (ModRmByte == 0xE9)
		{
			strcpy_s(DisasmResult->Opcode, "fucompp");
			DisasmResult->OperandNum = 0;
		}
		else
		{
			strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
			strcpy_s(DisasmResult->Operand[0], "st");
			char tmp[8] = { 0 };
			sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
			strcpy_s(DisasmResult->Operand[1], tmp);
			DisasmResult->OperandNum = 2;

		}
		DisasmPoint->CurMemAddr += 2;
	}
	else
	{
		char OpCode[][8] = { "fiadd" , "fimul" , "ficom" , "ficomp" , "fisub" , "fisubr" , "fidiv" , "fidivr" };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xdb(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		char OpCode[][10] = { "fcmovnb" , "fcmovne" , "fcmovnbe" , "fcmovnu" , "" , "fucomi" , "fcomi" , "" , };
		if (ModRmByte == 0xE2)
		{
			strcpy_s(DisasmResult->Opcode, "fclex");
			DisasmResult->OperandNum = 0;
		}
		else if (ModRmByte == 0xE3)
		{
			strcpy_s(DisasmResult->Opcode, "finit");
			DisasmResult->OperandNum = 0;
		}
		else
		{
			strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
			strcpy_s(DisasmResult->Operand[0], "st");
			char tmp[8] = { 0 };
			sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
			strcpy_s(DisasmResult->Operand[1], tmp);
			DisasmResult->OperandNum = 2;

		}
		DisasmPoint->CurMemAddr += 2;
	}
	else
	{
		char OpCode[][8] = { "fild" , "fisttp" , "fist" , "fistp" , "" , "fld" , "" , "fstp" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xdc(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		char OpCode[][8] = { "fadd" , "fmul" , "" , "" , "fsubr" , "fsub" , "fdivr" , "fdiv" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
		strcpy_s(DisasmResult->Operand[1], "st");
		char tmp[8] = { 0 };
		sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
		strcpy_s(DisasmResult->Operand[0], tmp);
		DisasmPoint->CurMemAddr += 2;
		DisasmResult->OperandNum = 2;
	}
	else
	{
		char OpCode[][8] = { "fadd" , "fmul" , "fcom" , "fcomp" , "fsub" , "fsubr" , "fdiv" , "fdivr" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xdd(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		char OpCode[][8] = { "ffree" , "" , "fst" , "fstp" , "fucom" , "fucomp" , "" , "" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
		char tmp[8] = { 0 };
		sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
		strcpy_s(DisasmResult->Operand[0], tmp);
		if (ModRmByte & 0xE0)
		{
			strcpy_s(DisasmResult->Operand[1], "st");
			DisasmResult->OperandNum = 2;
		}
		else
		{
			DisasmResult->OperandNum = 1;
		}
		DisasmPoint->CurMemAddr += 2;
	}
	else
	{
		char OpCode[][8] = { "fld" , "fisttp" , "fst" , "fstp" , "frstor" , "" , "fsave" , "fstsw" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xde(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		if (ModRmByte == 0xD9)
		{
			strcpy_s(DisasmResult->Opcode, "fcompp");
			DisasmResult->OperandNum = 0;
		}
		else
		{
			char OpCode[][8] = { "faddp" , "fmulp" , "" , "" , "fsubrp" , "fsubp" , "fdivrp" , "fdivp" , };
			strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte - 0xC0) / 8]);
			strcpy_s(DisasmResult->Operand[0], "st");
			char tmp[8] = { 0 };
			sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
			strcpy_s(DisasmResult->Operand[1], tmp);
			DisasmPoint->CurMemAddr += 2;
			DisasmResult->OperandNum = 2;
		}
	}
	else
	{
		char OpCode[][8] = { "fiadd" , "fimul" , "ficom" , "ficomp" , "fisub" , "fisubr" , "fidiv" , "fidivr" , };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_ESC_0xdf(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)DisasmPoint->CurMemAddr;
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (ModRmByte > 0xBF)
	{
		if (ModRmByte == 0xE0)
		{

		}
		else if (ModRmByte & 0xF0)
		{
			if (ModRmByte & 0xE0)
				strcpy_s(DisasmResult->Opcode, "fucomip");
			else if (ModRmByte & 0xF0)
				strcpy_s(DisasmResult->Opcode, "fcomip");
			strcpy_s(DisasmResult->Operand[0], "st");
			char tmp[8] = { 0 };
			sprintf(tmp, "st(%d)", (ModRmByte - 0xC0) % 8);
			strcpy_s(DisasmResult->Operand[1], tmp);
			DisasmPoint->CurMemAddr += 2;
			DisasmResult->OperandNum = 2;
		}
	}
	else
	{
		char OpCode[][8] = { "fild" , "fisttp" , "fist" , "fistp" , "fbld" , "fbld" , "fbstp" , "fistp" };
		strcpy_s(DisasmResult->Opcode, OpCode[(ModRmByte & 0b111000) >> 3]);
		Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_two_opcode(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;

	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	//�ȿ������Ƿ�  ����ָ���ں��������޸����Ƿ�
	if (TwoByteCodeMap[code].OpStr)
		strcpy_s(DisasmResult->Opcode, TwoByteCodeMap[code].OpStr);
	DisasmResult->OperandNum = GET_OPERAND_NUM(TwoByteCodeMap[code].Operand);
	DisasmResult->CodeMap = (int*)TwoByteCodeMap;
	TwoByteCodeMap[code].DisasmFunc(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_Exception(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_0x98(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	switch (DisasmPoint->PlatForm)
	{
	case PLATFORM_16BIT: strcpy_s(DisasmResult->Opcode, "cbw"); break;
	case PLATFORM_32BIT: strcpy_s(DisasmResult->Opcode, "cwde"); break;
	case PLATFORM_64BIT: 
		if(DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "cdqe");
		else
			strcpy_s(DisasmResult->Opcode, "cwde");
		break;
	}
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_0x99(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	switch (DisasmPoint->PlatForm)
	{
	case PLATFORM_16BIT: strcpy_s(DisasmResult->Opcode, "cwd"); break;
	case PLATFORM_32BIT: strcpy_s(DisasmResult->Opcode, "cdq"); break;
	case PLATFORM_64BIT:
		if (DisasmResult->PrefixState&PREFIX_REX_W)
			strcpy_s(DisasmResult->Opcode, "cqo");
		else
			strcpy_s(DisasmResult->Opcode, "cdq");
		break;
	}
	DisasmPoint->CurMemAddr += 1;
	return true;
}

bool Disasm::Disasm_0x6c_0x6d(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (*(UCHAR*)(DisasmPoint->CurMemAddr) == 0x6c)
	{

	}
	else
	{
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			strcpy_s(DisasmResult->Opcode, "insw");
		else
			strcpy_s(DisasmResult->Opcode, "insd");
		DisasmPoint->CurMemAddr += 1;
	}
	return true;
}



bool Disasm::Disasm_TWO_grp_0x00(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	char Opcode[][8] = { "sldt","str","lldt","ltr","verr","verw","","" };
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_TWO_grp_0x01(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (((ModRmByte >> 6) & 3) == 3)
	{
		switch ((ModRmByte >> 3) & 7)
		{
		case 0:
		{
			DisasmPoint->CurMemAddr += 1;
			char Opcode[][10] = { "","vmcall","vmlaunch","vmresume","vmxoff","","","" };
			strcpy_s(DisasmResult->Opcode, Opcode[ModRmByte & 3]);
			return true;
		}
		case 1:
		{
			DisasmPoint->CurMemAddr += 1;
			char Opcode[][10] = { "monitor","mwait","clac","stac","","","","encls" };
			strcpy_s(DisasmResult->Opcode, Opcode[ModRmByte & 3]);
			return true;
		}
		case 2:
		{
			DisasmPoint->CurMemAddr += 1;
			char Opcode[][10] = { "xgetbv","xsetbv","","","vmfunc","xend","xtest","enclu" };
			strcpy_s(DisasmResult->Opcode, Opcode[ModRmByte & 3]);
			return true;
		}
		case 3:
			DisasmPoint->CurMemAddr += 1;
			return true;
		case 5:
			DisasmPoint->CurMemAddr += 1;
			return true;
		case 7:
		{
			DisasmPoint->CurMemAddr += 1;
			char Opcode[][10] = { "swapgs","rdtscp","","","","","","" };
			strcpy_s(DisasmResult->Opcode, Opcode[ModRmByte & 3]);
			return true;
		}
		}
	}
	char Opcode[][8] = { "sgdt","sidt","lgdt","lidt","smsw","","lmsw","invlpg" };
	//�޸����Ƿ�
	sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_TWO_grp_0xae(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	if (((ModRmByte >> 5) & 3) == 3)
	{
		if (DisasmResult->PrefixState&PREFIX_Repe_F3)
		{
			char Opcode[][10] = { "rdfsbase","rdgsbase","wrfsbase","wrgsbase","","","","" };
			TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__R, OT__y, 0, 0, 0, 0, 0, 0);
			//TODO ����
		}
		else
		{
			char Opcode[][10] = { "","","","","","lfence","mfence","sfence" };
			//�޸����Ƿ�
			sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
			DisasmPoint->CurMemAddr += 1;
		}
	}
	else
	{
		char Opcode[][10] = { "fxsave","fxstor","ldmxcsr","stmxcsr","xsave","xrstor","xsaveopt","clflush" };
		//�޸����Ƿ�
		sprintf(DisasmResult->Opcode, "%s", Opcode[(ModRmByte >> 3) & 7]);
		DisasmPoint->CurMemAddr += 1;
	}
	return true;
}

bool Disasm::Disasm_TWO_0xbx(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		switch (code)
		{
		case 0xb8:
			strcpy_s(DisasmResult->Opcode, "popcnt");
			break;
		case 0xbc:
			strcpy_s(DisasmResult->Opcode, "tzcnt");
			break;
		case 0xbd:
			strcpy_s(DisasmResult->Opcode, "lzcnt");
			break;
		}
	}
	else
	{
		switch (code)
		{
		case 0xbb:
			strcpy_s(DisasmResult->Opcode, "btc");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__v, AT__G, OT__v, 0, 0, 0, 0); //�޸Ĳ�����
			break;
		case 0xbc:
			strcpy_s(DisasmResult->Opcode, "bsf");
			break;
		case 0xbd:
			strcpy_s(DisasmResult->Opcode, "bsr");
			break;
		}

	}
	Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_TWO_0x6x_0xdx_0xex_0xfx(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	switch (code) //�������⴦��
	{
	case 0x6e:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vmovd");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__y, AT__E, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2) {}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3) {}
		else
		{
			strcpy_s(DisasmResult->Opcode, "movd");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__d, AT__E, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0x6f:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vmovdqa");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__M, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2) {}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
		{
			strcpy_s(DisasmResult->Opcode, "vmovdqu");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__M, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else
		{
			strcpy_s(DisasmResult->Opcode, "movq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__Q, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xD0:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vaddsubpd");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
		{
			strcpy_s(DisasmResult->Opcode, "vaddsubps");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xD6:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vmovq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__q, AT__V, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
		{
			strcpy_s(DisasmResult->Opcode, "movq2dq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__dq, AT__N, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
		{
			strcpy_s(DisasmResult->Opcode, "movdq2q");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__U, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xE6:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vcvttpd2dq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
		{
			strcpy_s(DisasmResult->Opcode, "vcvtdq2pd");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
		{
			strcpy_s(DisasmResult->Opcode, "vcvtpd2dq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xD7:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vpmovmskb");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__U, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2) {}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3) {}
		else
		{
			strcpy_s(DisasmResult->Opcode, "pmovmskb");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__N, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xE7:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vmovntdq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__x, AT__V, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2) {}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3) {}
		else
		{
			strcpy_s(DisasmResult->Opcode, "movntq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__q, AT__P, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xF0:
		if (DisasmResult->PrefixState&PREFIX_Repne_F2)
		{
			strcpy_s(DisasmResult->Opcode, "vlddqu");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__M, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xF7:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			strcpy_s(DisasmResult->Opcode, "vmaskmovdqu");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__dq, AT__U, OT__dq, 0, 0, 0, 0); //�޸Ĳ�����
		}
		else if (DisasmResult->PrefixState&PREFIX_Repne_F2) {}
		else if (DisasmResult->PrefixState&PREFIX_Repe_F3) {}
		else
		{
			strcpy_s(DisasmResult->Opcode, "maskmovq");
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__N, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
		break;
	case 0xFF:
		break;
	default:
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
		{
			if ((code & 0xF0) == 0x60)
			{
				char Opcode[][15] = { "vpunpcklbw","vpunpcklwd","vpunpckldq","vpacksswb","vpcmpgtb","vpcmpgtw","vpcmpgtd","vpackuswb","vpunpckhbw","vpunpckhwd","vpunpckhdq","vpackssdw","vpunpcklqdq","vpunpckhqdq","","" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);

			}
			else if ((code & 0xF0) == 0xd0)
			{
				char Opcode[][10] = { "","vpsrlw","vpsrld","vpsrlq","vpaddq","vpmullw","","","vpsubusb","vpsubusw","vpminub","vpand","vpaddusb","vpaddusw","vpmaxub","vpandn" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);

			}
			else if ((code & 0xF0) == 0xe0)
			{
				char Opcode[][10] = { "vpavgb","vpsraw","vpsrad","vpavgw","vpmulhuw","vpmulhw","","","vpsubsb","vpsubsw","vpminsw","vpor","vpaddsb","vpaddsw","vpmaxsw","vpxor" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);
			}
			else if ((code & 0xF0) == 0xF0)
			{
				char Opcode[][10] = { "","vpsllw","vpslld","vpsllq","vpmuludq","vpmaddwd","vpsadbw","","vpsubb","vpsubw","vpsubd","vpsubq","vpaddb","vpaddw","vpaddd","" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);
			}
			TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__H, OT__x, AT__W, OT__x, 0, 0); //�޸Ĳ�����
		}
		else //û��ǰ׺��״̬
		{
			if ((code & 0xF0) == 0x60)
			{
				char Opcode[][15] = { "punpcklbw","punpcklwd","punpckldq","packsswb","pcmpgtb","pcmpgtw","pcmpgtd","packuswb","punpckhbw","punpckhwd","punpckhdq","packssdw","","","","" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);

			}
			else if ((code & 0xF0) == 0xd0)
			{
				char Opcode[][10] = { "","psrlw","psrld","psrlq","paddq","pmullw","","","psubusb","psubusw","pminub","pand","paddusb","paddusw","pmaxub","pandn" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);

			}
			else if ((code & 0xF0) == 0xe0)
			{
				char Opcode[][10] = { "pavgb","psraw","psrad","pavgw","pmulhuw","pmulhw","","","psubsb","psubsw","pminsw","por","paddsb","paddsw","pmaxsw","pxor" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);
			}
			else if ((code & 0xF0) == 0xF0)
			{
				char Opcode[][10] = { "","psllw","pslld","psllq","pmuludq","pmaddwd","psadbw","","psubb","psubw","psubd","psubq","paddb","paddw","paddd","" };
				//�޸����Ƿ�
				sprintf(DisasmResult->Opcode, "%s", Opcode[code & 0xf]);
			}
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__Q, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
		}
	}
	//TODO �����Ľ�������
	return true;
}

bool Disasm::Disasm_TWO_three_opcode38(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;

	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	//�ȿ������Ƿ�  ����ָ���ں��������޸����Ƿ�
	if (ThreeByteCodeMap38[code].OpStr)
		strcpy_s(DisasmResult->Opcode, ThreeByteCodeMap38[code].OpStr);
	DisasmResult->OperandNum = GET_OPERAND_NUM(ThreeByteCodeMap38[code].Operand);
	DisasmResult->CodeMap = (int*)ThreeByteCodeMap38;
	ThreeByteCodeMap38[code].DisasmFunc(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_TWO_three_opcode3A(DISASM_RESULT * DisasmResult, DISASM_POINT* DisasmPoint, int * IsFinished)
{
	DisasmPoint->CurMemAddr += 1;

	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	//�ȿ������Ƿ�  ����ָ���ں��������޸����Ƿ�
	if (ThreeByteCodeMap3A[code].OpStr)
		strcpy_s(DisasmResult->Opcode, ThreeByteCodeMap3A[code].OpStr);
	DisasmResult->OperandNum = GET_OPERAND_NUM(ThreeByteCodeMap3A[code].Operand);
	DisasmResult->CodeMap = (int*)ThreeByteCodeMap3A;
	ThreeByteCodeMap3A[code].DisasmFunc(DisasmResult, DisasmPoint, IsFinished);
	return true;
}

bool Disasm::Disasm_TWO_0x10(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovupd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__pd, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__H, OT__x, AT__W, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vmovsd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__H, OT__x, AT__W, OT__sd, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovups");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x11(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovupd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__pd, AT__V, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__W, OT__ss, AT__H, OT__x, AT__V, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vmovsd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__W, OT__sd, AT__H, OT__x, AT__V, OT__sd, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovups");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__ps, AT__V, OT__ps, 0, 0, 0, 0 ); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x12(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovlpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__q, AT__H, OT__q, AT__M, OT__q, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovsldup");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vmovddup");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovlps"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__q, AT__H, OT__q, AT__M, OT__q, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x13(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovlps");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovlps");
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x14(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vunpcklpd");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vunpcklps");
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x15(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vunpckhpd");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vunpckhps");
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x16(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovhpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__dq, AT__H, OT__q, AT__M, OT__q, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovshdup");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__x, 0, 0, 0, 0); //�޸Ĳ�����

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovhps");  //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__dq, AT__H, OT__q, AT__M, OT__q, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x17(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovhpd");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovhps");
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_grp_16(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	DisasmPoint->CurMemAddr += 2; // �������ֽں�mod�ֽ�
	if (((ModRmByte >> 5) & 3) == 3)
	{
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
	}
	else
	{
		switch ((ModRmByte >> 3) & 7)
		{
		case 0b000:
			sprintf(DisasmResult->Opcode, "PREFETCHNTA");
			break;
		case 0b001:
			sprintf(DisasmResult->Opcode, "PREFETCHT0");
			break;
		case 0b010:
			sprintf(DisasmResult->Opcode, "PREFETCHT1");
			break;
		case 0b011:
			sprintf(DisasmResult->Opcode, "PREFETCHT2");
			break;
		default:
			strcpy_s(DisasmResult->Opcode, "reserve opcode");
		}
	}
	return true;
}

bool Disasm::Disasm_TWO_0x1a(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	DisasmPoint->CurMemAddr += 1;
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "bndmov");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "bndcl");

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "bndcu");
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "bndldx");
	}
	return true;
}

bool Disasm::Disasm_TWO_0x1b(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	DisasmPoint->CurMemAddr += 1;
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "bndmov");
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "bndmk");

	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "bndcn");
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "bndstx");
	}
	return true;
}

bool Disasm::Disasm_TWO_0x28(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovapd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__pd, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2|| DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovaps");  //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x29(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovapd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__pd, AT__V, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovaps");  
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__ps, AT__V, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x2a(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "cvtpi2pd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__pd, AT__Q, OT__pi, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcvtsi2ss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__E, OT__y, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "cvtpi2pd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__sd, AT__H, OT__sd, AT__E, OT__y, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "cvtpi2ps");  
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__Q, OT__pi, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x2b(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovntpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__pd, AT__V, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovntps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__ps, AT__V, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x2c(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "cvttpd2pi");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__pi, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcvttss2si");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__W, OT__ss, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vcvttsd2si");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__W, OT__sd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "cvttps2pi");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__pi, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x2d(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "cvttpd2pi");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__Q, OT__pi, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcvttss2si");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__W, OT__ss, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vcvttsd2si");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__W, OT__sd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "cvtps2pi");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__pi, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x2e_0x2f(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		if(code==0x2e)
			strcpy_s(DisasmResult->Opcode, "vucomisd");
		else
			strcpy_s(DisasmResult->Opcode, "vcomisd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__sd, AT__W, OT__sd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		if (code == 0x2e)
			strcpy_s(DisasmResult->Opcode, "vucomiss");
		else
			strcpy_s(DisasmResult->Opcode, "vcomiss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ss, AT__W, OT__ss, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x50(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovmskpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__U, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vmovmskps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__U, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x51(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vsqrtpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__pd, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vsqrtss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__W, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vsqrtsd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__sd, AT__H, OT__sd, AT__W, OT__sd, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vsqrtps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x52_0x53(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		if(code==0x51)
			strcpy_s(DisasmResult->Opcode, "vrsqrtss");
		else
			strcpy_s(DisasmResult->Opcode, "vrcpss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__W, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		if (code == 0x51)
			strcpy_s(DisasmResult->Opcode, "vrsqrtps");
		else
			strcpy_s(DisasmResult->Opcode, "vrcpps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x54_0x55_0x56_0x57(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		switch (code)
		{
		case 0x54:strcpy_s(DisasmResult->Opcode, "vandpd"); break;
		case 0x55:strcpy_s(DisasmResult->Opcode, "vandnpd"); break;
		case 0x56:strcpy_s(DisasmResult->Opcode, "vorpd"); break;
		case 0x57:strcpy_s(DisasmResult->Opcode, "vxorpd"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		switch (code)
		{
		case 0x54:strcpy_s(DisasmResult->Opcode, "vandps"); break;
		case 0x55:strcpy_s(DisasmResult->Opcode, "vandnps"); break;
		case 0x56:strcpy_s(DisasmResult->Opcode, "vorps"); break;
		case 0x57:strcpy_s(DisasmResult->Opcode, "vxorps"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x58_0x59_0x5c_0x5d_0x5e_0x5f(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		switch (code)
		{
		case 0x58:strcpy_s(DisasmResult->Opcode, "vaddpd"); break;
		case 0x59:strcpy_s(DisasmResult->Opcode, "vmulpd"); break;
		case 0x5c:strcpy_s(DisasmResult->Opcode, "vsubpd"); break;
		case 0x5d:strcpy_s(DisasmResult->Opcode, "vminpd"); break;
		case 0x5e:strcpy_s(DisasmResult->Opcode, "vdivpd"); break;
		case 0x5f:strcpy_s(DisasmResult->Opcode, "vmaxpd"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		switch (code)
		{
		case 0x58:strcpy_s(DisasmResult->Opcode, "vaddss"); break;
		case 0x59:strcpy_s(DisasmResult->Opcode, "vmulss"); break;
		case 0x5c:strcpy_s(DisasmResult->Opcode, "vsubss"); break;
		case 0x5d:strcpy_s(DisasmResult->Opcode, "vminss"); break;
		case 0x5e:strcpy_s(DisasmResult->Opcode, "vdivss"); break;
		case 0x5f:strcpy_s(DisasmResult->Opcode, "vmaxss"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__W, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		switch (code)
		{
		case 0x58:strcpy_s(DisasmResult->Opcode, "vaddsd"); break;
		case 0x59:strcpy_s(DisasmResult->Opcode, "vmulsd"); break;
		case 0x5c:strcpy_s(DisasmResult->Opcode, "vsubsd"); break;
		case 0x5d:strcpy_s(DisasmResult->Opcode, "vminsd"); break;
		case 0x5e:strcpy_s(DisasmResult->Opcode, "vdivsd"); break;
		case 0x5f:strcpy_s(DisasmResult->Opcode, "vmaxsd"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__sd, AT__H, OT__sd, AT__W, OT__sd, 0, 0); //�޸Ĳ�����
	}
	else
	{
		switch (code)
		{
		case 0x58:strcpy_s(DisasmResult->Opcode, "vaddps"); break;
		case 0x59:strcpy_s(DisasmResult->Opcode, "vmulps"); break;
		case 0x5c:strcpy_s(DisasmResult->Opcode, "vsubps"); break;
		case 0x5d:strcpy_s(DisasmResult->Opcode, "vminps"); break;
		case 0x5e:strcpy_s(DisasmResult->Opcode, "vdivps"); break;
		case 0x5f:strcpy_s(DisasmResult->Opcode, "vmaxps"); break;
		}
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x5a(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vcvtpd2ps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcvtss2sd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__W, OT__ss, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vcvtsd2ss");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ss, AT__H, OT__x, AT__W, OT__sd, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vcvtps2pd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__pd, AT__W, OT__pd, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x5b(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vcvtps2dq");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__dq, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcvttps2dq");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__dq, AT__W, OT__ps, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vcvtdq2ps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__ps, AT__W, OT__dq, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x70(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vpshufd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__W, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vpshufhw");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__W, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vpshuflw");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__W, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "pshufw");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__P, OT__q, AT__Q, OT__q, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_grp12_grp13_grp14(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	BOOL IsValidCode = false;
	if (((ModRmByte >> 5) & 3) == 3)
	{
		switch ((ModRmByte >> 3) & 7)
		{
		case 0b010:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "vpsrlw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "vpsrld"); break;
				case 0x73:strcpy_s(DisasmResult->Opcode, "vpsrlq"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__H, OT__x, AT__U, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
			}
			else
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "psrlw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "psrld"); break;
				case 0x73:strcpy_s(DisasmResult->Opcode, "psrlq"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__N, OT__q,  AT__I, OT__b,0,0, 0, 0); //�޸Ĳ�����
			}
			break;
		case 0b011:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66&&code==0x73)
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vpsrldq");
				TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__H, OT__x, AT__U, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
			}
			break;
		case 0b100:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "vpsrlw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "vpsrad"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__H, OT__x, AT__U, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
			}
			else
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "psraw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "psrad"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__N, OT__q, AT__I, OT__b, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		case 0b110:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "vpsllw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "vpslld"); break;
				case 0x73:strcpy_s(DisasmResult->Opcode, "vpsllq"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__H, OT__x, AT__U, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
			}
			else
			{
				IsValidCode = true;
				switch (code)
				{
				case 0x71:strcpy_s(DisasmResult->Opcode, "psllw"); break;
				case 0x72:strcpy_s(DisasmResult->Opcode, "pslld"); break;
				case 0x73:strcpy_s(DisasmResult->Opcode, "psllq"); break;
				}
				TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__N, OT__q, AT__I, OT__b, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		case 0b111:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66&&code == 0x73)
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vpslldq");
				TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__H, OT__x, AT__U, OT__x, AT__I, OT__b, 0, 0); //�޸Ĳ�����
			}
			break;
		}
	}
	if (IsValidCode == false)
	{
		DisasmPoint->CurMemAddr += 2;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x74_0x75_0x76(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vpcmpeqb");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__H, OT__x, AT__W, OT__x, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2|| DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "pcmpeqb");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__Q, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x77(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	return false; //TODO
}

bool Disasm::Disasm_TWO_0x7c_0x7d(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		if(code==0x7c)
			strcpy_s(DisasmResult->Opcode, "vhaddpd");
		else
			strcpy_s(DisasmResult->Opcode, "vhsubpd");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 )
	{
		if (code == 0x7c)
			strcpy_s(DisasmResult->Opcode, "vhaddps");
		else
			strcpy_s(DisasmResult->Opcode, "vhsubps");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, 0, 0); //�޸Ĳ�����
	}
	else
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}



bool Disasm::Disasm_TWO_0x7e(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovd"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__y, AT__V, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 )
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else if ( DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovq");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__q, AT__W, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "movd");//TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__y, AT__P, OT__d, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0x7f(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vmovdqa"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__x, AT__V, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vmovdqu");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__W, OT__x, AT__V, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "movq");//TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__Q, OT__q, AT__P, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0xc0_0xc1_0xc3(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66 
		|| DisasmResult->PrefixState&PREFIX_Repne_F2
		|| DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		if(code==0xc0)
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__b, AT__G, OT__b, 0, 0, 0, 0); //�޸Ĳ�����
		else if(code==0xc1)
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__E, OT__v, AT__G, OT__v, 0, 0, 0, 0); //�޸Ĳ�����
		else
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__y, AT__G, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
}

bool Disasm::Disasm_TWO_0xc2(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vcmppd"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, AT__I, OT__b); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "vcmpsd"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__sd, AT__H, OT__sd, AT__W, OT__sd, AT__I, OT__b); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "vcmpss"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__ss, AT__H, OT__ss, AT__W, OT__ss, AT__I, OT__b); //�޸Ĳ�����
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vcmpps");//TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, AT__I, OT__b); //�޸Ĳ�����
	}

	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);

}

bool Disasm::Disasm_TWO_0xc4(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vpinsrw"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, AT__I, OT__b); //�޸Ĳ�����
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2|| DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "pinsrw");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__P, OT__q, AT__R, OT__y, AT__I, OT__b, 0, 0); //�޸Ĳ�����
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
}

bool Disasm::Disasm_TWO_0xc5(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vpextrw"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__d, AT__N, OT__q, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2 || DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "pextrw");
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__d, AT__U, OT__dq, AT__I, OT__b, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_0xc6(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "vcmppd"); //TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__pd, AT__H, OT__pd, AT__W, OT__pd, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2|| DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 1;
		strcpy_s(DisasmResult->Opcode, "reserve opcode");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "vcmpps");//TODO
		TwoByteCodeMap[code].Operand = PACK_OPERAND(FOUR_OPERAND, AT__V, OT__ps, AT__H, OT__ps, AT__W, OT__ps, AT__I,OT__b); //�޸Ĳ�����
	}

	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_TWO_grp9(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1); 
	bool IsValidCode=false;
	if (((ModRmByte >> 5) & 3) == 3)
	{
		switch (((ModRmByte >> 3) & 7))
		{
		case 1:
			if (!(DisasmResult->PrefixState&PREFIX_Repne_F2 
				|| DisasmResult->PrefixState&PREFIX_Repe_F3 
				|| DisasmResult->PrefixState&PREFIX_Oprand_Size_66))
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "cmpxch8b");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__q, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		case 6:
			if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vmclear");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__q, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vmxon");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__q, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
			{
				//ʲô��Ҳ���� ռλ�õ�
			}
			else
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vmptrld");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__q, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		case 7:
			if (!(DisasmResult->PrefixState&PREFIX_Repne_F2
				|| DisasmResult->PrefixState&PREFIX_Repe_F3
				|| DisasmResult->PrefixState&PREFIX_Oprand_Size_66))
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "vmptrst");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__M, OT__q, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		}
	}
	else
	{
		switch ((ModRmByte >> 3) & 7)
		{
		case 6:
			if (!(DisasmResult->PrefixState&PREFIX_Repne_F2
			|| DisasmResult->PrefixState&PREFIX_Repe_F3
			|| DisasmResult->PrefixState&PREFIX_Oprand_Size_66))
		{
				IsValidCode = true;
			strcpy_s(DisasmResult->Opcode, "rdrand");//TODO
			TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__R, OT__v, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
		}
			break;
		case 7:
			if (DisasmResult->PrefixState&PREFIX_Repe_F3)
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "rdpid");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__R, OT__d, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			else if (!(DisasmResult->PrefixState&PREFIX_Repne_F2
					|| DisasmResult->PrefixState&PREFIX_Repe_F3
					|| DisasmResult->PrefixState&PREFIX_Oprand_Size_66))
			{
				IsValidCode = true;
				strcpy_s(DisasmResult->Opcode, "rdseed");//TODO
				TwoByteCodeMap[code].Operand = PACK_OPERAND(ONE_OPERAND, AT__R, OT__v, 0, 0, 0, 0, 0, 0); //�޸Ĳ�����
			}
			break;
		}
	}
	if (IsValidCode == false)
	{
		DisasmPoint->CurMemAddr += 2;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}


bool Disasm::Disasm_TWO_0xc8_0xcf(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (DisasmResult->PrefixState & PREFIX_REX_R)
	{
		UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
		switch (code)
		{
		case 0xc8:strcpy_s(DisasmResult->Operand[0], "r8"); break;
		case 0xc9:strcpy_s(DisasmResult->Operand[0], "r9"); break;
		case 0xca:strcpy_s(DisasmResult->Operand[0], "r10"); break;
		case 0xcb:strcpy_s(DisasmResult->Operand[0], "r11"); break;
		case 0xcc:strcpy_s(DisasmResult->Operand[0], "r12"); break;
		case 0xcd:strcpy_s(DisasmResult->Operand[0], "r13"); break;
		case 0xce:strcpy_s(DisasmResult->Operand[0], "r14"); break;
		case 0xcf:strcpy_s(DisasmResult->Operand[0], "r15"); break;
		}
		DisasmPoint->CurMemAddr += 1;
	}
	else if (DisasmResult->PrefixState & PREFIX_REX_W)
	{
		UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
		switch (code)
		{
		case 0xc8:strcpy_s(DisasmResult->Operand[0], "r8d"); break;
		case 0xc9:strcpy_s(DisasmResult->Operand[0], "r9d"); break;
		case 0xca:strcpy_s(DisasmResult->Operand[0], "r10d"); break;
		case 0xcb:strcpy_s(DisasmResult->Operand[0], "r11d"); break;
		case 0xcc:strcpy_s(DisasmResult->Operand[0], "r12d"); break;
		case 0xcd:strcpy_s(DisasmResult->Operand[0], "r13d"); break;
		case 0xce:strcpy_s(DisasmResult->Operand[0], "r14d"); break;
		case 0xcf:strcpy_s(DisasmResult->Operand[0], "r15d"); break;
		}
		DisasmPoint->CurMemAddr += 1;
	}
	else
	{
		return	Disasm_reg_or_imm(DisasmResult, DisasmPoint, IsFinished);
	}
	return true;
}

bool Disasm::Disasm_THREE38_0x0x(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState & PREFIX_Oprand_Size_66)
	{
		switch (code)
		{
		case 0x00:strcpy_s(DisasmResult->Opcode, "vpshufb");break;
		case 0x01:strcpy_s(DisasmResult->Opcode, "vphaddw");break;
		case 0x02:strcpy_s(DisasmResult->Opcode, "vphaddd");break;
		case 0x03:strcpy_s(DisasmResult->Opcode, "vphaddsw");break;
		case 0x04:strcpy_s(DisasmResult->Opcode, "vpmaddubsw");break;
		case 0x05:strcpy_s(DisasmResult->Opcode, "vphsubw");break;
		case 0x06:strcpy_s(DisasmResult->Opcode, "vphsubd");break;
		case 0x07:strcpy_s(DisasmResult->Opcode, "vphsubsw");break;
		case 0x08:strcpy_s(DisasmResult->Opcode, "vpsignb");break;
		case 0x09:strcpy_s(DisasmResult->Opcode, "vpsignw");break;
		case 0x0a:strcpy_s(DisasmResult->Opcode, "vpsignd");break;
		case 0x0b:strcpy_s(DisasmResult->Opcode, "vpmulhrsw");break;
		default:
			DisasmPoint->CurMemAddr += 3;
			strcpy_s(DisasmResult->Opcode, "reserve code");
			return true;
		}
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__V, OT__x, AT__H, OT__x, AT__W, OT__x, 0, 0); //�޸Ĳ�����
	}
	else
	{
		switch (code)
		{
		case 0x00:strcpy_s(DisasmResult->Opcode, "pshufb"); break;
		case 0x01:strcpy_s(DisasmResult->Opcode, "phaddw"); break;
		case 0x02:strcpy_s(DisasmResult->Opcode, "phaddd"); break;
		case 0x03:strcpy_s(DisasmResult->Opcode, "phaddsw"); break;
		case 0x04:strcpy_s(DisasmResult->Opcode, "pmaddubsw"); break;
		case 0x05:strcpy_s(DisasmResult->Opcode, "phsubw"); break;
		case 0x06:strcpy_s(DisasmResult->Opcode, "phsubd"); break;
		case 0x07:strcpy_s(DisasmResult->Opcode, "phsubsw"); break;
		case 0x08:strcpy_s(DisasmResult->Opcode, "psignb"); break;
		case 0x09:strcpy_s(DisasmResult->Opcode, "psignw"); break;
		case 0x0a:strcpy_s(DisasmResult->Opcode, "psignd"); break;
		case 0x0b:strcpy_s(DisasmResult->Opcode, "pmulhrsw"); break;
		default:
			DisasmPoint->CurMemAddr += 3;
			strcpy_s(DisasmResult->Opcode, "reserve code");
			return true;
		}
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__Q, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_gernel(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (!(DisasmResult->PrefixState & PREFIX_Oprand_Size_66))
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);;
}

bool Disasm::Disasm_THREE38_0x1c_0x1d_0x1e(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState & PREFIX_Oprand_Size_66)
	{
		switch (code)
		{
		case 0x1c:strcpy_s(DisasmResult->Opcode, "vpabsb"); break;
		case 0x1d:strcpy_s(DisasmResult->Opcode, "vpabsw"); break;
		case 0x1e:strcpy_s(DisasmResult->Opcode, "vpabsd"); break;
		}
		ThreeByteCodeMap3A[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__V, OT__x, AT__W, OT__x, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else
	{
		switch (code)
		{
		case 0x1c:strcpy_s(DisasmResult->Opcode, "pabsb"); break;
		case 0x1d:strcpy_s(DisasmResult->Opcode, "pabsw"); break;
		case 0x1e:strcpy_s(DisasmResult->Opcode, "pabsd"); break;
		}
		ThreeByteCodeMap3A[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__P, OT__q, AT__Q, OT__q, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);;
}

bool Disasm::Disasm_THREE38_0xf0(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "movbe");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__w, AT__M, OT__w, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "crc32");
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			TwoByteCodeMap[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__E, OT__b, 0, 0, 0, 0); //TODO ������ b Ӧ����v��
		else
			ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__E, OT__b, 0, 0, 0, 0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "movbe");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__M, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_0xf1(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "movbe");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__w, AT__G, OT__w, 0, 0, 0, 0); //�޸Ĳ�����
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "crc32");
		if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
			ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__E, OT__w, 0, 0, 0, 0);
		else
			ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__d, AT__E, OT__y, 0, 0, 0, 0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "movbe");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__M, OT__y, AT__G, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_0xf2(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Repne_F2
		|| DisasmResult->PrefixState&PREFIX_Repe_F3
		|| DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "andn");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__B, OT__y, AT__E, OT__y, 0, 0); //�޸Ĳ�����
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
}

bool Disasm::Disasm_THREE38_grp17(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	UCHAR ModRmByte = *(UCHAR*)(DisasmPoint->CurMemAddr + 1);
	bool IsValidCode = false;
	switch (((ModRmByte >> 3) & 7))
	{
	case 2:
		IsValidCode = true;
		strcpy_s(DisasmResult->Opcode, "blsrv");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__B, OT__y, AT__E, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		break;
	case 3:
		IsValidCode = true;
		strcpy_s(DisasmResult->Opcode, "blsmskv");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__B, OT__y, AT__E, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		break;
	case 4:
		IsValidCode = true;
		strcpy_s(DisasmResult->Opcode, "blsiv");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__B, OT__y, AT__E, OT__y, 0, 0, 0, 0); //�޸Ĳ�����
		break;
	}
	if (IsValidCode == false)
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_0xf5(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "pdep");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__B, OT__y, AT__E, OT__y, 0, 0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "pext");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__B, OT__y, AT__E, OT__y, 0, 0);
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "bzhi");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__E, OT__y, AT__B, OT__y, 0, 0);
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_0xf6(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "adcx");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__E, OT__y, 0, 0, 0, 0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "mulx");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__B, OT__y, AT__G, OT__y, AT__E, OT__y, 0, 0);
		//���⴦�� �ĸ�������
		bool status=Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
		strcpy_s(DisasmResult->Operand[3],DisasmResult->Operand[2]);
		if (DisasmPoint->PlatForm == PLATFORM_32BIT)
			strcpy_s(DisasmResult->Operand[2], "edx");
		else if (DisasmPoint->PlatForm == PLATFORM_64BIT)
			strcpy_s(DisasmResult->Operand[2], "rdx");
		else if (DisasmPoint->PlatForm == PLATFORM_16BIT)
			strcpy_s(DisasmResult->Operand[2], "dx");
		return status;
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "adox");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(TWO_OPERAND, AT__G, OT__y, AT__E, OT__y, 0, 0, 0, 0);
	}
	else
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE38_0xf7(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
	if (DisasmResult->PrefixState&PREFIX_Oprand_Size_66)
	{
		strcpy_s(DisasmResult->Opcode, "shlx");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__E, OT__y, AT__B, OT__y, 0, 0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
	{
		strcpy_s(DisasmResult->Opcode, "shrx");
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__E, OT__y, AT__B, OT__y,0,0);
	}
	else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
	{
		strcpy_s(DisasmResult->Opcode, "sarx");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__E, OT__y, AT__B, OT__y, 0, 0);
	}
	else
	{
		strcpy_s(DisasmResult->Opcode, "bextr");//TODO
		ThreeByteCodeMap38[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__G, OT__y, AT__E, OT__y, AT__B, OT__y, 0, 0);
	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
}

bool Disasm::Disasm_THREE3A_gernel(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (!(DisasmResult->PrefixState & PREFIX_Oprand_Size_66))
	{
		DisasmPoint->CurMemAddr += 3;
		strcpy_s(DisasmResult->Opcode, "reserve code");
		return true;

	}
	return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);;
}


bool Disasm::Disasm_THREE3A_0x0f(DISASM_RESULT * DisasmResult, DISASM_POINT * DisasmPoint, int * IsFinished)
{
	if (DisasmResult->PrefixState & PREFIX_Oprand_Size_66)
	{	
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	else if(!(DisasmResult->PrefixState &PREFIX_Repne_F2
		|| DisasmResult->PrefixState &PREFIX_Repe_F3))
	{
		UCHAR code = *(UCHAR*)(DisasmPoint->CurMemAddr);
		strcpy_s(DisasmResult->Opcode, "palignr");
		ThreeByteCodeMap3A[code].Operand = PACK_OPERAND(THREE_OPERAND, AT__P, OT__q, AT__Q, OT__q, AT__I, OT__b,0,0); //�޸Ĳ�����
		return Disasm_ModRM(DisasmResult, DisasmPoint, IsFinished);
	}
	DisasmPoint->CurMemAddr += 3;
	strcpy_s(DisasmResult->Opcode, "reserve code");
	return true;
}

