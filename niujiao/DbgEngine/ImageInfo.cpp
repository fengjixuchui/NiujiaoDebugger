/*
ʵ��PE�ļ���ʽ�Ľ���
*/
#include "stdafx.h"
#include "ImageInfo.h"

CImageInfo::CImageInfo()
{
	PeSectionHeader = nullptr;
	MapFileAddr = nullptr;
	hFile = 0;
	hMap = 0;
}

CImageInfo::~CImageInfo()
{
	if(PeSectionHeader)
		delete[] PeSectionHeader;	
	if(MapFileAddr)
		UnmapViewOfFile(MapFileAddr);
	if(hMap)
		CloseHandle(hMap);
	if(hFile)
		CloseHandle(hFile);
}


bool CImageInfo::Is32Image() const
{
	return (PeHeader.Characteristics & 0x100) > 0;
}

DWORD CImageInfo::GetNumberOfSections() const
{
	return PeHeader.NumberOfSections;
}

DWORD CImageInfo::GetSubSystem() const
{
	return OptionalPeHeader.Subsystem;
}

DWORD CImageInfo::GetOptionalHeaderSize() const
{
	return PeHeader.SizeOfOptionalHeader;
}

DWORD CImageInfo::GetDateTimeStamp() const
{
	return PeHeader.TimeDateStamp;
}


UINT CImageInfo::GetAddressOfEntryPoint() const
{
	return OptionalPeHeader.AddressOfEntryPoint;
}

UINT64 CImageInfo::GetImageBase() const
{
	return OptionalPeHeader.ImageBase;
}

DWORD CImageInfo::GetImageSize() const
{
	return OptionalPeHeader.SizeOfImage;
}

DWORD CImageInfo::GetNumOfRVA() const
{
	return OptionalPeHeader.NumberOfRvaAndSizes;
}

DWORD CImageInfo::GetVirtualAddress() const
{	// ��ȡ��һ����ִ�жε�ָ��   ����һЩ���ѹ����PE�ļ����ܻ�ʧЧ
	for (int i = 0; i < PeHeader.NumberOfSections; i++)
	{
		if ((PeSectionHeader + i)->Characteristics == 0x60000020)
			return (PeSectionHeader + i)->VirtualAddress;
	}
	return 0;
}

DWORD CImageInfo::GetBaseOfCode() const
{
	return OptionalPeHeader.BaseOfCode;
}

DWORD CImageInfo::GetBaseOfCodeInFile() const
{
	// ��ȡ��һ����ִ�жε�ָ��   ����һЩ���ѹ����PE�ļ����ܻ�ʧЧ
	for (int i = 0; i < PeHeader.NumberOfSections; i++)
	{
		if ((PeSectionHeader + i)->Characteristics == 0x60000020)
			return (PeSectionHeader + i)->PointerToRawData;
	}
	return 0;
}

DWORD CImageInfo::GetSizeOfCode() const
{
	return OptionalPeHeader.SizeOfCode;
}

DWORD CImageInfo::GetBaseOfData() const
{
	return OptionalPeHeader.BaseOfData;
}

DWORD CImageInfo::GetSizeOfHeaders() const
{
	return OptionalPeHeader.SizeOfHeaders;
}

DWORD CImageInfo::GetMemSizeOfCode() const
{
	return PeSectionHeader->VirtualSize;
}

DWORD CImageInfo::GetMemorySize() const
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	DWORD MemorySize = 1;//PEͷ�ڶ���û������  ���ڴ���ռ��һ��ҳ��

	for (int i = 0; i < PeHeader.NumberOfSections; i++)
	{
		int Tmp = (PeSectionHeader + i)->VirtualSize%si.dwPageSize;
		MemorySize += int((PeSectionHeader + i)->VirtualSize / si.dwPageSize);
		if (Tmp)
			MemorySize++;
	}
	return MemorySize * si.dwPageSize;
}

DWORD CImageInfo::GetCheckSum() const
{
	return OptionalPeHeader.CheckSum;
}

DWORD CImageInfo::GetAlignmentOfBlock() const
{
	return OptionalPeHeader.SectionAlignment;
}

DWORD CImageInfo::GetAlignmentOfFile() const
{
	return OptionalPeHeader.FileAlignment;
}

DWORD CImageInfo::GetMachine() const
{
	return PeHeader.machine;
}

PVOID CImageInfo::GetMapFileAddr() const
{
	return MapFileAddr;
}

DWORD CImageInfo::GetCharacteritic() const
{
	return PeHeader.Characteristics;
}

UINT64 CImageInfo::VoaToFoa(DWORD Voa) const
{
	//�ж� Voa c�����ĸ�������
	int i = GetNumberOfSections() - 1;
	for (; i>-1  ; i--)
	{
		PE_SECTION_HEADER* TmpHeader = (PeSectionHeader + i);
		if (Voa > TmpHeader->VirtualAddress || Voa== TmpHeader->VirtualAddress)
		{
			//TODO �����ϣ�����ź͵�ַ�ǵ�����ϵ�ģ����Կ�������д���Ǵ治���ڶε���ź͵�ַ��ϵ��������أ�
			UINT64 aa= (Voa - TmpHeader->VirtualAddress) + TmpHeader->PointerToRawData;
			return aa;
		}
	}
	return 0;
}

DWORD CImageInfo::GetImportTable(char** FuncName,char** DllName,int Flag) const
//0 ��ͷ��ʼ���� 1 ������һ�α���
{
	static int Num = 0;
	if (Flag == 0) Num = 0;
	UINT64 ImpTblFileOffset = VoaToFoa(DataDirectory[1].VirtualAddress);
	if (ImpTblFileOffset)
	{
		IMPORT_DIRECTORT_TABLE* TblAddr = (IMPORT_DIRECTORT_TABLE*)((UINT64)MapFileAddr + ImpTblFileOffset)+Num;

		if (TblAddr->ForwarderChain == 0
			&& TblAddr->ImportAdressTableRVA == 0
			&& TblAddr->ImportLookUpTableRVA == 0
			&& TblAddr->NameRVA == 0
			&& TblAddr->TimeDateStamp == 0)
		{
			return false;
		}
		else
		{
			//������Ų���
			//ImportDirTable->ImportLookUpTableRVA = TblAddr->ImportLookUpTableRVA;
			//ImportDirTable->ForwarderChain = TblAddr->ForwarderChain;
			//�������Ʋ���
			UINT64 TmpNameAddr = VoaToFoa(TblAddr->ImportAdressTableRVA) + (UINT64)MapFileAddr;  //���������ܱ� pecoff 44
			int FuncNum = 0; //�����ܸ���
			size_t NameLen = 0; //�����ܳ���
			while (*((UINT64*)TmpNameAddr + FuncNum))
			{
				UINT64 TmpAddr= VoaToFoa(*(UINT64*)TmpNameAddr) + (UINT64)MapFileAddr;
				NameLen = NameLen + strlen((char*)TmpAddr + 2) + 1; //�������һ�����Ƶĳ���
				FuncNum++;
			}		

			
			*FuncName = (char*)malloc(NameLen);
			memcpy(*FuncName, (char*)TmpNameAddr, NameLen);
			
			//����dll����
			TmpNameAddr = VoaToFoa(TblAddr->NameRVA) + (UINT64)MapFileAddr;
			strcpy(*DllName, (char*)TmpNameAddr);
			Num++;
			return FuncNum;
		}
	}
	return 0;
}

DATA_DIRECTORY * CImageInfo::GetDataDirectory()
{
	return DataDirectory;
}

DWORD CImageInfo::GetNumOfSections() const
{
	return PeHeader.NumberOfSections;
}

PE_SECTION_HEADER * CImageInfo::GetSectionHeader() const
{
	return PeSectionHeader;
}

pe_header * CImageInfo::GetPeHeader()
{
	return &PeHeader;
}

bool CImageInfo::ReadImageFromMem(LPVOID startAddr)
{
	return GetImageInfo(startAddr);;
}

bool CImageInfo::ReadImageFromFile(LPCTSTR fileName)
{
	if (fileName == nullptr || lstrlen(fileName) == 0)
		return false;
	//�����ӳ�����ڴ�
	if (hFile != 0)
		CloseHandle(hFile); //��δ򿪵�ʱ�򣬹ر���һ�������ľ��
	hFile = CreateFile(fileName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, NULL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;
	return ReadImageFromHandle(hFile);
}

bool CImageInfo::ReadImageFromHandle(HANDLE tmpHandle)
{
	bool ret = true;
	if (tmpHandle == 0 || tmpHandle == INVALID_HANDLE_VALUE)
		return false;
	if (hMap != 0)
		CloseHandle(hMap); //��δ򿪵�ʱ�򣬹ر���һ��������ӳ���ַ
	hMap = CreateFileMapping(tmpHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);  
	if (hMap == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	if (MapFileAddr != nullptr)
		UnmapViewOfFile(MapFileAddr); //��δ򿪵�ʱ�򣬹ر���һ��������ӳ���ַ
	MapFileAddr = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	if (MapFileAddr == nullptr)
	{
		CloseHandle(hMap);

		hMap = nullptr;
		return false;
	}
	return GetImageInfo(MapFileAddr);
}

bool CImageInfo::GetImageInfo(LPVOID PeAddr)
{
	//��ȡpeheader
	UINT64 Tmp = (UINT64)PeAddr;
	
	DWORD32 PeHeaderPoint = *(DWORD32*)(Tmp + 0x3c);

	Tmp = Tmp + PeHeaderPoint;
	memcpy(&PeHeader, LPVOID(Tmp), sizeof(PeHeader));

	Tmp = Tmp + sizeof(PeHeader);
	ZeroMemory(&OptionalPeHeader, sizeof(OptionalPeHeader));

	OptionalPeHeader.Magic = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MajorLinkerVersion = *(BYTE*)Tmp; Tmp += sizeof(BYTE);
	OptionalPeHeader.MinorLinkerVersion = *(BYTE*)Tmp; Tmp += sizeof(BYTE);
	OptionalPeHeader.SizeOfCode = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.SizeOfInitializedData = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.SizeOfUninitializedData = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.AddressOfEntryPoint = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.BaseOfCode = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);

	if (PeHeader.Characteristics & 0x100)//32λ
	{
		OptionalPeHeader.BaseOfData = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
		OptionalPeHeader.ImageBase = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	}
	else
	{
		OptionalPeHeader.ImageBase = *(DWORD64*)Tmp; Tmp += sizeof(DWORD64);
	}
	OptionalPeHeader.SectionAlignment = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.FileAlignment = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.MajorOperatingSystemVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MinorOperatingSystemVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MajorImageVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MinorImageVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MajorSubsystemVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.MinorSubsystemVersion = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.Win32VersionValue = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.SizeOfImage = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.SizeOfHeaders = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.CheckSum = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.Subsystem = *(USHORT*)Tmp; Tmp += sizeof(USHORT);
	OptionalPeHeader.DllCharacteristics = *(USHORT*)Tmp; Tmp += sizeof(USHORT);

	if (PeHeader.Characteristics & 0x100)//32λ
	{
		OptionalPeHeader.SizeOfStackReserve = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
		OptionalPeHeader.SizeOfStackCommit = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
		OptionalPeHeader.SizeOfHeapReserve = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
		OptionalPeHeader.SizeOfHeapCommit = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	}
	else
	{
		OptionalPeHeader.SizeOfStackReserve = *(DWORD64*)Tmp; Tmp += sizeof(DWORD64);
		OptionalPeHeader.SizeOfStackCommit = *(DWORD64*)Tmp; Tmp += sizeof(DWORD64);
		OptionalPeHeader.SizeOfHeapReserve = *(DWORD64*)Tmp; Tmp += sizeof(DWORD64);
		OptionalPeHeader.SizeOfHeapCommit = *(DWORD64*)Tmp; Tmp += sizeof(DWORD64);
	}
	OptionalPeHeader.LoaderFlags = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);
	OptionalPeHeader.NumberOfRvaAndSizes = *(DWORD32*)Tmp; Tmp += sizeof(DWORD32);

	//����Ŀ¼
	memcpy(&DataDirectory, (LPVOID)Tmp, sizeof(DATA_DIRECTORY)*DD_MAX_DIRECTORY_NAME_VALUE);
	Tmp = Tmp + sizeof(DATA_DIRECTORY)*(DD_MAX_DIRECTORY_NAME_VALUE+1);
	Tmp= Tmp + sizeof(DWORD) * 2;

	//����
	//PeSectionHeader = (PE_SECTION_HEADER*)malloc(sizeof(PE_SECTION_HEADER)*PeHeader.NumberOfSections);
	PeSectionHeader = new PE_SECTION_HEADER[PeHeader.NumberOfSections];
	memcpy(PeSectionHeader, (LPVOID)Tmp, sizeof(PE_SECTION_HEADER)*PeHeader.NumberOfSections);

	return true;

}

optional_pe_header * CImageInfo::GetOptionalHeader()
{
	return &OptionalPeHeader;
}
