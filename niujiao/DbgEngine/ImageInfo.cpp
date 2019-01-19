/*
实现PE文件格式的解析
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
{	// 获取第一个可执行段的指针   对于一些而已构造的PE文件可能会失效
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
	// 获取第一个可执行段的指针   对于一些而已构造的PE文件可能会失效
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
	DWORD MemorySize = 1;//PE头在段中没有体现  在内存中占用一个页面

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
	//判断 Voa c处于哪个段上面
	int i = GetNumberOfSections() - 1;
	for (; i>-1  ; i--)
	{
		PE_SECTION_HEADER* TmpHeader = (PeSectionHeader + i);
		if (Voa > TmpHeader->VirtualAddress || Voa== TmpHeader->VirtualAddress)
		{
			//TODO 理论上，段序号和地址是递增关系的，所以可以这样写。那存不存在段的序号和地址关系是乱序的呢？
			UINT64 aa= (Voa - TmpHeader->VirtualAddress) + TmpHeader->PointerToRawData;
			return aa;
		}
	}
	return 0;
}

DWORD CImageInfo::GetImportTable(char** FuncName,char** DllName,int Flag) const
//0 重头开始遍历 1 继续上一次遍历
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
			//根据序号查找
			//ImportDirTable->ImportLookUpTableRVA = TblAddr->ImportLookUpTableRVA;
			//ImportDirTable->ForwarderChain = TblAddr->ForwarderChain;
			//根据名称查找
			UINT64 TmpNameAddr = VoaToFoa(TblAddr->ImportAdressTableRVA) + (UINT64)MapFileAddr;  //函数名称总表 pecoff 44
			int FuncNum = 0; //函数总个数
			size_t NameLen = 0; //名称总长度
			while (*((UINT64*)TmpNameAddr + FuncNum))
			{
				UINT64 TmpAddr= VoaToFoa(*(UINT64*)TmpNameAddr) + (UINT64)MapFileAddr;
				NameLen = NameLen + strlen((char*)TmpAddr + 2) + 1; //补上最后一个名称的长度
				FuncNum++;
			}		

			
			*FuncName = (char*)malloc(NameLen);
			memcpy(*FuncName, (char*)TmpNameAddr, NameLen);
			
			//返回dll名称
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
	//将句柄映射至内存
	if (hFile != 0)
		CloseHandle(hFile); //多次打开的时候，关闭上一次遗留的句柄
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
		CloseHandle(hMap); //多次打开的时候，关闭上一次遗留的映射地址
	hMap = CreateFileMapping(tmpHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);  
	if (hMap == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	if (MapFileAddr != nullptr)
		UnmapViewOfFile(MapFileAddr); //多次打开的时候，关闭上一次遗留的映射地址
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
	//读取peheader
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

	if (PeHeader.Characteristics & 0x100)//32位
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

	if (PeHeader.Characteristics & 0x100)//32位
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

	//数据目录
	memcpy(&DataDirectory, (LPVOID)Tmp, sizeof(DATA_DIRECTORY)*DD_MAX_DIRECTORY_NAME_VALUE);
	Tmp = Tmp + sizeof(DATA_DIRECTORY)*(DD_MAX_DIRECTORY_NAME_VALUE+1);
	Tmp= Tmp + sizeof(DWORD) * 2;

	//区段
	//PeSectionHeader = (PE_SECTION_HEADER*)malloc(sizeof(PE_SECTION_HEADER)*PeHeader.NumberOfSections);
	PeSectionHeader = new PE_SECTION_HEADER[PeHeader.NumberOfSections];
	memcpy(PeSectionHeader, (LPVOID)Tmp, sizeof(PE_SECTION_HEADER)*PeHeader.NumberOfSections);

	return true;

}

optional_pe_header * CImageInfo::GetOptionalHeader()
{
	return &OptionalPeHeader;
}
