#pragma once
/*
定义PE文件格式结构，参考pecoff_81.pdf
*/
#include <Windows.h>

typedef struct pe_header
{
	BYTE PE[4];
	USHORT machine;
	USHORT NumberOfSections;
	UINT  TimeDateStamp;
	UINT PointerToSymbolTable;
	UINT NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
}PE_HEADER;

typedef struct optional_pe_header
{
	USHORT Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	UINT SizeOfCode;
	UINT SizeOfInitializedData;
	UINT SizeOfUninitializedData;
	UINT AddressOfEntryPoint;
	UINT BaseOfCode;
	UINT BaseOfData;   //64位下没有这个域
	UINT64 ImageBase;
	UINT SectionAlignment;
	UINT FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	UINT Win32VersionValue;
	UINT SizeOfImage;
	UINT SizeOfHeaders;
	UINT CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	UINT64 SizeOfStackReserve;
	UINT64 SizeOfStackCommit;
	UINT64 SizeOfHeapReserve;
	UINT64 SizeOfHeapCommit;
	UINT LoaderFlags;
	UINT NumberOfRvaAndSizes;
}OPTIONAL_PE_HEADER;

typedef struct data_directory
{
	UINT VirtualAddress;
	UINT Size;
}DATA_DIRECTORY;

typedef struct pe_section_header
{
	BYTE Name[8];
	UINT VirtualSize;
	UINT VirtualAddress;
	UINT SizeOfRawData;
	UINT PointerToRawData;
	UINT PointerToRelocations;
	UINT PointerToLinenumbers;
	USHORT NumberOfRelocations;
	USHORT NumberOfLinenumbers;
	UINT Characteristics;
}PE_SECTION_HEADER,*PPE_SECTION_HEADER;

typedef struct import_directory_table
{
	UINT ImportLookUpTableRVA;
	UINT TimeDateStamp;
	UINT ForwarderChain;
	UINT NameRVA;
	UINT ImportAdressTableRVA;
}IMPORT_DIRECTORT_TABLE;

typedef struct import_search_table_32
{

}IMPORT_SEARCH_TABLE_32;
typedef struct export_directory_table
{
	UINT ExportFlags;
	UINT DateTimeStamp;
	USHORT MajorVersion;
	USHORT MinorVersion;
	UINT NameRVA;
	UINT OrdinalBase;
	UINT AdressTableEntries;
	UINT NumbersOfNamePointers;
	UINT ExportAdressTableRVA;
	UINT NamePointerRVA;
	UINT OrdinalTableRVA;
}EXPORT_DIRECTORY_TABLE;

typedef  struct tls_table_32
{
	UINT RawDataStart;
	UINT RawDataEnd;
	UINT AddressOfIndex;
	UINT AddressOfCallback;
	UINT SizeOfZeroFill;
	UINT Characteristics;
}
TLS_TABLE_32;
typedef  struct tls_table_64
{
	UINT RawDataStart;
	UINT RawDataEnd;
	UINT AddressOfIndex;
	UINT AddressOfCallback;
	UINT SizeOfZeroFill;
	UINT Characteristics;
}
TLS_TABLE_64;
typedef struct point_arr
{
	UINT FileStart;
	PE_HEADER* PeHeader;
	OPTIONAL_PE_HEADER* OptionPeHeader;
	DATA_DIRECTORY* PeDataDir;
	PE_SECTION_HEADER* PeSectionHeader;
	IMPORT_DIRECTORT_TABLE* ImportDirectoryTable;
	EXPORT_DIRECTORY_TABLE* ExportDirectoryTable;
	union
	{
		TLS_TABLE_32* TlsTable32;
		TLS_TABLE_64* TlsTable64;
	};
}POINT_ARR;

//分别区分 64位和32位  PE和dll
enum DATA_DIRECTORY_NAME{
	DD_EXPORT_TABLE,
	DD_IMPORT_TABLE,
	DD_RESOURCCE_TABLE,
	DD_EXCEPTION_TABLE,
	DD_ATTR_CERT_TABLE,
	DD_RELOCATION_TABLE,
	DD_DEBUG_INFO_BASE_ADDR,
	DD_GLOBAL_POINTER,
	DD_LOCAL_THREAD_STORAGE,
	DD_LOAD_CONFIG_TABLE,
	DD_BIND_IMPORT_TABLE,
	DD_EXPORT_ADDR_TABLE,
	DD_DELAY_IMPORT_DESCRIPTOR,
	DD_CLR_RUNTIME,
	DD_MAX_DIRECTORY_NAME_VALUE
};

class CImageInfo
{
private:
	pe_header PeHeader;
	OPTIONAL_PE_HEADER OptionalPeHeader;
	DATA_DIRECTORY DataDirectory[DD_MAX_DIRECTORY_NAME_VALUE];
	PE_SECTION_HEADER* PeSectionHeader;
	PVOID MapFileAddr;
	HANDLE hFile;
	HANDLE hMap;
	
public :
	CImageInfo();
	~CImageInfo() ;
	bool Is32Image() const;
	DWORD GetNumberOfSections() const;
	DWORD GetSubSystem() const;
	DWORD GetOptionalHeaderSize() const;
	DWORD GetDateTimeStamp() const;
	UINT GetAddressOfEntryPoint() const;
	UINT64 GetImageBase() const;
	DWORD GetImageSize() const;
	DWORD GetNumOfRVA() const;
	DWORD GetVirtualAddress() const;
	DWORD GetBaseOfCode() const;
	DWORD GetBaseOfCodeInFile() const;
	DWORD GetSizeOfCode() const;
	DWORD GetBaseOfData() const;
	DWORD GetSizeOfHeaders() const;
	DWORD GetMemSizeOfCode() const;
	DWORD GetMemorySize() const;
	DWORD GetCheckSum() const;
	DWORD GetAlignmentOfBlock() const;
	DWORD GetAlignmentOfFile() const;
	DWORD GetMachine() const;
	PVOID GetMapFileAddr() const;
	DWORD GetCharacteritic() const;
	UINT64 VoaToFoa(DWORD Voa) const;
	DWORD GetImportTable(char** FuncName, char** DllName, int Flag) const;
	
	DATA_DIRECTORY*GetDataDirectory();

	DWORD GetNumOfSections() const;
	PE_SECTION_HEADER* GetSectionHeader() const;
	pe_header* GetPeHeader();
	bool ReadImageFromMem(LPVOID startAddr);
	bool ReadImageFromFile(LPCTSTR FileName);
	bool ReadImageFromHandle(HANDLE hFile);
	bool GetImageInfo(LPVOID startAddr);
	optional_pe_header* GetOptionalHeader();
};
