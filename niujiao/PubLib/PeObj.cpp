/*
绑定 python 中PE文件格式对象和项目的PE解析结构
*/
#include "stdafx.h"
#include "PeObj.h"
#define NJ_CHECK_PY_OBJECT_NEW(PyObject,Type,TypeObj) if((PyObject = PyObject_New(Type, TypeObj))==NULL)\
													  {\
															Py_DECREF(self);\
															return NULL;\
													  }
PyObject * PEHeader_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	
	PEHeader *self;
	self = (PEHeader *)type->tp_alloc(type, 0);
	if (self != NULL) {
		PE_HEADER* pe_header = nullptr;
		if (args && ((PyTupleObject*)args)->ob_base.ob_size == 1)
		{
			PyArg_ParseTuple(args, "i", &pe_header);
		}
		if(pe_header)
		{
			self->PESign = PyUnicode_FromString((char*)&(pe_header->PE));
			self->Machine = pe_header->machine;
			self->NumberOfSections = pe_header->NumberOfSections;
			self->TimeDateStamp = pe_header->TimeDateStamp;
			self->PointerToSymbolTable = pe_header->PointerToSymbolTable;
			self->NumberOfSymbols = pe_header->NumberOfSymbols;
			self->SizeOfOptionalHeader = pe_header->SizeOfOptionalHeader;
			self->Characteristics = pe_header->Characteristics;
			Py_DECREF(args);
		}
		else
		{
			self->PESign = PyUnicode_FromString("");
			self->Machine = 0;
			self->NumberOfSections = 0;
			self->TimeDateStamp = 0;
			self->PointerToSymbolTable = 0;
			self->NumberOfSymbols = 0;
			self->SizeOfOptionalHeader = 0;
			self->Characteristics = 0;
		}
	}
	return (PyObject *)self;
}

Py_ssize_t PEHeader_length(PEHeader * mp)
{
	return sizeof(PEHeader_members)/sizeof(PyMemberDef)-1;
}

PyObject * PEHeader_subscript(PEHeader * mp, PyObject * key)
{
	char* ttt = (char*)key + sizeof(PyASCIIObject); //TODO 找不到 key 的实际类型   先暂时这样解决
	for (int i = 0; i < (sizeof(PEHeader_members) / sizeof(PyMemberDef) - 1); i++)
	{
		if (strcmp(ttt, PEHeader_members[i].name) == 0)
		{
			switch (PEHeader_members[i].type)
			{
			case T_OBJECT_EX: return (PyObject *)*(int*)((int)mp + PEHeader_members[i].offset);
			case T_USHORT: return PyLong_FromLong(*(USHORT*)((int)mp + PEHeader_members[i].offset));
			case T_UINT: return PyLong_FromLong(*(UINT*)((int)mp + PEHeader_members[i].offset));
			}
		}
	}
	return (PyObject *)&_PyNone_Type;
}

PyObject * PEOptionalHeader_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	PEOptionalHeader *self;
	self = (PEOptionalHeader *)type->tp_alloc(type, 0);
	if (self != NULL) {
		optional_pe_header * pe_optional_header = nullptr;
		int Is32Image = 0;
		if (args && ((PyTupleObject*)args)->ob_base.ob_size == 1)
		{
			PyArg_ParseTuple(args, "i", &pe_optional_header);
		}
		if (pe_optional_header)
		{
			memcpy(&(self->Magic), pe_optional_header, sizeof(OPTIONAL_PE_HEADER));
			Py_DECREF(args);
		}
		else
		{
			ZeroMemory(&(self->Magic), sizeof(OPTIONAL_PE_HEADER));
		}
	}
	return (PyObject *)self;
}

PyObject * PEOptionalHeader_subscript(PEOptionalHeader * mp, PyObject * key)
{
	char* ttt = (char*)key + sizeof(PyASCIIObject); //TODO 找不到 key 的实际类型   先暂时这样解决
	for (int i = 0; i < (sizeof(PEOptionalHeader_members) / sizeof(PyMemberDef) - 1); i++)
	{
		if (strcmp(ttt, PEOptionalHeader_members[i].name) == 0)
		{
			switch (PEOptionalHeader_members[i].type)
			{
			case T_USHORT: return PyLong_FromLong(*(USHORT*)((UINT64)mp + PEOptionalHeader_members[i].offset));
			case T_UINT: return PyLong_FromLong(*(UINT*)((UINT64)mp + PEOptionalHeader_members[i].offset));
			case T_BYTE: return PyLong_FromLong(*(BYTE*)((UINT64)mp + PEOptionalHeader_members[i].offset));
			case T_ULONG: return PyLong_FromLong(*(ULONG*)((UINT64)mp + PEOptionalHeader_members[i].offset));
			}
		}
	}
	return (PyObject *)&_PyNone_Type;
}

PyObject * PEFormat_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PEFormat *self;
	self = (PEFormat *)type->tp_alloc(type, 0);
	if (self != NULL) {
		UINT64 ImageInfo = 0;
		UINT64 PeHeader = 0;
		UINT64 PeOptionalHeader = 0;
		int Is32Image = 1;
		if (args&&((PyTupleObject*)args)->ob_base.ob_size>0)  //允许无参构造
		{
			PyArg_ParseTuple(args, "l", &ImageInfo);
			PeHeader = (UINT64)((CImageInfo*)ImageInfo)->GetPeHeader();
			PeOptionalHeader = (UINT64)((CImageInfo*)ImageInfo)->GetOptionalHeader();
		}
		self->PeHeader = (PEHeader *)PEHeaderType.tp_new(&PEHeaderType, Py_BuildValue("(l)", PeHeader), NULL);
		if (self->PeHeader == NULL)
		{
			Py_DECREF(self);
			return NULL;
		}
		self->PeOptionalHeader = (PEOptionalHeader *)PEOptionalHeaderType.tp_new(&PEOptionalHeaderType, Py_BuildValue("(l)", PeOptionalHeader), NULL);
		if (self->PeHeader == NULL)
		{
			Py_DECREF(self);
			return NULL;
		}
		NJ_CHECK_PY_OBJECT_NEW(self->PeDataDir, PEDataDir, &PEDataDirType)
		NJ_CHECK_PY_OBJECT_NEW(self->PeSectionHeader, PESectionHeader, &PESectionHeaderType)
		NJ_CHECK_PY_OBJECT_NEW(self->PeImportTable, PEImportTable, &PEImportTableType)
		NJ_CHECK_PY_OBJECT_NEW(self->PeExportTable, PEExportTable, &PEExportTableType)
	}		
	if (args)
		Py_DECREF(args);
	return (PyObject *)self;
}