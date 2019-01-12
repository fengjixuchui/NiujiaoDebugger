/*
绑定 python 中NiuJiao模块对象和项目
*/
#include "stdafx.h"
#include "NiujiaoMod.h"
#include "DbgEngine/ImageInfo.h"
#include "DbgEngine/asm.h"
#include "DbgEngine/Disasm.h"

static PyObject *niujiaoError;

static PyMethodDef niujiaoMethods[] = {
	{"readpe",  niujiao_readpe, METH_VARARGS,"read PE file format . input : file path"},
	{"asmfromstr",  niujiao_asmfromstr, METH_VARARGS,"asm from string . input : assembly string"},
	{"disasmfromstr",  niujiao_disasmfromstr, METH_VARARGS,"disasm from string . input : disassembly string"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef niujiaomodule = {
	PyModuleDef_HEAD_INIT,
	"niujiao",   /* name of module */
	NULL, /* module documentation, may be NULL */
	-1,       /* size of per-interpreter state of the module,
				 or -1 if the module keeps state in global variables. */
	niujiaoMethods
};

static PyObject *
niujiao_readpe(PyObject *self, PyObject *args)
{
	const char *FileName;
	if (!PyArg_ParseTuple(args, "s", &FileName))
		return NULL;
	TCHAR tFileName[1024] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, FileName, strlen(FileName), tFileName, 32);
	CImageInfo *ImageInfo =new  CImageInfo();
	if (ImageInfo->ReadImageFromFile(tFileName) == false)
		return (PyObject *)&_PyNone_Type;

	PEFormat* pf = (PEFormat *)PEFormatType.tp_new(&PEFormatType, 
													Py_BuildValue("(l)", (UINT64)ImageInfo) , 
													NULL);
	return (PyObject *)pf;
}

PyObject * niujiao_asmfromstr(PyObject * self, PyObject * args)
{
	const char *Str;
	if (!PyArg_ParseTuple(args, "s", &Str))
		return NULL;
	TCHAR tFileName[1024] = { 0 };

	MultiByteToWideChar(CP_ACP, 0, Str, strlen(Str), tFileName, 32);
	SAsmResultSet AsmResultSet = { 0 };
	CAsm aaa = CAsm();
	if (aaa.AsmFromStr(tFileName, &AsmResultSet) == 0)
	{
		return AsmObjectType.tp_new(&AsmObjectType, 
			Py_BuildValue("(s,l)",(int)Str,(UINT64)&AsmResultSet),
			NULL);
	}
	else
	{
		return (PyObject *)&_PyNone_Type;
	}
}

PyObject * niujiao_disasmfromstr(PyObject * self, PyObject * args)
{
	const char *str;
	int platForm = 0;
	if (!PyArg_ParseTuple(args, "si", &str,&platForm))
		return NULL;
	char MachineCode[32] = { 0 };
	for (int i = 0; i < strlen(str); i++)
	{
		int aa = 0;
		for (int j = 0; j < 2; j++)
		{
			switch (*(str + i + j))
			{
			case 'a':case 'A': aa = (aa << (j * 4)) + 0xa; break;
			case 'b':case 'B': aa = (aa << (j * 4)) + 0xb; break;
			case 'c':case 'C': aa = (aa << (j * 4)) + 0xc; break;
			case 'd':case 'D': aa = (aa << (j * 4)) + 0xd; break;
			case 'e':case 'E': aa = (aa << (j * 4)) + 0xe; break;
			case 'f':case 'F': aa = (aa << (j * 4)) + 0xf; break;
			default:
				aa = (aa << (j * 4)) + *(str + i + j)-'0'; break;
			}
		}
		MachineCode[i / 2] = aa;
		i++;
	}
	DISASM_RESULT DisasmResult;
	ZeroMemory(&DisasmResult, sizeof(DISASM_RESULT));
	Disasm Disasm;
	 // platForm==0 32位  platForm==1 64位
	if (Disasm.DisasmFromStr((char*)MachineCode, PLATFORM_32BIT+platForm, 3, &DisasmResult) == false)
	{
		return (PyObject *)&_PyNone_Type;
	}
	else
	{
		return DisasmObjectType.tp_new(&DisasmObjectType,Py_BuildValue("(s,l)", str,(UINT64)&DisasmResult),NULL);
	}
}

PyMODINIT_FUNC
PyInit_niujiao(void)
{
	PyObject *m;
	if (PyType_Ready(&PEFormatType) < 0)
		return NULL;
	m= PyModule_Create(&niujiaomodule);
	if (m == NULL)
		return NULL;
	Py_INCREF(&PEFormatType);
	PyModule_AddObject(m, "PEFormat", (PyObject *)&PEFormatType);
	return m;
}
