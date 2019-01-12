/*
绑定 python 中Asm汇编结构对象和项目汇编结构体
*/
#include "stdafx.h"
#include "DisasmObj.h"

PyObject * DisasmObject_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	DisasmObject *self;
	self = (DisasmObject *)type->tp_alloc(type, 0);
	if (self != NULL) {
		const char* str = nullptr;
		UINT64 TmpResult = 0;
		DISASM_RESULT* DisasmResult = nullptr;
		if (args && ((PyTupleObject*)args)->ob_base.ob_size ==2)
		{
			PyArg_ParseTuple(args, "sl", &str,&TmpResult);
			DisasmResult = (DISASM_RESULT*)TmpResult;
			char tmpOpStr[16] = { 0 };
			char tmpDisasmStr[128] = { 0 };

			if (DisasmResult->PrefixState&PREFIX_Lock_F0)
				strcat(tmpDisasmStr, "lock ");
			else if (DisasmResult->PrefixState&PREFIX_Repne_F2)
				strcat(tmpDisasmStr, "repne ");
			else if (DisasmResult->PrefixState&PREFIX_Repe_F3)
				strcat(tmpDisasmStr, "repe ");

			if (DisasmResult->OperandNum == 0)
				sprintf(tmpOpStr, "%s", DisasmResult->Opcode);
			else if (DisasmResult->OperandNum == 1)
				sprintf(tmpOpStr, "%s %s", DisasmResult->Opcode, DisasmResult->FirstOperand);
			else if (DisasmResult->OperandNum == 2)
				sprintf(tmpOpStr, "%s %s,%s", DisasmResult->Opcode, DisasmResult->FirstOperand, DisasmResult->SecondOperand);
			else if (DisasmResult->OperandNum == 3)
				sprintf(tmpOpStr, "%s %s,%s,%s", DisasmResult->Opcode, DisasmResult->FirstOperand,
					DisasmResult->SecondOperand, DisasmResult->ThirdOperand);
			strcat(tmpDisasmStr, tmpOpStr);

			self->Result = PyUnicode_FromString(tmpDisasmStr);
			Py_DECREF(args);
		}	
	}
	return (PyObject *)self;
}

PyObject * DisasmObject_subscript(DisasmObject * mp, PyObject * key)
{
	char* ttt = (char*)key + sizeof(PyASCIIObject); //TODO 找不到 key 的实际类型   先暂时这样解决
	for (int i = 0; i < (sizeof(DisasmObject_members) / sizeof(PyMemberDef) - 1); i++)
	{
		if (strcmp(ttt, DisasmObject_members[i].name) == 0)
		{
			return (PyObject *)*(int*)((int)mp + DisasmObject_members[i].offset);
		}
	}
	return (PyObject *)&_PyNone_Type;
}
 void DisasmObject_dealloc(PyObject *ptr)
{
	PyObject_Del(ptr);
}