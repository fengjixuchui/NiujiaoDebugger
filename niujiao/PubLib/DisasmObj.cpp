/*
�� python ��Asm���ṹ�������Ŀ���ṹ��
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
			char tmpOpStr[64] = { 0 };
			char tmpDisasmStr[128] = { 0 };

			if (DisasmResult->PreStr[0])
				strcat(tmpDisasmStr, DisasmResult->PreStr);

			if (DisasmResult->OperandNum == 0)
				sprintf(tmpOpStr, "%s", DisasmResult->Opcode);
			else if (DisasmResult->OperandNum == 1)
				sprintf(tmpOpStr, "%s %s", DisasmResult->Opcode, DisasmResult->Operand[0]);
			else if (DisasmResult->OperandNum == 2)
				sprintf(tmpOpStr, "%s %s,%s", DisasmResult->Opcode, DisasmResult->Operand[0], DisasmResult->Operand[1]);
			else if (DisasmResult->OperandNum == 3)
				sprintf(tmpOpStr, "%s %s,%s,%s", DisasmResult->Opcode, DisasmResult->Operand[0],
					DisasmResult->Operand[1], DisasmResult->Operand[2]);
			strcat(tmpDisasmStr, tmpOpStr);

			self->Result = PyUnicode_FromString(tmpDisasmStr);
			Py_DECREF(args);
		}	
	}
	return (PyObject *)self;
}

PyObject * DisasmObject_subscript(DisasmObject * mp, PyObject * key)
{
	char* ttt = (char*)key + sizeof(PyASCIIObject); //TODO �Ҳ��� key ��ʵ������   ����ʱ�������
	for (int i = 0; i < (sizeof(DisasmObject_members) / sizeof(PyMemberDef) - 1); i++)
	{
		if (strcmp(ttt, DisasmObject_members[i].name) == 0)
		{
			return (PyObject *)*(int*)((int)mp + DisasmObject_members[i].offset);
		}
	}
	return _PyNone_Type.tp_new(NULL, Py_BuildValue("()"), NULL);
}
 void DisasmObject_dealloc(PyObject *ptr)
{
	PyObject_Del(ptr);
}