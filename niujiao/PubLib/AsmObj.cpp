/*
�� python ��Asm���ṹ�������Ŀ���ṹ��
*/
#include "stdafx.h"
#include "AsmObj.h"

PyObject * AsmObject_new(PyTypeObject * type, PyObject * args, PyObject * kwds)
{
	AsmObject *self;
	self = (AsmObject *)type->tp_alloc(type, 0);
	if (self != NULL) {
		const char* AsmStr = 0;
		UINT64 TmpPoint = 0;
		int TimeElapse = 0;
		SAsmResultSet* AsmResultSet = nullptr;
		if (args && ((PyTupleObject*)args)->ob_base.ob_size ==3)
		{
			PyArg_ParseTuple(args, "sli", &AsmStr, &TmpPoint,&TimeElapse);
			AsmResultSet = (SAsmResultSet*)TmpPoint;
			self->AsmStr = PyUnicode_FromString(AsmStr);
			if (AsmResultSet->m_SuccessRecord < 1)
			{
				self->Result= (PyObject *)&_PyNone_Type;
			}
			else
			{
				char tmpStr[64] = { 0 };
				int pos = 0;
				for (int i = 0; i < MAX_INSTRUCT_NUM; i++)
				{
					if ((AsmResultSet->m_AsmResult + i)->m_TotalLength > 0)
					{
						pos = i;
						break;
					}
				}
				for (int i = 0; i < (AsmResultSet->m_AsmResult+pos)->m_TotalLength; i++)
				{
					char ttt[8] = { 0 };
					sprintf(ttt, "%02X", (AsmResultSet->m_AsmResult + pos)->m_Result[i]);
					strcat(tmpStr, ttt);
				}
				self->Result = PyUnicode_FromString(tmpStr);
				self->TimeElapse = PyLong_FromLong(TimeElapse);
			}
			Py_DECREF(args);
		}	
	}
	return (PyObject *)self;
}

PyObject * AsmObject_subscript(AsmObject * mp, PyObject * key)
{
	char* ttt = (char*)key + sizeof(PyASCIIObject); //TODO �Ҳ��� key ��ʵ������   ����ʱ�������
	for (int i = 0; i < (sizeof(AsmObject_members) / sizeof(PyMemberDef) - 1); i++)
	{
		if (strcmp(ttt, AsmObject_members[i].name) == 0)
		{
			return (PyObject *)*(int*)((int)mp + AsmObject_members[i].offset);
		}
	}
	return _PyNone_Type.tp_new(NULL, Py_BuildValue("()"), NULL);
}
 void AsmObject_dealloc(PyObject *ptr)
{
	PyObject_Del(ptr);
}