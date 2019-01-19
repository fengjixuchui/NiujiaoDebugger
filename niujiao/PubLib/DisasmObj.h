#pragma once
/*
定义 python 下的 Disasm 对象的相关结构
*/
#include "python.h"
#include "structmember.h"
#include "DbgEngine/Disasm.h"
typedef struct {
	PyObject_HEAD
		/* Type-specific fields go here. */
	PyObject* DisasmStr;   //原始字符串 
	PyObject* Result;   //汇编结果
} DisasmObject;
PyObject * DisasmObject_new(PyTypeObject * type, PyObject * args, PyObject * kwds);

PyObject * DisasmObject_subscript(DisasmObject *mp, PyObject *key);
void DisasmObject_dealloc(PyObject * ptr);
static PyMappingMethods DisasmObject_as_mapping = {
	NULL, /*mp_length*/
	(binaryfunc)DisasmObject_subscript, /*mp_subscript*/
	NULL
	//(objobjargproc)PEHeader_ass_sub, /*mp_ass_subscript*/
};
static PyMemberDef DisasmObject_members[] = {
	{"DisasmStr", T_OBJECT_EX, offsetof(DisasmObject, DisasmStr), 0,"original disasm string"},
	{"Result", T_OBJECT_EX, offsetof(DisasmObject, Result), 0,"disassembly result"},
	{NULL}  /* Sentinel */
};

static PyTypeObject DisasmObjectType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"DisasmObject",
	sizeof(DisasmObject),
	0,
	DisasmObject_dealloc,                                  /* tp_dealloc */
	0,                                  /* tp_print */
	0,                                  /* tp_getattr */
	0,                                  /* tp_setattr */
	0,                                  /* tp_reserved */
	0,                                  /* tp_repr */
	0,                                  /* tp_as_number */
	0,                                  /* tp_as_sequence */
	&DisasmObject_as_mapping,               /* tp_as_mapping */
	0,                                  /* tp_hash */
	0,                                  /* tp_call */
	0,                                  /* tp_str */
	PyObject_GenericGetAttr,            /* tp_getattro */
	0,                                  /* tp_setattro */
	0,                                  /* tp_as_buffer */
	Py_TPFLAGS_DEFAULT ,                /* tp_flags */
	"DisasmObject",                        /* tp_doc */
	0,                                  /* tp_traverse */
	0,                                  /* tp_clear */
	0,                                  /* tp_richcompare */
	0,                                  /* tp_weaklistoffset */
	0,                                  /* tp_iter */
	0,                                  /* tp_iternext */
	0,                                  /* tp_methods */
	DisasmObject_members,                   /* tp_members */
	0,                                  /* tp_getset */
	0,                                  /* tp_base */
	0,                                  /* tp_dict */
	0,                                  /* tp_descr_get */
	0,                                  /* tp_descr_set */
	0,                                  /* tp_dictoffset */
	(initproc)0,                        /* tp_init */
	PyType_GenericAlloc,                /* tp_alloc */
	DisasmObject_new,                       /* tp_new */
	PyObject_Del,                       /* tp_free */
};
