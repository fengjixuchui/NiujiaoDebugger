#pragma once
/*
���� python �µ� NiuJiao ģ�����ش�����
*/
#include "PeObj.h"
#include "AsmObj.h"
#include "DisasmObj.h"

static PyObject * niujiao_readpe(PyObject * self, PyObject * args);
static PyObject * niujiao_asmfromstr(PyObject * self, PyObject * args);
static PyObject * niujiao_disasmfromstr(PyObject * self, PyObject * args);

PyMODINIT_FUNC PyInit_niujiao(void);
