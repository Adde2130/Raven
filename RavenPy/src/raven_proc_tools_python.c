#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "raven.h"

static PyObject* raven_inject_dll(PyObject *self, PyObject *args) {
    const char* dllname;
    int pid;
    if(!PyArg_ParseTuple(args, "si", &dllname, &pid)){
        return NULL;
    }

    bool result = inject_dll(dllname, pid);

    return result ? Py_True : Py_False;
}

static PyObject* raven_get_pid(PyObject *self, PyObject *args) {
    const char* target;
    if(!PyArg_ParseTuple(args, "s", &target)){
        return NULL;
    }

    DWORD result = get_process_id(target);

    return PyLong_FromLong(result);
}

static PyMethodDef RavenMethods[] = {
    {"raven_inject_dll",  raven_inject_dll, METH_VARARGS, "Inject DLL into a process"},
    {"raven_get_pid",     raven_get_pid,    METH_VARARGS, "Get a process ID using its name"},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};

static struct PyModuleDef RavenModule = {
    PyModuleDef_HEAD_INIT,
    "RavenPy", 
    NULL, 
    -1, 

    RavenMethods
};

PyMODINIT_FUNC PyInit_RavenPy(void){
    return PyModule_Create(&RavenModule);
}