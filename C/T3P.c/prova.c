#include <Python.h>

static PyObject *
wrapper(PyObject *self, PyObject *args)
{
    return Py_BuildValue("i", 42);
}

static PyMethodDef Methods[] = {
    {"wrapper",  wrapper, METH_VARARGS, "Sniff packets."},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC
initc_extension(void) {
  (void) Py_InitModule("extension", Methods);
}


stringa=(char*)malloc(sizeof(char)*(bytes*2)+1);
for (i = ppd->tp_mac; i <(bytes+ppd->tp_mac); i++)
{
  sprintf(&stringa[2*(i-ppd->tp_mac)],"%02x", ((unsigned char*)ppd)[i]);

}
printf("\n");
