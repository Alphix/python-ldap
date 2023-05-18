/* See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "constants.h"
#include "functions.h"
#include "ldapcontrol.h"

#include "LDAPObject.h"

static const char version_str[] = Py_STRINGIFY(LDAPMODULE_VERSION);
static const char author_str[] = Py_STRINGIFY(LDAPMODULE_AUTHOR);
static const char license_str[] = Py_STRINGIFY(LDAPMODULE_LICENSE);

static void
init_pkginfo(PyObject *m)
{
    PyModule_AddStringConstant(m, "__version__", version_str);
    PyModule_AddStringConstant(m, "__author__", author_str);
    PyModule_AddStringConstant(m, "__license__", license_str);
}

/* dummy module methods */
static PyMethodDef methods[] = {
    {NULL, NULL}
};

#if PY_MAJOR_VERSION == 3 && PY_MINOR_VERSION < 9
static int
PyModule_AddType(PyObject *module, PyTypeObject *type)
{
    const char *name;

    if (PyType_Ready(type) < 0) {
        return -1;
    }

    name = _PyType_Name(type);
    assert(name != NULL);

    Py_INCREF(type);
    if (PyModule_AddObject(module, name, (PyObject *)type) < 0) {
        Py_DECREF(type);
        return -1;
    }

    return 0;
}
#endif

/* Common initialization code */
PyMODINIT_FUNC
PyInit__ldap(void)
{
    PyObject *m, *d;

    /* Create the module and add the functions */
    static struct PyModuleDef ldap_moduledef = {
        PyModuleDef_HEAD_INIT,
        "_ldap",        /* m_name */
        "",             /* m_doc */
        -1,             /* m_size */
        methods,        /* m_methods */
    };
    m = PyModule_Create(&ldap_moduledef);

    /* Initialize LDAP class */
    if (PyModule_AddType(m, &LDAP_Type) < 0) {
        Py_DECREF(m);
        return NULL;
    }

    /* Add some symbolic constants to the module */
    d = PyModule_GetDict(m);

    init_pkginfo(m);

    if (LDAPinit_constants(m) == -1) {
        return NULL;
    }

    LDAPinit_functions(d);
    LDAPinit_control(d);

    /* Check for errors */
    if (PyErr_Occurred())
        Py_FatalError("can't initialize module _ldap");

    return m;
}
