/* See https://www.python-ldap.org/ for details. */

#include "pythonldap.h"

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

static struct PyModuleDef ldap_moduledef = {
    PyModuleDef_HEAD_INIT,
    "_ldap",        /* m_name */
    "",             /* m_doc */
    -1,             /* m_size */
    methods,        /* m_methods */
};

int
LDAPinit_types(PyObject *d)
{
    /* PyStructSequence types */
    static struct sequence_types {
        PyStructSequence_Desc *desc;
        PyTypeObject *where;
    } sequence_types[] = {
        {
            .desc = &result_tuple_desc,
            .where = &result_tuple_type,
        },
        {
            .desc = NULL,
	    .where = NULL,
        }
    };
    static struct sequence_types *type;

    for (type = sequence_types; type->desc; type++) {
        /* We'd like to use PyStructSequence_NewType from Stable ABI but can't
         * until Python 3.8 because of https://bugs.python.org/issue34784 */
        if (PyStructSequence_InitType2(type->where, type->desc))
            return -1;
        if (PyDict_SetItemString(d, type->desc->name, (PyObject *)type->where))
            return -1;
    }

    return 0;
}

/* module initialisation */
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

PyMODINIT_FUNC
PyInit__ldap(void)
{
    PyObject *m, *d;

    /* Create the module and add the functions */
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

    if (LDAPinit_types(d) < 0) {
        return NULL;
    }

    /* Check for errors */
    if (PyErr_Occurred())
        Py_FatalError("can't initialize module _ldap");

    return m;
}
