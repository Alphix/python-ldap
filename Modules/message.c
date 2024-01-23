/* See https://www.python-ldap.org/ for details. */

#include "common.h"
#include "LDAPObject.h"
#include "message.h"
#include "berval.h"
#include "ldapcontrol.h"
#include "constants.h"

static int
process_entry_attribute(LDAP *ld, LDAPMessage *entry, PyObject *attrdict,
                        const char *attr, BerElement *ber)
{
    PyObject *pyattr;
    struct berval **bvals;
    PyObject *valuelist;
    PyObject *valuestr = NULL;
    int result = -1;

    pyattr = PyUnicode_FromString(attr);
    if (!pyattr)
        goto out;

    bvals = ldap_get_values_len(ld, entry, attr);
    if (!bvals) {
        LDAPerror(ld);
        goto out_pyattr;
    }

    /* Find the list to append to */
    valuelist = PyDict_GetItem(attrdict, pyattr);
    if (valuelist) {
        /*
         * Multiple attribute entries with same name. This code path
         * is rarely used and cannot be exhausted with OpenLDAP
         * tests. 389-DS sometimes triggeres it, see
         * https://github.com/python-ldap/python-ldap/issues/218
         */
        Py_INCREF(valuelist);
    } else {
        valuelist = PyList_New(0);

        if (!valuelist)
            goto out_bvals;

        if (PyDict_SetItem(attrdict, pyattr, valuelist) < 0)
            goto out_valuelist;
    }

    for (int i = 0; bvals[i]; i++) {
        valuestr = LDAPberval_to_object(bvals[i]);
        if (!valuestr)
            goto out_valuelist;

        if (PyList_Append(valuelist, valuestr) < 0)
            goto out_valuestr;

        Py_DECREF(valuestr);
        valuestr = NULL;
    }

    result = 0;

out_valuestr:
    Py_XDECREF(valuestr);
out_valuelist:
    Py_DECREF(valuelist);
out_bvals:
    ldap_value_free_len(bvals);
out_pyattr:
    Py_XDECREF(pyattr);
out:
    return result;
}

static PyObject *
process_entry(LDAP *ld, LDAPMessage *entry, bool add_ctrls)
{
    char *dn;
    PyObject *pydn = NULL;
    PyObject *attrdict = NULL;
    BerElement *ber = NULL;
    LDAPControl **serverctrls = NULL;
    PyObject *pyctrls = NULL;
    PyObject *result = NULL;

    dn = ldap_get_dn(ld, entry);
    if (!dn) {
        LDAPerror(ld);
        goto out;
    }

    pydn = PyUnicode_FromString(dn);
    if (!pydn)
        goto out_dn;

    attrdict = PyDict_New();
    if (!attrdict)
        goto out_dn;

    /* FIXME: could use ldap_get_attribute_ber here? */
    for (const char *attr = ldap_first_attribute(ld, entry, &ber); attr;
         attr = ldap_next_attribute(ld, entry, ber)) {
        if (process_entry_attribute(ld, entry, attrdict, attr, ber) < 0)
		    goto out_ber;
    }

    if (add_ctrls) {
        if (ldap_get_entry_controls(ld, entry, &serverctrls) != LDAP_SUCCESS) {
            LDAPerror(ld);
            goto out_ber;
        }

        pyctrls = LDAPControls_to_List(serverctrls);
        if (!pyctrls) {
            int err = LDAP_NO_MEMORY;
            /* FIXME: missing LDAP_BEGIN/END_ALLOW_THREADS? */
            ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
            LDAPerror(ld);
            goto out_ctrls;
        }

        result = Py_BuildValue("(OOO)", pydn, attrdict, pyctrls);
    } else {
        result = Py_BuildValue("(OO)", pydn, attrdict);
    }

out_ctrls:
    Py_XDECREF(pyctrls);
    ldap_controls_free(serverctrls);
out_ber:
    ber_free(ber, 0);
    Py_XDECREF(attrdict);
out_dn:
    Py_XDECREF(pydn);
    ldap_memfree(dn);
out:
    return result;
}

static PyObject *
process_reference(LDAP *ld, LDAPMessage *entry, bool add_ctrls)
{
    PyObject *reflist;
    char **refs = NULL;
    LDAPControl **serverctrls = NULL;
    PyObject *refstr = NULL;
    PyObject *pyctrls = NULL;
    PyObject *result = NULL;

    reflist = PyList_New(0);
    if (!reflist)
        goto out;

    if (ldap_parse_reference(ld, entry, &refs, &serverctrls, 0) != LDAP_SUCCESS)
        goto out_reflist;

    for (int i = 0; refs && refs[i]; i++) {
        /* A referal is a distinguishedName => unicode */
        PyObject *refstr = PyUnicode_FromString(refs[i]);
        if (!refstr)
            goto out_refs;

        if (PyList_Append(reflist, refstr) < 0)
            goto out_refstr;

        Py_DECREF(refstr);
        refstr = NULL;
    }

    if (add_ctrls) {
        pyctrls = LDAPControls_to_List(serverctrls);
        if (!pyctrls) {
            int err = LDAP_NO_MEMORY;
            /* FIXME: missing LDAP_BEGIN/END_ALLOW_THREADS? */
            ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
            LDAPerror(ld);
            goto out_ctrls;
        }

        result = Py_BuildValue("(sOO)", NULL, reflist, pyctrls);
    } else {
        result = Py_BuildValue("(sO)", NULL, reflist);
    }

out_ctrls:
    Py_XDECREF(pyctrls);
out_refstr:
    Py_XDECREF(refstr);
out_refs:
    ldap_controls_free(serverctrls);
    ber_memvfree((void **)refs);
out_reflist:
    Py_DECREF(reflist);
out:
    return result;
}

static PyObject *
process_intermediate(LDAP *ld, LDAPMessage *entry)
{
    char *retoid = NULL;
    struct berval *retdata = NULL;
    LDAPControl **serverctrls = NULL;
    PyObject *pyoid;
    PyObject *value;
    PyObject *pyctrls;
    PyObject *result = NULL;

    if (ldap_parse_intermediate(ld, entry, &retoid, &retdata, &serverctrls, 0)
        != LDAP_SUCCESS) {
        LDAPerror(ld);
        goto out;
    }

    pyoid = PyUnicode_FromString(retoid);
    if (!pyoid)
        goto out_intermediate;

    value = LDAPberval_to_object(retdata);
    if (!value)
        goto out_pyoid;

    pyctrls = LDAPControls_to_List(serverctrls);
    if (!pyctrls) {
        int err = LDAP_NO_MEMORY;
        /* FIXME: missing LDAP_BEGIN/END_ALLOW_THREADS? */
        ldap_set_option(ld, LDAP_OPT_ERROR_NUMBER, &err);
        LDAPerror(ld);
        goto out_value;
    }

    result = Py_BuildValue("(OOO)", pyoid, value, pyctrls);

    Py_DECREF(pyctrls);
out_value:
    Py_DECREF(value);
out_pyoid:
    Py_DECREF(pyoid);
out_intermediate:
    ldap_memfree(retoid);
    ber_bvfree(retdata);
    ldap_controls_free(serverctrls);
out:
    return result;
}

static PyObject *
process_result(LDAPObject *lo, LDAPMessage *msg, int res_type)
{
    int res_msgid = ldap_msgid(msg);
    int rc;
    int result;
    LDAPControl **serverctrls = NULL;
    PyObject *pyctrls = NULL;
    char *retoid;
    PyObject *valuestr;
    PyObject *retval = NULL;

    if (res_type == LDAP_RES_EXTENDED) {
        struct berval *retdata = NULL;

        LDAP_BEGIN_ALLOW_THREADS(lo);
        rc = ldap_parse_extended_result(lo->ldap, msg, &retoid, &retdata, 0);
        LDAP_END_ALLOW_THREADS(lo);

        if (rc != LDAP_SUCCESS) {
            LDAPraise_for_message(lo->ldap, msg);
            goto out;
        }

        valuestr = LDAPberval_to_object(retdata);
        ber_bvfree(retdata);
        if (!valuestr)
            goto out;

    } else {
        retoid = NULL;
        Py_INCREF(Py_None);
        valuestr = Py_None;
    }

    LDAP_BEGIN_ALLOW_THREADS(lo);
    rc = ldap_parse_result(lo->ldap, msg, &result, NULL, NULL, NULL,
                           &serverctrls, 0);
    LDAP_END_ALLOW_THREADS(lo);

    if (result != LDAP_SUCCESS) {
        LDAPraise_for_message(lo->ldap, msg);
        goto out;
    }

    /*
     * Create a list of control tuples (if any were returned from
     * ldap_parse_result() above), or an empty list.
     */
    pyctrls = LDAPControls_to_List(serverctrls);
    if (!pyctrls) {
        int err = LDAP_NO_MEMORY;

        LDAP_BEGIN_ALLOW_THREADS(lo);
        ldap_set_option(lo->ldap, LDAP_OPT_ERROR_NUMBER, &err);
        LDAP_END_ALLOW_THREADS(lo);
        LDAPerror(lo->ldap);
        goto out_serverctrls;
    }

    retval = Py_BuildValue("(iiOsO)", res_type, res_msgid,
                           pyctrls, retoid,
                           valuestr ? valuestr : Py_None);

    Py_DECREF(pyctrls);
out_serverctrls:
    ldap_controls_free(serverctrls);
out:
    Py_DECREF(valuestr);
    ldap_memfree(retoid);
    return retval;
}

/*
 * Converts an LDAP message into a Python structure.
 *
 * On success, returns a list of 2- or 3-tuples.
 * On failure, returns NULL, and sets an error.
 *
 * For an entry, the 2-tuples contain:
 *   (dn: str, attrdict: Dict[str, List[bytes]])
 *
 * For a referral, the 2-tuples contain:
 *   (None, reflist: List[str])
 *
 * If add_ctrls is true, per-entry/referral controls will be added
 * as a third item to each of the above tuples.
 *
 * If add_intermediates is true, intermediate/partial results will
 * also be included in the returned list, always as 3-tuples:
 *   (oid: str, value: bytes, controls)
 *
 * Controls are lists of 3-tuples:
 *   (type: str, criticality: bool, value: bytes | None)
 *
 * The message m is always freed, regardless of return value.
 */
static PyObject *
LDAPmessage_to_Tuples(LDAP *ld, LDAPMessage *m, bool add_ctrls,
                      bool add_intermediates)
{
    PyObject *list;
    PyObject *result = NULL;

    list = PyList_New(0);
    if (!list)
        goto out;

    for (LDAPMessage *entry = ldap_first_entry(ld, m); entry;
         entry = ldap_next_entry(ld, entry)) {
        PyObject *entrytuple = process_entry(ld, entry, add_ctrls);
        if (!entrytuple)
            goto out_list;

        if (PyList_Append(list, entrytuple) < 0) {
            Py_DECREF(entrytuple);
            goto out_list;
        }

        Py_DECREF(entrytuple);
    }

    for (LDAPMessage *ref = ldap_first_reference(ld, m); ref;
         ref = ldap_next_reference(ld, ref)) {
        PyObject *reftuple = process_reference(ld, ref, add_ctrls);
        if (!reftuple)
            goto out_list;

        if (PyList_Append(list, reftuple) < 0) {
            Py_DECREF(reftuple);
            goto out_list;
        }

        Py_DECREF(reftuple);
    }

    if (!add_intermediates)
        goto done;

    for (LDAPMessage *inter = ldap_first_message(ld, m); inter;
         inter = ldap_next_message(ld, inter)) {
        PyObject *intertuple;

        if (ldap_msgtype(inter) != LDAP_RES_INTERMEDIATE)
            continue;

        intertuple = process_intermediate(ld, inter);
        if (!intertuple)
            goto out_list;

        if (PyList_Append(list, intertuple) < 0) {
            Py_DECREF(intertuple);
            goto out_list;
        }

        Py_DECREF(intertuple);
    }

done:
    result = list;
    list = NULL;
out_list:
    Py_XDECREF(list);
out:
    return result;
}

PyObject *
LDAPmessages_to_python(LDAPObject *lo, LDAPMessage *msg, bool add_ctrls,
                       bool add_intermediates)
{
    int res_type;
    PyObject *retval = NULL;
    PyObject *pmsg = NULL;
    PyObject *presult = NULL;

    /*
     * For most operations, ldap_result will return a single result message,
     * but for searches it will return a chain of messages, with the last
     * message being the result message. So we pick the last message in the
     * chain to determine the proper type (which will also match the return
     * value of ldap_result().
     */
    res_type = ldap_msgtype(msg);
    for (LDAPMessage *tmp = ldap_first_message(lo->ldap, msg); tmp;
         tmp = ldap_next_message(lo->ldap, tmp)) {
        res_type = ldap_msgtype(tmp);
    }

    if (res_type == LDAP_RES_SEARCH_ENTRY ||
        res_type == LDAP_RES_SEARCH_REFERENCE ||
        res_type == LDAP_RES_INTERMEDIATE) {
        Py_INCREF(Py_None);
        presult = Py_None;
    } else {
        presult = process_result(lo, msg, res_type);
        if (!presult)
            goto out;
    }

    pmsg = LDAPmessage_to_Tuples(lo->ldap, msg, add_ctrls, add_intermediates);
    if (!pmsg)
        goto out;

    retval = Py_BuildValue("[O, O]", pmsg, presult);

out:
    Py_XDECREF(pmsg);
    Py_XDECREF(presult);
    //ldap_msgfree(msg);
    return retval;
}
