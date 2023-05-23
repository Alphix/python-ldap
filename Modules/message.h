/* See https://www.python-ldap.org/ for details. */

#ifndef __h_message
#define __h_message

#include <stdbool.h>

#include "common.h"

extern PyObject *
LDAPmessages_to_python(LDAPObject *lo, LDAPMessage *m, bool add_ctrls,
                       bool add_intermediates);

#endif /* __h_message_ */
