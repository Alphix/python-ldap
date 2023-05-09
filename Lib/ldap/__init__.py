"""
ldap - base module

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

# This is also the overall release version number

from ldap.pkginfo import __version__, __author__, __license__

import os
import sys

from typing import Any, Type


if __debug__:
  # Tracing is only supported in debugging mode
  import atexit
  import traceback
  _trace_level = int(os.environ.get("PYTHON_LDAP_TRACE_LEVEL", 0))
  _trace_file_path = os.environ.get("PYTHON_LDAP_TRACE_FILE")
  if _trace_file_path is None:
    _trace_file = sys.stderr
  else:
    _trace_file = open(_trace_file_path, 'a')
    atexit.register(_trace_file.close)
  _trace_stack_limit = None
else:
  # Any use of the _trace attributes should be guarded by `if __debug__`,
  # so they should not be needed here.
  # But, providing different API for debug mode is unnecessarily fragile.
  _trace_level = 0
  _trace_file = sys.stderr
  _trace_stack_limit = None

import _ldap
assert _ldap.__version__==__version__, \
       ImportError(f'ldap {__version__} and _ldap {_ldap.__version__} version mismatch!')
from _ldap import *
# call into libldap to initialize it right now
LIBLDAP_API_INFO = _ldap.get_option(_ldap.OPT_API_INFO)

OPT_NAMES_DICT = {}
for k,v in vars(_ldap).items():
  if k.startswith('OPT_'):
    OPT_NAMES_DICT[v]=k

class DummyLock:
  """Define dummy class with methods compatible to threading.Lock"""
  def __init__(self) -> None:
    pass

  def acquire(self) -> bool:
    return True

  def release(self) -> None:
    pass

try:
  # Check if Python installation was build with thread support
  # FIXME: This can be simplified, from Python 3.7 this module is mandatory
  import threading
except ImportError:
  LDAPLockBaseClass: Type[DummyLock] | Type[threading.Lock] = DummyLock
else:
  LDAPLockBaseClass = threading.Lock


class LDAPLock:
  """
  Mainly a wrapper class to log all locking events.
  Note that this cumbersome approach with _lock attribute was taken
  since threading.Lock is not suitable for sub-classing.
  """
  _min_trace_level = 3

  def __init__(
    self,
    lock_class: Type[Any] | None = None,
    desc: str = ''
  ) -> None:
    """
    lock_class
        Class compatible to threading.Lock
    desc
        Description shown in debug log messages
    """
    self._desc = desc
    self._lock = (lock_class or LDAPLockBaseClass)()

  def acquire(self) -> bool:
    if __debug__:
      global _trace_level
      if _trace_level>=self._min_trace_level:
        _trace_file.write('***{}.acquire() {} {}\n'.format(self.__class__.__name__,repr(self),self._desc))
    return self._lock.acquire()

  def release(self) -> None:
    if __debug__:
      global _trace_level
      if _trace_level>=self._min_trace_level:
        _trace_file.write('***{}.release() {} {}\n'.format(self.__class__.__name__,repr(self),self._desc))
    self._lock.release()


# Create module-wide lock for serializing all calls into underlying LDAP lib
_ldap_module_lock = LDAPLock(desc='Module wide')

from ldap.functions import initialize,get_option,set_option,escape_str,strf_secs,strp_secs

from ldap.ldapobject import NO_UNIQUE_ENTRY, LDAPBytesWarning

from ldap.dn import explode_dn,explode_rdn,str2dn,dn2str
del str2dn
del dn2str

# More constants

# For compatibility of 2.3 and 2.4 OpenLDAP API
OPT_DIAGNOSTIC_MESSAGE = OPT_ERROR_STRING
