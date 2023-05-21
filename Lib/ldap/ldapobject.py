"""
ldapobject.py - wraps class _ldap.LDAP

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

from os import strerror

from ldap.pkginfo import __version__, __author__, __license__

from ldap.controls import RequestControl, ResponseControl

from ldap_types import *
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, Dict, Iterable, List, Sequence, TextIO, Tuple, Type, cast
from types import TracebackType
if TYPE_CHECKING:
  from typing_extensions import Self

__all__ = [
  'LDAPObject',
  'SimpleLDAPObject',
  'ReconnectLDAPObject',
  'LDAPBytesWarning'
]


if __debug__:
  # Tracing is only supported in debugging mode
  import traceback

import sys,time,pprint,_ldap,ldap,ldap.sasl,ldap.functions
import warnings

from ldap.schema import SCHEMA_ATTRS
from ldap.controls import LDAPControl,DecodeControlTuples,RequestControlTuples
from ldap.extop import ExtendedRequest,ExtendedResponse,PasswordModifyResponse

from ldap import LDAPError


class LDAPBytesWarning(BytesWarning):
    """Python 2 bytes mode warning"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        warnings.warn(
            "LDAPBytesWarning is deprecated and will be removed in the future",
            DeprecationWarning,
        )
        super().__init__(*args, **kwargs)


class NO_UNIQUE_ENTRY(ldap.NO_SUCH_OBJECT):
  """
  Exception raised if a LDAP search returned more than entry entry
  although assumed to return a unique single search result.
  """


class CallLock():
    """
    Wrapper class mainly for serializing calls into OpenLDAP libs
    and trace log output.

    In order for trace logging to work properly, the CallLock should
    be used like this:

    ```
    with lock_object(some_function, arg1, arg2) as lock:
        result = some_function(arg1, arg2)
        lock.result = result
        <do something with result>
    ```
    """

    def __init__(
        self,
        parent: SimpleLDAPObject,
        uri: str,
        trace_level: int,
        trace_file: TextIO | None,
        trace_stack_limit: int,
    ) -> None:
        self._parent = parent
        self._uri = uri
        self._trace_level = trace_level
        self._trace_file = trace_file
        self._trace_stack_limit = trace_stack_limit
        self._func_name = '<unknown>'
        self._func_args = None
        self._func_kwargs = None
        self.result: Any | None = None

        if ldap.LIBLDAP_R:
            self._lock = ldap.LDAPLock(desc=f'opcall within {repr(parent)}')
        else:
            self._lock = ldap._ldap_module_lock

    def __call__(
        self,
        func: Callable[..., Any],
        *func_args: Any,
        **func_kwargs: Any
    ) -> Self:
        self._func_name = func.__name__
        self._func_args = func_args
        self._func_kwargs = func_kwargs
        self.result = None
        return self

    def __enter__(self) -> Self:
        assert self._func_name is not None

        self._lock.acquire()

        if __debug__ and self._trace_level >=1 and self._trace_file is not None:
            call = '.'.join((self._parent.__class__.__name__, self._func_name))
            self._trace_file.write((
                f'*** {repr(self._parent)} {self._uri} - {call}\n'
                f'{pprint.pformat((self._func_args, self._func_kwargs))}\n'
            ))

        if __debug__ and self._trace_level >= 9:
            traceback.print_stack(
                limit=self._trace_stack_limit,
                file=self._trace_file
            )

        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc is None and __debug__ and self._trace_level >= 2 and self._trace_file is not None:
            if self._func_name != "unbind_ext":
                msg = self._parent._l.get_option(ldap.OPT_DIAGNOSTIC_MESSAGE)
                self._trace_file.write(f'=> diagnosticMessage: {repr(msg)}')

            self._trace_file.write((
                f'=> result:\n'
                f'{pprint.pformat(self.result)}\n'
            ))

        elif isinstance(exc, LDAPError):
            try:
                if 'info' not in exc.args[0] and 'errno' in exc.args[0]:
                    exc.args[0]['info'] = strerror(exc.args[0]['errno'])
            except IndexError:
                pass

            if __debug__ and self._trace_level >= 2 and self._trace_file is not None:
                self._trace_file.write((
                    '=> LDAPError - '
                    f'{exc.__class__.__name__}: {str(exc)}\n'
                ))

        self._func_name = '<unknown>'
        self._func_args = None
        self._func_kwargs = None
        self.result = None
        self._lock.release()

        # Propagate any exceptions
        return None


class SimpleLDAPObject:
  """
  This basic class wraps all methods of the underlying C API object.

  The arguments are same as for the :func:`~ldap.initialize()` function.
  """

  CLASSATTR_OPTION_MAPPING = {
    "protocol_version":   ldap.OPT_PROTOCOL_VERSION,
    "deref":              ldap.OPT_DEREF,
    "referrals":          ldap.OPT_REFERRALS,
    "timelimit":          ldap.OPT_TIMELIMIT,
    "sizelimit":          ldap.OPT_SIZELIMIT,
    "network_timeout":    ldap.OPT_NETWORK_TIMEOUT,
    "error_number":ldap.OPT_ERROR_NUMBER,
    "error_string":ldap.OPT_ERROR_STRING,
    "matched_dn":ldap.OPT_MATCHED_DN,
  }

  def __init__(
    self,
    uri: str,
    trace_level: int = 0,
    trace_file: TextIO | None = None,
    trace_stack_limit: int = 5,
    bytes_mode: Any | None = None,
    bytes_strictness: str | None = None,
    fileno: int | BinaryIO | None = None,
  ):
    self._trace_level = trace_level or ldap._trace_level
    self._trace_file = trace_file or ldap._trace_file
    self._trace_stack_limit = trace_stack_limit
    self._uri = uri
    self._lock = CallLock(
        self,
        self._uri,
        self._trace_level,
        self._trace_file,
        self._trace_stack_limit
    )

    if fileno is not None:
      if not hasattr(_ldap, "initialize_fd"):
        raise ValueError("libldap does not support initialize_fd")

      if hasattr(fileno, "fileno"):
        fileno = fileno.fileno()

      with self._lock(_ldap.initialize_fd, fileno, uri) as lock:
        self._l: _ldap.LDAP = _ldap.initialize_fd(fileno, uri)
        lock.result = self._l

    else:
      with self._lock(_ldap.initialize, uri) as lock:
        self._l = _ldap.initialize(uri)
        lock.result = self._l

    self.timeout = -1
    self.protocol_version = ldap.VERSION3

    if bytes_mode:
        raise ValueError("bytes_mode is *not* supported under Python 3.")

  @property
  def bytes_mode(self) -> bool:
    return False

  @property
  def bytes_strictness(self) -> str:
    return 'error'

  def __setattr__(self, name: str, value: Any) -> None:
    if name in self.CLASSATTR_OPTION_MAPPING:
      self.set_option(self.CLASSATTR_OPTION_MAPPING[name],value)
    else:
      self.__dict__[name] = value

  def __getattr__(self, name: str) -> Any:
    if name in self.CLASSATTR_OPTION_MAPPING:
      return self.get_option(self.CLASSATTR_OPTION_MAPPING[name])
    elif name in self.__dict__:
      return self.__dict__[name]
    else:
      raise AttributeError('{} has no attribute {}'.format(
        self.__class__.__name__,repr(name)
      ))

  def fileno(self) -> int:
    """
    Returns file description of LDAP connection.

    Just a convenience wrapper for LDAPObject.get_option(ldap.OPT_DESC)
    """
    fd = self.get_option(ldap.OPT_DESC)
    if isinstance(fd, int):
        return fd
    else:
        return -1

  def abandon_ext(
    self,
    msgid: int,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> None:
    """
    abandon_ext(msgid[,serverctrls=None[,clientctrls=None]]) -> None
    abandon(msgid) -> None
        Abandons or cancels an LDAP operation in progress. The msgid should
        be the message id of an outstanding LDAP operation as returned
        by the asynchronous methods search(), modify() etc.  The caller
        can expect that the result of an abandoned operation will not be
        returned from a future call to result().
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.abandon_ext, msgid, sctrls, cctrls) as lock:
      lock.result = self._l.abandon_ext(msgid, sctrls, cctrls)

  def abandon(self, msgid: int) -> None:
    return self.abandon_ext(msgid,None,None)

  def cancel(
    self,
    cancelid: int,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    cancel(cancelid[,serverctrls=None[,clientctrls=None]]) -> int
        Send cancels extended operation for an LDAP operation specified by cancelid.
        The cancelid should be the message id of an outstanding LDAP operation as returned
        by the asynchronous methods search(), modify() etc.  The caller
        can expect that the result of an abandoned operation will not be
        returned from a future call to result().
        In opposite to abandon() this extended operation gets an result from
        the server and thus should be preferred if the server supports it.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.cancel, cancelid, sctrls, cctrls) as lock:
      result = self._l.cancel(cancelid, sctrls, cctrls)
      lock.result = result
      return result

  def cancel_s(
    self,
    cancelid: int,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> Tuple[int, Sequence[LDAPResult]] | Tuple[None, None] | None:
    msgid = self.cancel(cancelid, serverctrls, clientctrls)
    try:
      res = self.result(msgid)
    except (ldap.CANCELLED, ldap.SUCCESS):
      res = None
    return res

  def add_ext(
    self,
    dn: str,
    modlist: LDAPAddModList,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    add_ext(dn, modlist[,serverctrls=None[,clientctrls=None]]) -> int
        This function adds a new entry with a distinguished name
        specified by dn which means it must not already exist.
        The parameter modlist is similar to the one passed to modify(),
        except that no operation integer need be included in the tuples.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.add_ext, dn, modlist, sctrls, cctrls) as lock:
      result = self._l.add_ext(dn, modlist, sctrls, cctrls)
      lock.result = result
      return result  # type: ignore

  def add_ext_s(
    self,
    dn: str,
    modlist: LDAPAddModList,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> Tuple[Any, Any, Any, Any]:
    # FIXME: The return value could be more specific
    msgid = self.add_ext(dn,modlist,serverctrls,clientctrls)
    resp_type, resp_data, resp_msgid, resp_ctrls = self.result3(msgid,all=1,timeout=self.timeout)
    return resp_type, resp_data, resp_msgid, resp_ctrls

  def add(
    self,
    dn: str,
    modlist: LDAPAddModList,
  ) -> int:
    """
    add(dn, modlist) -> int
        This function adds a new entry with a distinguished name
        specified by dn which means it must not already exist.
        The parameter modlist is similar to the one passed to modify(),
        except that no operation integer need be included in the tuples.
    """
    return self.add_ext(dn,modlist,None,None)

  def add_s(
    self,
    dn: str,
    modlist: LDAPAddModList,
  ) -> Tuple[Any, Any, Any, Any]:
    return self.add_ext_s(dn,modlist,None,None)

  def simple_bind(
    self,
    who: str | None = None,
    cred: str | None = None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    simple_bind([who=None[,cred=None[,serverctrls=None[,clientctrls=None]]]]) -> int
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.simple_bind, who, cred, sctrls, cctrls) as lock:
      result = self._l.simple_bind(who, cred, sctrls, cctrls)
      lock.result = result
      return result

  def simple_bind_s(
    self,
    who: str | None = None,
    cred: str | None = None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> Tuple[Any, Any, Any, Any]:
    # FIXME: The return value could be more specific
    """
    simple_bind_s([who=None[,cred=None[,serverctrls=None[,clientctrls=None]]]]) -> 4-tuple
    """
    msgid = self.simple_bind(who,cred,serverctrls,clientctrls)
    resp_type, resp_data, resp_msgid, resp_ctrls = self.result3(msgid,all=1,timeout=self.timeout)
    return resp_type, resp_data, resp_msgid, resp_ctrls

  def bind(
    self,
    who: str,
    cred: str,
    method: int = ldap.AUTH_SIMPLE,
  ) -> int:
    """
    bind(who, cred, method) -> int
    """
    assert method==ldap.AUTH_SIMPLE,'Only simple bind supported in LDAPObject.bind()'
    return self.simple_bind(who,cred)

  def bind_s(
    self,
    who: str,
    cred: str,
    method: int = ldap.AUTH_SIMPLE,
  ) -> None:
    """
    bind_s(who, cred, method) -> None
    """
    msgid = self.bind(who,cred,method)
    return self.result(msgid,all=1,timeout=self.timeout)  # type: ignore

  def sasl_interactive_bind_s(
    self,
    who: str,
    auth: ldap.sasl.sasl,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    sasl_flags: int = ldap.SASL_QUIET,
  ) -> None:
    """
    sasl_interactive_bind_s(who, auth [,serverctrls=None[,clientctrls=None[,sasl_flags=ldap.SASL_QUIET]]]) -> None
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.sasl_interactive_bind_s, who, auth, sctrls, cctrls, sasl_flags) as lock:
      self._l.sasl_interactive_bind_s(who, auth, sctrls, cctrls, sasl_flags)
      lock.result = None

  def sasl_non_interactive_bind_s(
    self,
    sasl_mech: str,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    sasl_flags: int = ldap.SASL_QUIET,
    authz_id: str = '',
  ) -> None:
    """
    Send a SASL bind request using a non-interactive SASL method (e.g. GSSAPI, EXTERNAL)
    """
    auth = ldap.sasl.sasl(
      {ldap.sasl.CB_USER:authz_id},
      sasl_mech
    )
    self.sasl_interactive_bind_s('',auth,serverctrls,clientctrls,sasl_flags)

  def sasl_external_bind_s(
    self,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    sasl_flags: int = ldap.SASL_QUIET,
    authz_id: str = '',
  ) -> None:
    """
    Send SASL bind request using SASL mech EXTERNAL
    """
    self.sasl_non_interactive_bind_s('EXTERNAL',serverctrls,clientctrls,sasl_flags,authz_id)

  def sasl_gssapi_bind_s(
    self,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    sasl_flags: int = ldap.SASL_QUIET,
    authz_id: str = '',
  ) -> None:
    """
    Send SASL bind request using SASL mech GSSAPI
    """
    self.sasl_non_interactive_bind_s('GSSAPI',serverctrls,clientctrls,sasl_flags,authz_id)

  def sasl_bind_s(
    self,
    dn: str | None,
    mechanism: str | None,
    cred: str | None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> bytes | None:
    """
    sasl_bind_s(dn, mechanism, cred [,serverctrls=None[,clientctrls=None]]) -> bytes | None
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.sasl_bind_s, dn, mechanism, cred, sctrls, cctrls) as lock:
      result = self._l.sasl_bind_s(dn, mechanism, cred, sctrls, cctrls)
      lock.result = result
      return result

  def compare_ext(
    self,
    dn: str,
    attr: str,
    value: str | bytes,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    compare_ext(dn, attr, value [,serverctrls=None[,clientctrls=None]]) -> int
    compare_ext_s(dn, attr, value [,serverctrls=None[,clientctrls=None]]) -> bool
    compare(dn, attr, value) -> int
    compare_s(dn, attr, value) -> bool
        Perform an LDAP comparison between the attribute named attr of entry
        dn, and the value value. The synchronous form returns True or False.
        The asynchronous form returns the message id of the initiates request,
        and the result of the asynchronous compare can be obtained using
        result().

        Note that this latter technique yields the answer by raising
        the exception objects COMPARE_TRUE or COMPARE_FALSE.

        A design bug in the library prevents value from containing
        nul characters.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.compare_ext, dn, attr, value, sctrls, cctrls) as lock:
      result = self._l.compare_ext(dn, attr, value, sctrls, cctrls)
      lock.result = result
      return result

  def compare_ext_s(
    self,
    dn: str,
    attr: str,
    value: str | bytes,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> bool:
    msgid = self.compare_ext(dn, attr, value, serverctrls, clientctrls)
    try:
        ldap_res = self.result3(msgid)
    except ldap.COMPARE_TRUE:
      return True
    except ldap.COMPARE_FALSE:
      return False
    raise ldap.PROTOCOL_ERROR(
        f'Compare operation returned wrong result: {ldap_res!r}'
    )

  def compare(
    self,
    dn: str,
    attr: str,
    value: str | bytes,
  ) -> int:
    return self.compare_ext(dn, attr, value)

  def compare_s(
    self,
    dn: str,
    attr: str,
    value: str | bytes,
  ) -> bool:
    return self.compare_ext_s(dn, attr, value)

  def delete_ext(
    self,
    dn: str,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    delete(dn) -> int
    delete_s(dn) -> None
    delete_ext(dn[,serverctrls=None[,clientctrls=None]]) -> int
    delete_ext_s(dn[,serverctrls=None[,clientctrls=None]]) -> 4-tuple
        Performs an LDAP delete operation on dn. The asynchronous
        form returns the message id of the initiated request, and the
        result can be obtained from a subsequent call to result().
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.delete_ext, dn, sctrls, cctrls) as lock:
      result = self._l.delete_ext(dn, sctrls, cctrls)
      lock.result = result
      return result

  def delete_ext_s(
    self,
    dn: str,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> Tuple[int, Sequence[LDAPResult], int, List[ResponseControl]] | Tuple[None, None, None, None]:
    msgid = self.delete_ext(dn, serverctrls, clientctrls)
    return self.result3(msgid)

  def delete(self, dn: str) -> int:
    return self.delete_ext(dn)

  def delete_s(self, dn: str) -> None:
    self.delete_ext_s(dn)

  def extop(
    self,
    extreq: ldap.extop.ExtendedRequest,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    extop(extreq[,serverctrls=None[,clientctrls=None]]]) -> int
    extop_s(extreq[,serverctrls=None[,clientctrls=None[,extop_resp_class=None]]]]) ->
        (respoid,respvalue)
        Performs an LDAP extended operation. The asynchronous
        form returns the message id of the initiated request, and the
        result can be obtained from a subsequent call to extop_result().
        The extreq is an instance of class ldap.extop.ExtendedRequest.

        If argument extop_resp_class is set to a sub-class of
        ldap.extop.ExtendedResponse this class is used to return an
        object of this class instead of a raw BER value in respvalue.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    reqname = extreq.requestName
    reqvalue = extreq.encodedRequestValue()
    with self._lock(self._l.extop, reqname, reqvalue, sctrls, cctrls) as lock:
      result = self._l.extop(reqname, reqvalue, sctrls, cctrls)
      lock.result = result
      return result

  def extop_result(
    self,
    msgid: int = ldap.RES_ANY,
    all: int = 1,
    timeout: int | None = None,
  ) -> Tuple[str | None, bytes | None]:
    resulttype, msg, rmsgid, respctrls, respoid, respvalue = self.result4(
      msgid, all=1, timeout=timeout, add_ctrls=1, add_intermediates=1
    )
    return respoid, respvalue

  def extop_s(
    self,
    extreq: ldap.extop.ExtendedRequest,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    extop_resp_class: Type[ldap.extop.ExtendedResponse] | None = None,
  ) -> Tuple[str | None, bytes | None] | ldap.extop.ExtendedResponse:
    msgid = self.extop(extreq, serverctrls, clientctrls)
    res = self.extop_result(msgid)
    respoid, respvalue = self.extop_result(msgid)
    if extop_resp_class and respoid is not None and respvalue is not None:
      if extop_resp_class.responseName != respoid:
        raise ldap.PROTOCOL_ERROR(f"Wrong OID in extended response! Expected {extop_resp_class.responseName}, got {respoid}")
      return extop_resp_class(extop_resp_class.responseName, respvalue)
    else:
      return respoid, respvalue

  def modify_ext(
    self,
    dn: str,
    modlist: LDAPModifyModList,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    modify_ext(dn, modlist[,serverctrls=None[,clientctrls=None]]) -> int
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.modify_ext, dn, modlist, sctrls, cctrls) as lock:
      result = self._l.modify_ext(dn, modlist, sctrls, cctrls)
      lock.result = result
      return result

  def modify_ext_s(
    self,
    dn: str,
    modlist: LDAPModifyModList,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> Tuple[int, Sequence[LDAPResult], int, List[ResponseControl]] | Tuple[None, None, None, None]:
    msgid = self.modify_ext(dn,modlist,serverctrls,clientctrls)
    return self.result3(msgid, all=1, timeout=self.timeout)

  def modify(
    self,
    dn: str,
    modlist: LDAPModifyModList,
  ) -> int:
    """
    modify(dn, modlist) -> int
    modify_s(dn, modlist) -> None
    modify_ext(dn, modlist[,serverctrls=None[,clientctrls=None]]) -> int
    modify_ext_s(dn, modlist[,serverctrls=None[,clientctrls=None]]) -> 4-tuple
        Performs an LDAP modify operation on an entry's attributes.
        dn is the DN of the entry to modify, and modlist is the list
        of modifications to make to the entry.

        Each element of the list modlist should be a tuple of the form
        (mod_op,mod_type,mod_vals), where mod_op is the operation (one of
        MOD_ADD, MOD_DELETE, MOD_INCREMENT or MOD_REPLACE), mod_type is a
        string indicating the attribute type name, and mod_vals is either a
        string value or a list of string values to add, delete, increment by or
        replace respectively.  For the delete operation, mod_vals may be None
        indicating that all attributes are to be deleted.

        The asynchronous modify() returns the message id of the
        initiated request.
    """
    return self.modify_ext(dn,modlist,None,None)

  def modify_s(
    self,
    dn: str,
    modlist: LDAPModifyModList,
  ) -> None:
    self.modify_ext_s(dn,modlist,None,None)

  def modrdn(
    self,
    dn: str,
    newrdn: str,
    delold: int = 1,
  ) -> int:
    """
    modrdn(dn, newrdn [,delold=1]) -> int
    modrdn_s(dn, newrdn [,delold=1]) -> None
        Perform a modify RDN operation. These routines take dn, the
        DN of the entry whose RDN is to be changed, and newrdn, the
        new RDN to give to the entry. The optional parameter delold
        is used to specify whether the old RDN should be kept as
        an attribute of the entry or not.  The asynchronous version
        returns the initiated message id.

        This operation is emulated by rename() and rename_s() methods
        since the modrdn2* routines in the C library are deprecated.
    """
    return self.rename(dn,newrdn,None,delold)

  def modrdn_s(
    self,
    dn: str,
    newrdn: str,
    delold: int = 1,
  ) -> None:
    return self.rename_s(dn,newrdn,None,delold)

  def passwd(
    self,
    user: str | None,
    oldpw: str | None,
    newpw: str | None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.passwd, user, oldpw, newpw, sctrls, cctrls) as lock:
      result = self._l.passwd(user, oldpw, newpw, sctrls, cctrls)
      lock.result = result
      return result

  def passwd_s(
    self,
    user: str | None,
    oldpw: str | None,
    newpw: str | None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    extract_newpw: bool = False,
  ) -> Tuple[str, bytes | PasswordModifyResponse | None]:
    msgid = self.passwd(user, oldpw, newpw, serverctrls, clientctrls)
    _, _, _, _, respoid, respvalue = self.result4(
        msgid, all=1, timeout=self.timeout,
        add_ctrls=1, add_intermediates=1
    )

    if respoid != PasswordModifyResponse.responseName:
      raise ldap.PROTOCOL_ERROR("Unexpected OID %s in extended response!" % respoid)

    if extract_newpw and respvalue:
      return respoid, PasswordModifyResponse(PasswordModifyResponse.responseName, respvalue)
    else:
      return respoid, respvalue

  def rename(
    self,
    dn: str,
    newrdn: str,
    newsuperior: str | None = None,
    delold: int = 1,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> int:
    """
    rename(dn, newrdn [, newsuperior=None [,delold=1][,serverctrls=None[,clientctrls=None]]]) -> int
    rename_s(dn, newrdn [, newsuperior=None] [,delold=1][,serverctrls=None[,clientctrls=None]]) -> None
        Perform a rename entry operation. These routines take dn, the
        DN of the entry whose RDN is to be changed, newrdn, the
        new RDN, and newsuperior, the new parent DN, to give to the entry.
        If newsuperior is None then only the RDN is modified.
        The optional parameter delold is used to specify whether the
        old RDN should be kept as an attribute of the entry or not.
        The asynchronous version returns the initiated message id.

        This actually corresponds to the rename* routines in the
        LDAP-EXT C API library.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.rename, dn, newrdn, newsuperior, delold, sctrls, cctrls) as lock:
      result = self._l.rename(dn, newrdn, newsuperior, delold, sctrls, cctrls)
      lock.result = result
      return result

  def rename_s(
    self,
    dn: str,
    newrdn: str,
    newsuperior: str | None = None,
    delold: int = 1,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> None:
    msgid = self.rename(dn,newrdn,newsuperior,delold,serverctrls,clientctrls)
    resp_type, resp_data, resp_msgid, resp_ctrls = self.result3(msgid,all=1,timeout=self.timeout)

  def result(
    self,
    msgid: int = ldap.RES_ANY,
    all: int = 1,
    timeout: int | None = None,
  ) -> Tuple[int, Sequence[LDAPResult]] | Tuple[None, None]:
    """
    result([msgid=RES_ANY [,all=1 [,timeout=None]]]) -> (result_type, result_data)

        This method is used to wait for and return the result of an
        operation previously initiated by one of the LDAP asynchronous
        operation routines (e.g. search(), modify(), etc.) They all
        returned an invocation identifier (a message id) upon successful
        initiation of their operation. This id is guaranteed to be
        unique across an LDAP session, and can be used to request the
        result of a specific operation via the msgid parameter of the
        result() method.

        If the result of a specific operation is required, msgid should
        be set to the invocation message id returned when the operation
        was initiated; otherwise RES_ANY should be supplied.

        The all parameter only has meaning for search() responses
        and is used to select whether a single entry of the search
        response should be returned, or to wait for all the results
        of the search before returning.

        A search response is made up of zero or more search entries
        followed by a search result. If all is 0, search entries will
        be returned one at a time as they come in, via separate calls
        to result(). If all is 1, the search response will be returned
        in its entirety, i.e. after all entries and the final search
        result have been received.

        For all set to 0, result tuples
        trickle in (with the same message id), and with the result type
        RES_SEARCH_ENTRY, until the final result which has a result
        type of RES_SEARCH_RESULT and a (usually) empty data field.
        When all is set to 1, only one result is returned, with a
        result type of RES_SEARCH_RESULT, and all the result tuples
        listed in the data field.

        The method returns a tuple of the form (result_type,
        result_data).  The result_type is one of the constants RES_*.

        See search() for a description of the search result's
        result_data, otherwise the result_data is normally meaningless.

        The result() method will block for timeout seconds, or
        indefinitely if timeout is negative.  A timeout of 0 will effect
        a poll. The timeout can be expressed as a floating-point value.
        If timeout is None the default in self.timeout is used.

        If a timeout occurs, a TIMEOUT exception is raised, unless
        polling (timeout = 0), in which case (None, None) is returned.
    """
    resp_type, resp_data, resp_msgid = self.result2(msgid, all, timeout)
    return resp_type, resp_data  # type: ignore

  def result2(
    self,
    msgid: int = ldap.RES_ANY,
    all: int = 1,
    timeout: int | None = None,
  ) -> Tuple[int, Sequence[LDAPResult], int] | Tuple[None, None, None]:
    resp_type, resp_data, resp_msgid, resp_ctrls = self.result3(msgid, all, timeout)
    return resp_type, resp_data, resp_msgid  # type: ignore

  def result3(
    self,
    msgid: int = ldap.RES_ANY,
    all: int = 1,
    timeout: int | None = None,
    resp_ctrl_classes: Dict[str, Type[ResponseControl]] | None = None,
  ) -> Tuple[int, Sequence[LDAPResult], int, List[ResponseControl]] | Tuple[None, None, None, None]:
    resp_type, resp_data, resp_msgid, decoded_resp_ctrls, retoid, retval = self.result4(
      msgid, all, timeout, resp_ctrl_classes=resp_ctrl_classes
    )
    return resp_type, resp_data, resp_msgid, decoded_resp_ctrls  # type: ignore

  def result4(
    self,
    msgid: int = ldap.RES_ANY,
    all: int = 1,
    timeout: int | None = None,
    add_ctrls: int = 0,
    add_intermediates: int = 0,
    add_extop: int = 0, # obsolete, but kept for backward compatibility
    resp_ctrl_classes: Dict[str, Type[ResponseControl]] | None = None,
  ) -> Tuple[int, Sequence[LDAPResult] | Sequence[LDAPResultDecoded], int, List[ResponseControl], str | None, bytes | None] | Tuple[None, None, None, None, None, None]:

    if timeout is None:
      timeout = self.timeout

    ldap_result = None
    with self._lock(self._l.result4, msgid,all,timeout,add_ctrls,add_intermediates) as lock:
      ldap_result = self._l.result4(msgid, all, timeout, add_ctrls, add_intermediates)
      lock.result = ldap_result

    if ldap_result is None:
      return None, None, None, None, None, None

    resp_type, resp_data, resp_msgid, resp_ctrls, resp_name, resp_value = ldap_result
    decoded_resp_ctrls = DecodeControlTuples(resp_ctrls, resp_ctrl_classes)

    if add_ctrls:
      tmp_resp_data = cast(Sequence[LDAPResult3], resp_data)
      decoded_resp_data = cast(
        List[LDAPResultDecoded],
        [ (t, r, DecodeControlTuples(c, resp_ctrl_classes)) for t, r, c in tmp_resp_data ]
      )
      return resp_type, decoded_resp_data, resp_msgid, decoded_resp_ctrls, resp_name, resp_value

    return resp_type, resp_data, resp_msgid, decoded_resp_ctrls, resp_name, resp_value

  def search_ext(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    timeout: int = -1,
    sizelimit: int = 0,
  ) -> int:
    """
    search(base, scope [,filterstr='(objectClass=*)' [,attrlist=None [,attrsonly=0]]]) -> int
    search_s(base, scope [,filterstr='(objectClass=*)' [,attrlist=None [,attrsonly=0]]])
    search_st(base, scope [,filterstr='(objectClass=*)' [,attrlist=None [,attrsonly=0 [,timeout=-1]]]])
    search_ext(base,scope,[,filterstr='(objectClass=*)' [,attrlist=None [,attrsonly=0 [,serverctrls=None [,clientctrls=None [,timeout=-1 [,sizelimit=0]]]]]]])
    search_ext_s(base,scope,[,filterstr='(objectClass=*)' [,attrlist=None [,attrsonly=0 [,serverctrls=None [,clientctrls=None [,timeout=-1 [,sizelimit=0]]]]]]])

        Perform an LDAP search operation, with base as the DN of
        the entry at which to start the search, scope being one of
        SCOPE_BASE (to search the object itself), SCOPE_ONELEVEL
        (to search the object's immediate children), or SCOPE_SUBTREE
        (to search the object and all its descendants).

        filter is a string representation of the filter to
        apply in the search (see RFC 4515).

        Each result tuple is of the form (dn,entry), where dn is a
        string containing the DN (distinguished name) of the entry, and
        entry is a dictionary containing the attributes.
        Attributes types are used as string dictionary keys and attribute
        values are stored in a list as dictionary value.

        The DN in dn is extracted using the underlying ldap_get_dn(),
        which may raise an exception of the DN is malformed.

        If attrsonly is non-zero, the values of attrs will be
        meaningless (they are not transmitted in the result).

        The retrieved attributes can be limited with the attrlist
        parameter.  If attrlist is None, all the attributes of each
        entry are returned.

        serverctrls=None

        clientctrls=None

        The synchronous form with timeout, search_st() or search_ext_s(),
        will block for at most timeout seconds (or indefinitely if
        timeout is negative). A TIMEOUT exception is raised if no result is
        received within the time.

        The amount of search results retrieved can be limited with the
        sizelimit parameter if non-zero.
    """
    if filterstr is None:
      filterstr = '(objectClass=*)'
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(
      self._l.search_ext, base, scope, filterstr, attrlist, attrsonly,
      sctrls, cctrls, timeout, sizelimit
    ) as lock:
      result = self._l.search_ext(
        base, scope, filterstr, attrlist, attrsonly,
        sctrls, cctrls, timeout, sizelimit
      )
      lock.result = result
      return result

  def search_ext_s(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    timeout: int = -1,
    sizelimit: int = 0,
  ) -> List[Tuple[str, LDAPEntryDict]]:
    msgid = self.search_ext(base,scope,filterstr,attrlist,attrsonly,serverctrls,clientctrls,timeout,sizelimit)
    return self.result(msgid,all=1,timeout=timeout)[1]  # type: ignore

  def search(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
  ) -> int:
    return self.search_ext(base,scope,filterstr,attrlist,attrsonly,None,None)

  def search_s(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
  ) -> List[Tuple[str, LDAPEntryDict]]:
    return self.search_ext_s(base,scope,filterstr,attrlist,attrsonly,None,None,timeout=self.timeout)

  def search_st(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
    timeout: int = -1,
  ) -> List[Tuple[str, LDAPEntryDict]]:
    return self.search_ext_s(base,scope,filterstr,attrlist,attrsonly,None,None,timeout)

  def start_tls_s(self) -> None:
    """
    start_tls_s() -> None
    Negotiate TLS with server. The `version' attribute must have been
    set to VERSION3 before calling start_tls_s.
    If TLS could not be started an exception will be raised.
    """
    with self._lock(self._l.start_tls_s) as lock:
      self._l.start_tls_s()
      lock.result = None

  def unbind_ext(
    self,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> None:
    """
    unbind() -> None
    unbind_s() -> None
    unbind_ext() -> None
    unbind_ext_s() -> None
        This call is used to unbind from the directory, terminate
        the current association, and free resources. Once called, the
        connection to the LDAP server is closed and the LDAP object
        is invalid. Further invocation of methods on the object will
        yield an exception.

        All the unbind methods methods are identical, and are synchronous
        in nature.
    """
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.unbind_ext, sctrls, cctrls) as lock:
      result = self._l.unbind_ext(sctrls, cctrls)
      lock.result = result

    try:
      del self._l
    except AttributeError:
      pass

    if __debug__ and self._trace_level>=1:
      try:
        self._trace_file.flush()
      except AttributeError:
        pass

  def unbind_ext_s(
    self,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> None:
    self.unbind_ext(serverctrls, clientctrls)

  def unbind(self) -> None:
    self.unbind_ext(None, None)

  def unbind_s(self) -> None:
    self.unbind_ext_s(None, None)

  def whoami_s(
    self,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> str:
    sctrls = RequestControlTuples(serverctrls)
    cctrls = RequestControlTuples(clientctrls)
    with self._lock(self._l.whoami_s, sctrls, cctrls) as lock:
      result = self._l.whoami_s(sctrls, cctrls)
      lock.result = result
      return result

  def get_option(
    self,
    option: int
  ) -> bool | int | str | bytes | float | Dict[str, int | str | Tuple[str, ...]] | List[ResponseControl]:
    result = None
    with self._lock(self._l.get_option, option) as lock:
      result = self._l.get_option(option)
      lock.result = result

    if option == ldap.OPT_SERVER_CONTROLS or option == ldap.OPT_CLIENT_CONTROLS:
      assert isinstance(result, Iterable)
      for x in result:
        assert isinstance(x, tuple)
      control_tuples = cast(Iterable[LDAPControlTuple], result)
      return DecodeControlTuples(control_tuples)
    else:
      assert not isinstance(result, list)
      return result

  def set_option(
    self,
    option: int,
    invalue: bool | int | str | bytes | float | Iterable[RequestControl] | None,
  ) -> None:
    if option == ldap.OPT_SERVER_CONTROLS or option == ldap.OPT_CLIENT_CONTROLS:
      assert isinstance(invalue, Iterable)
      for x in invalue:
        assert isinstance(x, RequestControl)
      invalue = cast(Iterable[RequestControl], invalue)
      value: bool | int | str | float | List[LDAPControlTuple] | None = RequestControlTuples(invalue)
    else:
      if invalue is None:
        value = invalue
      elif isinstance(invalue, bool):
        value = invalue
      elif isinstance(invalue, int):
        value = invalue
      elif isinstance(invalue, str):
        value = invalue
      elif isinstance(invalue, float):
        value = invalue
      else:
        raise TypeError(f"invalid type passed to set_option: {type(invalue)}")

    with self._lock(self._l.set_option, option, value) as lock:
      self._l.set_option(option, value)
      lock.result = None

  def search_subschemasubentry_s(
    self,
    dn: str | None = None,
  ) -> str | None:
    """
    Returns the distinguished name of the sub schema sub entry
    for a part of a DIT specified by dn.

    None as result indicates that the DN of the sub schema sub entry could
    not be determined.

    Returns: None or the DN as a string.
    """
    empty_dn = ''
    attrname = 'subschemaSubentry'
    if dn is None:
      dn = empty_dn
    try:
      r = self.search_s(
        dn,ldap.SCOPE_BASE,None,[attrname]
      )
    except (ldap.NO_SUCH_OBJECT,ldap.NO_SUCH_ATTRIBUTE,ldap.INSUFFICIENT_ACCESS):
      r = []
    except ldap.UNDEFINED_TYPE:
      return None
    try:
      if r:
        e = ldap.cidict.cidict(r[0][1])
        search_subschemasubentry_dn = e.get(attrname,[b''])[0]
        if search_subschemasubentry_dn == b'':
          if dn:
            # Try to find sub schema sub entry in root DSE
            return self.search_subschemasubentry_s(dn=empty_dn)
          else:
            # If dn was already root DSE we can return here
            return None
        else:
          dn_str: str = search_subschemasubentry_dn.decode('utf-8')
          return dn_str
    except IndexError:
      return None

    return None

  def read_s(
    self,
    dn: str,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    timeout: int = -1,
  ) -> LDAPEntryDict | None:
    """
    Reads and returns a single entry specified by `dn'.

    Other attributes just like those passed to `search_ext_s()'
    """
    r = self.search_ext_s(
      dn,
      ldap.SCOPE_BASE,
      filterstr,
      attrlist=attrlist,
      serverctrls=serverctrls,
      clientctrls=clientctrls,
      timeout=timeout,
    )
    if r:
      return r[0][1]
    else:
      return None

  def read_subschemasubentry_s(
    self,
    subschemasubentry_dn: str,
    attrs: List[str] | None = None,
  ) -> LDAPEntryDict | None:
    """
    Returns the sub schema sub entry's data
    """
    filterstr = '(objectClass=subschema)'
    if attrs is None:
      attrs = SCHEMA_ATTRS
    try:
      subschemasubentry = self.read_s(
        subschemasubentry_dn,
        filterstr=filterstr,
        attrlist=attrs
      )
    except ldap.NO_SUCH_OBJECT:
      return None
    else:
      return subschemasubentry

  def find_unique_entry(
    self,
    base: str,
    scope: int,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
    attrsonly: int = 0,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
    timeout: int = -1,
  ) -> Tuple[str, LDAPEntryDict]:
    """
    Returns a unique entry, raises exception if not unique
    """
    r = self.search_ext_s(
      base,
      scope,
      filterstr,
      attrlist=attrlist,
      attrsonly=attrsonly,
      serverctrls=serverctrls,
      clientctrls=clientctrls,
      timeout=timeout,
      sizelimit=2,
    )
    if len(r)!=1:
      raise NO_UNIQUE_ENTRY('No or non-unique search result for %s' % (repr(filterstr)))
    return r[0]

  def read_rootdse_s(
    self,
    filterstr: str | None = None,
    attrlist: List[str] | None = None,
  ) -> LDAPEntryDict | None:
    """
    convenience wrapper around read_s() for reading rootDSE
    """
    base = ''
    attrlist = attrlist or ['*', '+']
    ldap_rootdse = self.read_s(
      base,
      filterstr=filterstr,
      attrlist=attrlist,
    )
    return ldap_rootdse  # read_rootdse_s()

  def get_naming_contexts(self) -> List[bytes]:
    """
    returns all attribute values of namingContexts in rootDSE
    if namingContexts is not present (not readable) then empty list is returned
    """
    name = 'namingContexts'
    rootdse = self.read_rootdse_s(attrlist=[name])
    if rootdse is None:
        return []
    else:
        return rootdse.get(name, [])


class ReconnectLDAPObject(SimpleLDAPObject):
  """
  :py:class:`SimpleLDAPObject` subclass whose synchronous request methods
  automatically reconnect and re-try in case of server failure
  (:exc:`ldap.SERVER_DOWN`).

  The first arguments are same as for the :py:func:`~ldap.initialize()`
  function.
  For automatic reconnects it has additional arguments:

  * retry_max: specifies the number of reconnect attempts before
    re-raising the :py:exc:`ldap.SERVER_DOWN` exception.

  * retry_delay: specifies the time in seconds between reconnect attempts.

  This class also implements the pickle protocol.
  """

  __transient_attrs__ = {
    '_l',
    '_lock',
    '_trace_file',
    '_reconnect_lock',
    '_last_bind',
  }

  def __init__(
    self,
    uri: str,
    trace_level: int = 0,
    trace_file: TextIO | None = None,
    trace_stack_limit: int = 5,
    bytes_mode: Any | None = None,
    bytes_strictness: str | None = None,
    retry_max: int = 1,
    retry_delay: float = 60.0,
    fileno: int | BinaryIO | None = None,
  ) -> None:
    """
    Parameters like SimpleLDAPObject.__init__() with these
    additional arguments:

    retry_max
        Maximum count of reconnect trials
    retry_delay
        Time span to wait between two reconnect trials
    """
    self._uri = uri
    self._options: List[Tuple[int, Any]] = []
    self._last_bind: Tuple[Callable[..., Any] | str, Tuple[Any, ...], Dict[str, Any]] | None = None
    SimpleLDAPObject.__init__(self, uri, trace_level, trace_file,
                              trace_stack_limit, bytes_mode,
                              bytes_strictness=bytes_strictness,
                              fileno=fileno)
    self._reconnect_lock = ldap.LDAPLock(desc='reconnect lock within %s' % (repr(self)))
    self._retry_max = retry_max
    self._retry_delay = retry_delay
    self._start_tls = 0
    self._reconnects_done = 0

  def __getstate__(self) -> Dict[str, Any]:
    """return data representation for pickled object"""
    state = {
        k: v
        for k,v in self.__dict__.items()
        if k not in self.__transient_attrs__
    }
    if self._last_bind is not None and not isinstance(self._last_bind[0], str):
        state['_last_bind'] = self._last_bind[0].__name__, self._last_bind[1], self._last_bind[2]
    else:
        state['_last_bind'] = None
    return state

  def __setstate__(self, d: Dict[str, Any]) -> None:
    """set up the object from pickled data"""
    hardfail = d.get('bytes_mode_hardfail')
    if hardfail:
        d.setdefault('bytes_strictness', 'error')
    else:
        d.setdefault('bytes_strictness', 'warn')
    self.__dict__.update(d)
    if self._last_bind is not None and isinstance(self._last_bind[0], str):
        self._last_bind = getattr(SimpleLDAPObject, self._last_bind[0]), self._last_bind[1], self._last_bind[2]
    self._reconnect_lock = ldap.LDAPLock(desc='reconnect lock within %s' % (repr(self)))
    # XXX cannot pickle file, use default trace file
    self._trace_file = ldap._trace_file
    self._lock = CallLock(
        self,
        self._uri,
        self._trace_level,
        self._trace_file,
        self._trace_stack_limit
    )
    self.reconnect(self._uri,force=True)

  def _store_last_bind(
    self,
    _method: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
  ) -> None:
    self._last_bind = (_method,args,kwargs)

  def _apply_last_bind(self) -> None:
    if self._last_bind is not None and callable(self._last_bind[0]):
      func,args,kwargs = self._last_bind
      func(self,*args,**kwargs)  # type: ignore
    else:
      # Send explicit anon simple bind request to provoke ldap.SERVER_DOWN in method reconnect()
      SimpleLDAPObject.simple_bind_s(self, None, None)

  def _restore_options(self) -> None:
    """Restore all recorded options"""
    for k,v in self._options:
      SimpleLDAPObject.set_option(self,k,v)

  def passwd_s(
    self,
    *args: Any,
    **kwargs: Any,
  ) -> Tuple[str, bytes | PasswordModifyResponse]:
    return self._apply_method_s(SimpleLDAPObject.passwd_s,*args,**kwargs)  # type: ignore

  def reconnect(
    self,
    uri: str,
    retry_max: int = 1,
    retry_delay: float = 60.0,
    force: bool = True
  ) -> None:
    # Drop and clean up old connection completely
    # Reconnect
    self._reconnect_lock.acquire()
    try:
      if hasattr(self,'_l'):
        if force:
          SimpleLDAPObject.unbind_s(self)
        else:
          return
      reconnect_counter = retry_max
      while reconnect_counter:
        counter_text = '%d. (of %d)' % (retry_max-reconnect_counter+1,retry_max)
        if __debug__ and self._trace_level>=1:
          self._trace_file.write('*** Trying {} reconnect to {}...\n'.format(
            counter_text,uri
          ))
        try:
          try:
            # Do the connect
            self._l = ldap.functions._ldap_function_call(ldap._ldap_module_lock,_ldap.initialize,uri)
            self._restore_options()
            # StartTLS extended operation in case this was called before
            if self._start_tls:
              SimpleLDAPObject.start_tls_s(self)
            # Repeat last simple or SASL bind
            self._apply_last_bind()
          except ldap.LDAPError:
            SimpleLDAPObject.unbind_s(self)
            raise
        except (ldap.SERVER_DOWN,ldap.TIMEOUT):
          if __debug__ and self._trace_level>=1:
            self._trace_file.write('*** {} reconnect to {} failed\n'.format(
              counter_text,uri
            ))
          reconnect_counter = reconnect_counter-1
          if not reconnect_counter:
            raise
          if __debug__ and self._trace_level>=1:
            self._trace_file.write('=> delay %s...\n' % (retry_delay))
          time.sleep(retry_delay)
        else:
          if __debug__ and self._trace_level>=1:
            self._trace_file.write('*** {} reconnect to {} successful => repeat last operation\n'.format(
              counter_text,uri
            ))
          self._reconnects_done = self._reconnects_done + 1
          break
    finally:
      self._reconnect_lock.release()
    return # reconnect()

  def _apply_method_s(
    self,
    func: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
  ) -> Any:
    self.reconnect(self._uri,retry_max=self._retry_max,retry_delay=self._retry_delay,force=False)
    try:
      return func(self,*args,**kwargs)
    except ldap.SERVER_DOWN:
      # Try to reconnect
      self.reconnect(self._uri,retry_max=self._retry_max,retry_delay=self._retry_delay,force=True)
      # Re-try last operation
      return func(self,*args,**kwargs)

  def set_option(self, option: int, invalue: Any) -> Any:
    self._options.append((option,invalue))
    return SimpleLDAPObject.set_option(self,option,invalue)

  # FIXME: The following method signatures could match the SimpleLDAPObject counterpart?
  def bind_s(self, *args: Any, **kwargs: Any) -> Any:
    res = self._apply_method_s(SimpleLDAPObject.bind_s,*args,**kwargs)
    self._store_last_bind(SimpleLDAPObject.bind_s,*args,**kwargs)
    return res

  def simple_bind_s(self, *args: Any, **kwargs: Any) -> Any:
    res = self._apply_method_s(SimpleLDAPObject.simple_bind_s,*args,**kwargs)
    self._store_last_bind(SimpleLDAPObject.simple_bind_s,*args,**kwargs)
    return res

  def start_tls_s(self, *args: Any, **kwargs: Any) -> Any:
    res = self._apply_method_s(SimpleLDAPObject.start_tls_s,*args,**kwargs)
    self._start_tls = 1
    return res

  def sasl_interactive_bind_s(self, *args: Any, **kwargs: Any) -> Any:
    """
    sasl_interactive_bind_s(who, auth) -> None
    """
    res = self._apply_method_s(SimpleLDAPObject.sasl_interactive_bind_s,*args,**kwargs)
    self._store_last_bind(SimpleLDAPObject.sasl_interactive_bind_s,*args,**kwargs)
    return res

  def sasl_bind_s(self, *args: Any, **kwargs: Any) -> Any:
    res = self._apply_method_s(SimpleLDAPObject.sasl_bind_s,*args,**kwargs)
    self._store_last_bind(SimpleLDAPObject.sasl_bind_s,*args,**kwargs)
    return res

  def add_ext_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.add_ext_s,*args,**kwargs)

  def cancel_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.cancel_s,*args,**kwargs)

  def compare_ext_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.compare_ext_s,*args,**kwargs)

  def delete_ext_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.delete_ext_s,*args,**kwargs)

  def extop_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.extop_s,*args,**kwargs)

  def modify_ext_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.modify_ext_s,*args,**kwargs)

  def rename_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.rename_s,*args,**kwargs)

  def search_ext_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.search_ext_s,*args,**kwargs)

  def whoami_s(self, *args: Any, **kwargs: Any) -> Any:
    return self._apply_method_s(SimpleLDAPObject.whoami_s,*args,**kwargs)


# The class called LDAPObject will be used as default for
# ldap.open() and ldap.initialize()
LDAPObject = SimpleLDAPObject
