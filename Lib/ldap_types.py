"""
types - type annotations which are shared across modules

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

from ldap.pkginfo import __version__

#from ldap.schema.models import ObjectClass, AttributeType

from typing import TYPE_CHECKING, BinaryIO, List, MutableMapping, TextIO, Tuple, Type, Sequence, cast
if TYPE_CHECKING:
  from typing_extensions import TypeAlias
  from ldap.controls import ResponseControl

__all__ = [
    'LDAPModListAddEntry',
    'LDAPModListModifyEntry',
    'LDAPModListEntry',
    'LDAPAddModList',
    'LDAPModifyModList',
    'LDAPModList',
    'LDAPEntryDict',
    'LDAPSearchResult',
    'LDAPControlTuple',
    'LDAPControlTupleStr',
    'LDAPResultEntry2',
    'LDAPResultEntry3',
    'LDAPResultEntry',
    'LDAPResultEntryDecoded',
    'LDAPResultReferral2',
    'LDAPResultReferral3',
    'LDAPResultReferral',
    'LDAPResultReferralDecoded',
    'LDAPResultIntermediate',
    'LDAPResultIntermediateDecoded',
    'LDAPResult3',
    'LDAPResultDecoded',
    'LDAPResult',
]

LDAPModListAddEntry: TypeAlias = "Tuple[str, List[bytes]]"
"""The type of an addition entry in a modlist."""

LDAPModListModifyEntry: TypeAlias = "Tuple[int, str, List[bytes] | None]"
"""The type of a modification entry in a modlist."""

LDAPModListEntry: TypeAlias = "LDAPModListAddEntry | LDAPModListModifyEntry"
"""The type of any kind of entry in a modlist."""

LDAPAddModList: TypeAlias = "Sequence[LDAPModListAddEntry]"
"""The type of an add modlist."""

LDAPModifyModList: TypeAlias = "Sequence[LDAPModListModifyEntry]"
"""The type of a modify modlist."""

LDAPModList: TypeAlias = "Sequence[LDAPModListEntry]"
"""The type of a mixed modlist."""

LDAPEntryDict: TypeAlias = "MutableMapping[str, List[bytes]]"
"""The type used to store attribute-value mappings for a given LDAP entry (attribute name, list of binary values)."""

LDAPSearchResult: TypeAlias = "Tuple[str, LDAPEntryDict]"
"""The type of a search result, a tuple with a DN string and a dict of attributes."""

LDAPControlTuple: TypeAlias = "Tuple[str, bool, bytes | None]"
"""The type used to represent a request/response control (type, criticality, value)."""

LDAPControlTupleStr: TypeAlias = "Tuple[str, str, str | None]"
"""The type used to represent a request/response control in str form (type, criticality, value)."""

LDAPResultEntry2: TypeAlias = "Tuple[str, LDAPEntryDict]"
"""One type used to return an entry result, e.g. when searching."""

LDAPResultEntry3: TypeAlias = "Tuple[str, LDAPEntryDict, List[LDAPControlTuple]]"
"""Alternative type used to return an entry result, e.g. when searching."""

LDAPResultEntry: TypeAlias = "LDAPResultEntry2 | LDAPResultEntry3"
"""The type used to return an entry result, e.g. when searching."""

LDAPResultEntryDecoded: TypeAlias = "Tuple[str, LDAPEntryDict, List[ResponseControl]]"
"""The type used to return a decoded entry result."""

LDAPResultReferral2: TypeAlias = "Tuple[None, List[str]]"
"""One type used to return a referral result, e.g. when searching."""

LDAPResultReferral3: TypeAlias = "Tuple[None, List[str], List[LDAPControlTuple]]"
"""Another type used to return a referral result, e.g. when searching."""

LDAPResultReferral: TypeAlias = "LDAPResultReferral2 | LDAPResultReferral3"
"""The type used to return a referral result, e.g. when searching."""

LDAPResultReferralDecoded: TypeAlias = "Tuple[None, List[str], List[ResponseControl]]"
"""The type of a decoded referral result."""

LDAPResultIntermediate: TypeAlias = "Tuple[str, bytes, List[LDAPControlTuple]]"
"""The type used to return an intermediate result, e.g. when searching."""

LDAPResultIntermediateDecoded: TypeAlias = "Tuple[str, bytes, List[ResponseControl]]"
"""The type used to return a decoded intermediate result."""

LDAPResult3: TypeAlias = "LDAPResultEntry3 | LDAPResultReferral3 | LDAPResultIntermediate"
"""A convenience type for any kind of 3-tuple result."""

LDAPResultDecoded: TypeAlias = "LDAPResultEntryDecoded | LDAPResultReferralDecoded | LDAPResultIntermediateDecoded"
"""A convenience type for any kind of decoded 3-tuple result."""

LDAPResult: TypeAlias = "LDAPResultEntry | LDAPResultReferral | LDAPResultIntermediate"
"""A convenience type for any kind of result."""
