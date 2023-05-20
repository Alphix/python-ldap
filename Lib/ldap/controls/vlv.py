"""
ldap.controls.vlv - classes for Virtual List View
(see draft-ietf-ldapext-ldapv3-vlv)

See https://www.python-ldap.org/ for project details.
"""

__all__ = [
  'VLVRequestControl',
  'VLVResponseControl',
]

import ldap
from ldap.ldapobject import LDAPObject
from ldap.controls import (RequestControl, ResponseControl,
        KNOWN_RESPONSE_CONTROLS, DecodeControlTuples)

from pyasn1.type import univ, namedtype, tag, namedval, constraint
from pyasn1.codec.ber import encoder, decoder

from typing import Optional


class ByOffsetType(univ.Sequence):  # type: ignore
    tagSet = univ.Sequence.tagSet.tagImplicitly(
            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('offset', univ.Integer()),
            namedtype.NamedType('contentCount', univ.Integer()))


class TargetType(univ.Choice):  # type: ignore
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('byOffset', ByOffsetType()),
            namedtype.NamedType('greaterThanOrEqual', univ.OctetString().subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 1))))


class VirtualListViewRequestType(univ.Sequence):  # type: ignore
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('beforeCount', univ.Integer()),
            namedtype.NamedType('afterCount', univ.Integer()),
            namedtype.NamedType('target', TargetType()),
            namedtype.OptionalNamedType('contextID', univ.OctetString()))


class VLVRequestControl(RequestControl):
    controlType = '2.16.840.1.113730.3.4.9'

    def __init__(
        self,
        criticality: bool = False,
        before_count: int = 0,
        after_count: int = 0,
        offset: Optional[int] = None,
        content_count: Optional[int] = None,
        greater_than_or_equal: Optional[str] = None,
        context_id: Optional[str] = None,
    ):
        super().__init__(criticality)
        assert (offset is not None and content_count is not None) or \
               greater_than_or_equal, \
            ValueError(
                'offset and content_count must be set together or greater_than_or_equal must be used'
            )
        self.before_count = before_count
        self.after_count = after_count
        self.offset = offset
        self.content_count = content_count
        self.greater_than_or_equal = greater_than_or_equal
        self.context_id = context_id

    def encodeControlValue(self) -> bytes:
        p = VirtualListViewRequestType()
        p.setComponentByName('beforeCount', self.before_count)
        p.setComponentByName('afterCount', self.after_count)
        if self.offset is not None and self.content_count is not None:
            by_offset = ByOffsetType()
            by_offset.setComponentByName('offset', self.offset)
            by_offset.setComponentByName('contentCount', self.content_count)
            target = TargetType()
            target.setComponentByName('byOffset', by_offset)
        elif self.greater_than_or_equal:
            target = TargetType()
            target.setComponentByName('greaterThanOrEqual',
                    self.greater_than_or_equal)
        else:
            raise NotImplementedError
        p.setComponentByName('target', target)
        return encoder.encode(p)  # type: ignore

# FIXME: This is a request control though?
#KNOWN_RESPONSE_CONTROLS[VLVRequestControl.controlType] = VLVRequestControl


class VirtualListViewResultType(univ.Enumerated):  # type: ignore
    namedValues = namedval.NamedValues(
               ('success', 0),
               ('operationsError', 1),
               ('protocolError', 3),
               ('unwillingToPerform', 53),
               ('insufficientAccessRights', 50),
               ('adminLimitExceeded', 11),
               ('innapropriateMatching', 18),
               ('sortControlMissing', 60),
               ('offsetRangeError', 61),
               ('other', 80),
    )


class VirtualListViewResponseType(univ.Sequence):  # type: ignore
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('targetPosition', univ.Integer()),
            namedtype.NamedType('contentCount', univ.Integer()),
            namedtype.NamedType('virtualListViewResult',
                VirtualListViewResultType()),
            namedtype.OptionalNamedType('contextID', univ.OctetString()))


class VLVResponseControl(ResponseControl):
    controlType = '2.16.840.1.113730.3.4.10'

    def __init__(self, criticality: bool = False) -> None:
        super().__init__(criticality)

    def decodeControlValue(self, encoded: Optional[bytes]) -> None:
        p, rest = decoder.decode(encoded, asn1Spec=VirtualListViewResponseType())
        assert not rest, 'all data could not be decoded'
        self.targetPosition = int(p.getComponentByName('targetPosition'))
        self.contentCount = int(p.getComponentByName('contentCount'))
        virtual_list_view_result = p.getComponentByName('virtualListViewResult')
        self.virtualListViewResult = int(virtual_list_view_result)
        context_id = p.getComponentByName('contextID')
        if context_id.hasValue():
            self.contextID: Optional[str] = str(context_id)
        else:
            self.contextID = None
        # backward compatibility class attributes
        self.target_position = self.targetPosition
        self.content_count = self.contentCount
        self.result = self.virtualListViewResult
        self.context_id = self.contextID

KNOWN_RESPONSE_CONTROLS[VLVResponseControl.controlType] = VLVResponseControl
