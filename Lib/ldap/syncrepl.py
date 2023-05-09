"""
ldap.syncrepl - for implementing syncrepl consumer (see RFC 4533)

See https://www.python-ldap.org/ for project details.
"""
from __future__ import annotations

from uuid import UUID

# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder

from ldap.pkginfo import __version__, __author__, __license__
from ldap.controls import RequestControl, ResponseControl, KNOWN_RESPONSE_CONTROLS
import ldap

from ldap_types import *
from typing import Any, Dict, List, Type, Tuple

__all__ = [
    'SyncreplConsumer',
]


class SyncUUID(univ.OctetString):  # type: ignore
    """
    syncUUID ::= OCTET STRING (SIZE(16))
    """
    subtypeSpec = constraint.ValueSizeConstraint(16, 16)


class SyncCookie(univ.OctetString):  # type: ignore
    """
    syncCookie ::= OCTET STRING
    """


class SyncRequestMode(univ.Enumerated):  # type: ignore
    """
           mode ENUMERATED {
               -- 0 unused
               refreshOnly       (1),
               -- 2 reserved
               refreshAndPersist (3)
           },
    """
    namedValues = namedval.NamedValues(
        ('refreshOnly', 1),
        ('refreshAndPersist', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(1, 3)


class SyncRequestValue(univ.Sequence):  # type: ignore
    """
       syncRequestValue ::= SEQUENCE {
           mode ENUMERATED {
               -- 0 unused
               refreshOnly       (1),
               -- 2 reserved
               refreshAndPersist (3)
           },
           cookie     syncCookie OPTIONAL,
           reloadHint BOOLEAN DEFAULT FALSE
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mode', SyncRequestMode()),
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('reloadHint', univ.Boolean(False))
    )


class SyncRequestControl(RequestControl):
    """
    The Sync Request Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.1 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncRequestValue.  The criticality field is either TRUE or FALSE.
    [..]
    The Sync Request Control is only applicable to the SearchRequest
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.1'

    def __init__(
        self,
        criticality: int | bool = True,
        cookie: str | None = None,
        mode: str = 'refreshOnly',
        reloadHint: bool = False,
    ) -> None:
        if criticality:
            self.criticality = True
        else:
            self.criticality = False
        self.cookie = cookie
        self.mode = mode
        self.reloadHint = reloadHint

    def encodeControlValue(self) -> bytes:
        rcv = SyncRequestValue()
        rcv.setComponentByName('mode', SyncRequestMode(self.mode))
        if self.cookie is not None:
            rcv.setComponentByName('cookie', SyncCookie(self.cookie))
        if self.reloadHint:
            rcv.setComponentByName('reloadHint', univ.Boolean(self.reloadHint))
        return encoder.encode(rcv)  # type: ignore


class SyncStateOp(univ.Enumerated):  # type: ignore
    """
           state ENUMERATED {
               present (0),
               add (1),
               modify (2),
               delete (3)
           },
    """
    namedValues = namedval.NamedValues(
        ('present', 0),
        ('add', 1),
        ('modify', 2),
        ('delete', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(0, 1, 2, 3)


class SyncStateValue(univ.Sequence):  # type: ignore
    """
       syncStateValue ::= SEQUENCE {
           state ENUMERATED {
               present (0),
               add (1),
               modify (2),
               delete (3)
           },
           entryUUID syncUUID,
           cookie    syncCookie OPTIONAL
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('state', SyncStateOp()),
        namedtype.NamedType('entryUUID', SyncUUID()),
        namedtype.OptionalNamedType('cookie', SyncCookie())
    )


class SyncStateControl(ResponseControl):
    """
    The Sync State Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.2 and the
    controlValue, an OCTET STRING, contains a BER-encoded SyncStateValue.
    The criticality is FALSE.
    [..]
    The Sync State Control is only applicable to SearchResultEntry and
    SearchResultReference Messages.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.2'
    opnames = ('present', 'add', 'modify', 'delete')

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        d = decoder.decode(encodedControlValue, asn1Spec=SyncStateValue())
        state = d[0].getComponentByName('state')
        uuid = UUID(bytes=bytes(d[0].getComponentByName('entryUUID')))
        cookie = d[0].getComponentByName('cookie')
        if cookie is not None and cookie.hasValue():
            self.cookie: str | None = str(cookie)
        else:
            self.cookie = None
        self.state = self.__class__.opnames[int(state)]
        self.entryUUID = str(uuid)

KNOWN_RESPONSE_CONTROLS[SyncStateControl.controlType] = SyncStateControl


class SyncDoneValue(univ.Sequence):  # type: ignore
    """
       syncDoneValue ::= SEQUENCE {
           cookie          syncCookie OPTIONAL,
           refreshDeletes  BOOLEAN DEFAULT FALSE
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False))
    )


class SyncDoneControl(ResponseControl):
    """
    The Sync Done Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.3 and the
    controlValue contains a BER-encoded syncDoneValue.  The criticality
    is FALSE (and hence absent).
    [..]
    The Sync Done Control is only applicable to the SearchResultDone
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.3'

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        d = decoder.decode(encodedControlValue, asn1Spec=SyncDoneValue())
        cookie = d[0].getComponentByName('cookie')
        if cookie.hasValue():
            self.cookie: str | None = str(cookie)
        else:
            self.cookie = None
        refresh_deletes = d[0].getComponentByName('refreshDeletes')
        if refresh_deletes.hasValue():
            self.refreshDeletes = bool(refresh_deletes)
        else:
            self.refreshDeletes = False

KNOWN_RESPONSE_CONTROLS[SyncDoneControl.controlType] = SyncDoneControl


class RefreshDelete(univ.Sequence):  # type: ignore
    """
           refreshDelete  [1] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class RefreshPresent(univ.Sequence):  # type: ignore
    """
           refreshPresent [2] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class SyncUUIDs(univ.SetOf):  # type: ignore
    """
    syncUUIDs      SET OF syncUUID
    """
    componentType = SyncUUID()


class SyncIdSet(univ.Sequence):  # type: ignore
    """
     syncIdSet      [3] SEQUENCE {
         cookie         syncCookie OPTIONAL,
         refreshDeletes BOOLEAN DEFAULT FALSE,
         syncUUIDs      SET OF syncUUID
     }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False)),
        namedtype.NamedType('syncUUIDs', SyncUUIDs())
    )


class SyncInfoValue(univ.Choice):  # type: ignore
    """
       syncInfoValue ::= CHOICE {
           newcookie      [0] syncCookie,
           refreshDelete  [1] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
           refreshPresent [2] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
           syncIdSet      [3] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDeletes BOOLEAN DEFAULT FALSE,
               syncUUIDs      SET OF syncUUID
           }
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'newcookie',
            SyncCookie().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType(
            'refreshDelete',
            RefreshDelete().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.NamedType(
            'refreshPresent',
            RefreshPresent().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.NamedType(
            'syncIdSet',
            SyncIdSet().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
    )


class SyncInfoMessage:
    """
    The Sync Info Message is an LDAP Intermediate Response Message
    [RFC4511] where responseName is the object identifier
    1.3.6.1.4.1.4203.1.9.1.4 and responseValue contains a BER-encoded
    syncInfoValue.  The criticality is FALSE (and hence absent).
    """
    responseName = '1.3.6.1.4.1.4203.1.9.1.4'

    def __init__(self, encodedMessage: bytes) -> None:
        d = decoder.decode(encodedMessage, asn1Spec=SyncInfoValue())
        self.newcookie = None
        self.refreshDelete = None
        self.refreshPresent = None
        self.syncIdSet = None

        # Due to the way pyasn1 works, refreshDelete and refreshPresent are both
        # valid in the components as they are fully populated defaults. We must
        # get the component directly from the message, not by iteration.
        attr = d[0].getName()
        comp = d[0].getComponent()

        if comp is not None and comp.hasValue():
            if attr == 'newcookie':
                self.newcookie = str(comp)
                return

            val: Dict[str, str | bool | List[str]] = {}

            cookie = comp.getComponentByName('cookie')
            if cookie.hasValue():
                val['cookie'] = str(cookie)

            if attr.startswith('refresh'):
                val['refreshDone'] = bool(comp.getComponentByName('refreshDone'))
            elif attr == 'syncIdSet':
                uuids = []
                ids = comp.getComponentByName('syncUUIDs')
                for i in range(len(ids)):
                    uuid = UUID(bytes=bytes(ids.getComponentByPosition(i)))
                    uuids.append(str(uuid))
                val['syncUUIDs'] = uuids
                val['refreshDeletes'] = bool(comp.getComponentByName('refreshDeletes'))

            setattr(self, attr, val)


# FIXME: This class expects to be a subclass of ldap.ldapobject.*
class SyncreplConsumer():
    """
    SyncreplConsumer - LDAP syncrepl consumer object.
    """

    def syncrepl_search(
        self,
        base: str,
        scope: int,
        mode: str = 'refreshOnly',
        cookie: str | None = None,
        **search_args: Any,
    ) -> int:
        """
        Starts syncrepl search operation.

        base, scope, and search_args are passed along to
        self.search_ext unmodified (aside from adding a Sync
        Request control to any serverctrls provided).

        mode provides syncrepl mode. Can be 'refreshOnly'
        to finish after synchronization, or
        'refreshAndPersist' to persist (continue to
        receive updates) after synchronization.

        cookie: an opaque value representing the replication
        state of the client.  Subclasses should override
        the syncrepl_set_cookie() and syncrepl_get_cookie()
        methods to store the cookie appropriately, rather than
        passing it.

        Only a single syncrepl search may be active on a SyncreplConsumer
        object.  Multiple concurrent syncrepl searches require multiple
        separate SyncreplConsumer objects and thus multiple connections
        (LDAPObject instances).
        """
        if cookie is None:
            cookie = self.syncrepl_get_cookie()

        syncreq = SyncRequestControl(cookie=cookie, mode=mode)

        if 'serverctrls' in search_args:
            search_args['serverctrls'] += [syncreq]
        else:
            search_args['serverctrls'] = [syncreq]

        self.__refreshDone = False
        # FIXME: This assumes that we're subclassing LDAPObject
        return self.search_ext(base, scope, **search_args)  # type: ignore

    def syncrepl_poll(
        self,
        msgid: int = -1,
        timeout: int | None = None,
        all: int = 0,
    ) -> bool:
        """
        polls for and processes responses to the syncrepl_search() operation.
        Returns False when operation finishes, True if it is in progress, or
        raises an exception on error.

        If timeout is specified, raises ldap.TIMEOUT in the event of a timeout.

        If all is set to a nonzero value, poll() will return only when finished
        or when an exception is raised.

        """
        while True:
            # FIXME: This assumes that we're subclassing LDAPObject
            type, msg, mid, ctrls, n, v = self.result4(  # type: ignore
                msgid=msgid,
                timeout=timeout,
                add_intermediates=1,
                add_ctrls=1,
                all=0,
            )

            if type == 101:
                # search result. This marks the end of a refreshOnly session.
                # look for a SyncDone control, save the cookie, and if necessary
                # delete non-present entries.
                for c in ctrls or []:
                    if not isinstance(c, SyncDoneControl):
                        continue
                    self.syncrepl_present(None, refreshDeletes=c.refreshDeletes)
                    if c.cookie is not None:
                        self.syncrepl_set_cookie(c.cookie)

                return False

            elif type == 100:
                # search entry with associated SyncState control
                for m in msg or []:
                    dn, attrs, ctrls = m
                    for c in ctrls or []:
                        if not isinstance(c, SyncStateControl):
                            continue
                        if c.state == 'present':
                            self.syncrepl_present([c.entryUUID])
                        elif c.state == 'delete':
                            self.syncrepl_delete([c.entryUUID])
                        else:
                            self.syncrepl_entry(dn, attrs, c.entryUUID)
                            if self.__refreshDone is False:
                                self.syncrepl_present([c.entryUUID])
                        if c.cookie is not None:
                            self.syncrepl_set_cookie(c.cookie)
                        break

            elif type == 121:
                # Intermediate message. If it is a SyncInfoMessage, parse it
                for m in msg or []:
                    rname, resp, ctrls = m
                    if rname != SyncInfoMessage.responseName:
                        continue
                    sim = SyncInfoMessage(resp)
                    if sim.newcookie is not None:
                        self.syncrepl_set_cookie(sim.newcookie)
                    elif sim.refreshPresent is not None:
                        self.syncrepl_present(None, refreshDeletes=False)
                        if 'cookie' in sim.refreshPresent:
                            self.syncrepl_set_cookie(sim.refreshPresent['cookie'])
                        if sim.refreshPresent['refreshDone']:
                            self.__refreshDone = True
                            self.syncrepl_refreshdone()
                    elif sim.refreshDelete is not None:
                        self.syncrepl_present(None, refreshDeletes=True)
                        if 'cookie' in sim.refreshDelete:
                            self.syncrepl_set_cookie(sim.refreshDelete['cookie'])
                        if sim.refreshDelete['refreshDone']:
                            self.__refreshDone = True
                            self.syncrepl_refreshdone()
                    elif sim.syncIdSet is not None:
                        if sim.syncIdSet['refreshDeletes'] is True:
                            self.syncrepl_delete(sim.syncIdSet['syncUUIDs'])
                        else:
                            self.syncrepl_present(sim.syncIdSet['syncUUIDs'])
                        if 'cookie' in sim.syncIdSet:
                            self.syncrepl_set_cookie(sim.syncIdSet['cookie'])

            if all == 0:
                return True


    # virtual methods -- subclass must override these to do useful work

    def syncrepl_set_cookie(self, cookie: str) -> None:
        """
        Called by syncrepl_poll() to store a new cookie provided by the server.
        """
        # FIXME: The cookie is an opaque octet string, so the type should be bytes?
        pass

    def syncrepl_get_cookie(self) -> str:
        """
        Called by syncrepl_search() to retrieve the cookie stored by syncrepl_set_cookie()
        """
        # FIXME: The cookie is an opaque octet string, so the type should be bytes?
        return ''

    def syncrepl_present(
        self,
        uuids: List[str] | None,
        refreshDeletes: bool = False,
    ) -> None:
        """
        Called by syncrepl_poll() whenever entry UUIDs are presented to the client.
        syncrepl_present() is given a list of entry UUIDs (uuids) and a flag
        (refreshDeletes) which indicates whether the server explicitly deleted
        non-present entries during the refresh operation.

        If called with a list of uuids, the syncrepl_present() implementation
        should record those uuids as present in the directory.

        If called with uuids set to None and refreshDeletes set to False,
        syncrepl_present() should delete all non-present entries from the local
        mirror, and reset the list of recorded uuids.

        If called with uuids set to None and refreshDeletes set to True,
        syncrepl_present() should reset the list of recorded uuids, without
        deleting any entries.
        """
        pass

    def syncrepl_delete(self, uuids: List[str]) -> None:
        """
        Called by syncrepl_poll() to delete entries. A list
        of UUIDs of the entries to be deleted is given in the
        uuids parameter.
        """
        pass

    def syncrepl_entry(self, dn: str, attrs: LDAPEntryDict, uuid: str) -> None:
        """
        Called by syncrepl_poll() for any added or modified entries.

        The provided uuid is used to identify the provided entry in
        any future modification (including dn modification), deletion,
        and presentation operations.
        """
        pass

    def syncrepl_refreshdone(self) -> None:
        """
        Called by syncrepl_poll() between refresh and persist phase.

        It indicates that initial synchronization is done and persist phase
        follows.
        """
        pass
