# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2014, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import nfc.clf
from . import tt2

import os
import struct
from binascii import hexlify
from pyDes import triple_des, CBC

import logging
log = logging.getLogger(__name__)


class MifareUltralight(tt2.Type2Tag):
    """Mifare Ultralight is a simple type 2 tag with no specific
    features. It can store up to 46 byte NDEF message data. This class
    does not do much more than to provide the known memory size.

    """
    def __init__(self, clf, target):
        super(MifareUltralight, self).__init__(clf, target)
        self._product = "Mifare Ultralight (MF01CU1)"

    def dump(self):
        return super(MifareUltralight, self)._dump(stop=16)


class MifareUltralightC(tt2.Type2Tag):
    """Mifare Ultralight C provides more memory, to store up to 142 byte
    NDEF message data, and can be password protected.

    """
    class NDEF(tt2.Type2Tag.NDEF):
        def _read_capability_data(self, tag_memory):
            base_class = super(MifareUltralightC.NDEF, self)
            if base_class._read_capability_data(tag_memory):
                if self.tag.is_authenticated:
                    if not self._readable and tag_memory[15] >> 4 == 8:
                        self._readable = True
                    if not self._writeable and tag_memory[15] & 0xF == 8:
                        self._writeable = bool(tag_memory[10:12] == b"\0\0")
                return True
            return False

    def __init__(self, clf, target):
        super(MifareUltralightC, self).__init__(clf, target)
        self._product = "Mifare Ultralight C (MF01CU2)"

    def dump(self):
        lines = super(MifareUltralightC, self)._dump(stop=40)

        footer = dict(zip(range(40, 44), (
            "LOCK2-LOCK3", "CTR0-CTR1", "AUTH0", "AUTH1")))

        for i in sorted(footer.keys()):
            try:
                data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            lines.append(tt2.pagedump(i, data, footer[i]))

        return lines

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect a Mifare Ultralight C Tag.

        A Mifare Ultrlight C Tag can be provisioned with a custom
        password (or the default manufacturer key if the password is
        an empty string or bytearray).

        A non-empty *password* must provide at least 128 bit key
        material, in other words it must be a string or bytearray of
        length 16 or more.

        If *password* is not None, the first protected memory page can
        be specified with the *protect_from* integer argument. A
        memory page is 4 byte and the total number of pages is 48. A
        *protect_from* argument of 48 effectively disables memory
        protection. A *protect_from* argument of 3 protects all user
        data pages including the bitwise one-time-programmable page
        3. Any value less than 3 or more than 48 is accepted but to
        the same effect as if 3 or 48 were specified. If effective
        protection starts at page 3 and the tag is formatted for NDEF,
        the :meth:`protect` method does also modify the NDEF
        read/write capability byte.

        If *password* is not None and *read_protect* is True then the
        tag memory content will also be protected against read access,
        i.e. successful authentication will be required to read
        protected pages.

        The :meth:`protect` method verifies a password change by
        authenticating with the new *password* after all modifications
        were made and returns the result of :meth:`authenticate`.

        .. warning:: If protect is called without a password, the
            default Type 2 Tag protection method will set the lock
            bits to readonly. This process is not reversible.

        """
        args = (password, read_protect, protect_from)
        return super(MifareUltralightC, self).protect(*args)

    def _protect(self, password, read_protect, protect_from):
        if password is None:
            return self._protect_with_lockbits()
        else:
            args = (password, read_protect, protect_from)
            return self._protect_with_password(*args)

    def _protect_with_lockbits(self):
        try:
            ndef_cc = self.read(3)[0:4]
            if ndef_cc[0] == 0xE1 and ndef_cc[1] >> 4 == 1:
                ndef_cc[3] = 0x0F
                self.write(3, ndef_cc)
            self.write(2, b"\x00\x00\xFF\xFF")
            self.write(40, b"\xFF\xFF\x00\x00")
            return True
        except tt2.Type2TagCommandError:
            return False

    def _protect_with_password(self, password, read_protect, protect_from):
        if password and len(password) < 16:
            raise ValueError("password must be at least 16 byte")

        # The first 16 password character bytes are taken as key
        # unless the password is empty. If it's empty we use the
        # factory default password.
        key = password[0:16] if password != b"" else b"IEMKAERB!NACUOYF"
        log.debug("protect with key %s", hexlify(key).decode())

        # split the key and reverse
        key1, key2 = key[7::-1], key[15:7:-1]
        self.write(44, key1[0:4])
        self.write(45, key1[4:8])
        self.write(46, key2[0:4])
        self.write(47, key2[4:8])

        # protect from memory page
        self.write(42, bytearray([max(3, min(protect_from, 0x30))]) +
                   b"\0\0\0")

        # set read protection flag
        self.write(43, b"\0\0\0\0" if read_protect else b"\x01\0\0\0")

        # Set NDEF read/write permissions if protection starts at page
        # 3 and the tag is formatted for NDEF. We set the read/write
        # permission flags to 8, thus indicating proprietary access.
        if protect_from <= 3:
            ndef_cc = self.read(3)[0:4]
            if ndef_cc[0] == 0xE1 and ndef_cc[1] & 0xF0 == 0x10:
                ndef_cc[3] |= (0x88 if read_protect else 0x08)
                self.write(3, ndef_cc)

        # Reactivate the tag to have the key effective and
        # authenticate with the same key
        self._target = self.clf.sense(self.target)
        return self.authenticate(key) if self.target else False

    def authenticate(self, password):
        """Authenticate with a Mifare Ultralight C Tag.

        :meth:`autenticate` executes the Mifare Ultralight C mutual
        authentication protocol to verify that the *password* argument
        matches the key that is stored in the card. A new card key can
        be set with :meth:`protect`.

        The *password* argument must be a string with either 0 or at
        least 16 bytes. A zero length password string indicates that
        the factory default card key be used. From a password with 16
        or more bytes the first 16 byte are taken as card key,
        remaining bytes are ignored. A password length between 1 and
        15 generates a ValueError exception.

        The authentication result is True if the password was
        confirmed and False if not.

        """
        return super(MifareUltralightC, self).authenticate(password)

    def _authenticate(self, password):
        # The first 16 password character bytes are taken as key
        # unless the password is empty. If it's empty we use the
        # factory default password.
        key = password[0:16] if password != b"" else b"IEMKAERB!NACUOYF"

        if len(key) != 16:
            raise ValueError("password must be at least 16 byte")

        log.debug("authenticate with key %s", hexlify(key).decode())

        rsp = self.transceive(b"\x1A\x00")
        m1 = bytes(rsp[1:9])
        iv = b"\x00\x00\x00\x00\x00\x00\x00\x00"
        rb = triple_des(key, CBC, iv).decrypt(m1)

        log.debug("received challenge")
        log.debug("iv = %s", hexlify(iv).decode())
        log.debug("m1 = %s", hexlify(m1).decode())
        log.debug("rb = %s", hexlify(rb).decode())

        ra = os.urandom(8)
        iv = bytes(rsp[1:9])

        m2 = triple_des(key, CBC, iv).encrypt(ra + rb[1:8] + (
            struct.pack("B", rb[0]) if isinstance(rb[0], int) else rb[0]))

        log.debug("sending response")
        log.debug("ra = %s", hexlify(ra).decode())
        log.debug("iv = %s", hexlify(iv).decode())
        log.debug("m2 = %s", hexlify(m2).decode())
        try:
            rsp = self.transceive(b"\xAF" + m2)
        except tt2.Type2TagCommandError:
            return False

        m3 = bytes(rsp[1:9])
        iv = m2[8:16]
        log.debug("received confirmation")
        log.debug("iv = %s", hexlify(iv).decode())
        log.debug("m3 = %s", hexlify(m3).decode())

        return triple_des(key, CBC, iv).decrypt(m3) == ra[1:9] \
            + (struct.pack("B", ra[0]) if isinstance(ra[0], int) else ra[0])


class NTAG203(tt2.Type2Tag):
    """The NTAG203 is a plain memory Tag with 144 bytes user data memory
    plus a 16-bit one-way counter. It does not have any security
    features beyond the standard lock bit mechanism that permanently
    disables write access.

    """
    def __init__(self, clf, target):
        super(NTAG203, self).__init__(clf, target)
        self._product = "NXP NTAG203"

    def dump(self):
        lines = super(NTAG203, self)._dump(40)

        footer = dict(zip(range(40, 42), ("LOCK2-LOCK3", "CNTR0-CNTR1")))

        for i in sorted(footer.keys()):
            try:
                data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            lines.append(tt2.pagedump(i, data, footer[i]))

        return lines

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Set lock bits to disable future memory modifications.

        If *password* is None, all memory pages except the 16-bit
        counter in page 41 are protected by setting the relevant lock
        bits (note that lock bits can not be reset). If valid NDEF
        management data is found in page 4, protect() also sets the
        NDEF write flag to read-only.

        The NTAG203 can not be password protected. If a *password*
        argument is provided, the protect() method always returns
        False.

        """
        return super(NTAG203, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if password is None:
            try:
                ndef_cc = self.read(3)[0:4]
                if ndef_cc[0] == 0xE1 and ndef_cc[1] >> 4 == 1:
                    ndef_cc[3] = 0x0F
                    self.write(3, ndef_cc)
                self.write(2, b"\x00\x00\xFF\xFF")
                self.write(40, b"\xFF\x01\x00\x00")
                return True
            except tt2.Type2TagCommandError:
                pass
        return False

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x01\x03\xA0\x10')
            self.write(5, b'\x44\x03\x00\xFE')
        return super(NTAG203, self)._format(version, wipe)


class NTAG21x(tt2.Type2Tag):
    """Base class for the NTAG21x family (210/212/213/215/216). The
    methods and attributes documented here are supported for all
    NTAG21x products.

    All NTAG21x products support a simple password protection scheme
    that can be configured to restrict write as well as read access to
    memory starting from a selected page address. A factory programmed
    ECC signature allows to verify the tag unique identifier.

    """
    class NDEF(tt2.Type2Tag.NDEF):
        def _read_capability_data(self, tag_memory):
            if super(NTAG21x.NDEF, self)._read_capability_data(tag_memory):
                if self.tag.is_authenticated:
                    if not self._readable and tag_memory[15] >> 4 == 8:
                        self._readable = True
                    if not self._writeable and tag_memory[15] & 0xF == 8:
                        self._writeable = bool(tag_memory[10:12] == b"\0\0")
                return True
            return False

    @property
    def signature(self):
        """The 32-byte ECC tag signature programmed at chip production. The
        signature is provided as a string and can only be read.

        The signature attribute is always loaded from the tag when it
        is accessed, i.e. it is not cached. If communication with the
        tag fails for some reason the signature attribute is set to a
        32-byte string of all zeros.

        """
        log.debug("read tag signature")
        try:
            return bytes(self.transceive(b"\x3C\x00"))
        except tt2.Type2TagCommandError:
            return 32 * b"\0"

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Set password protection or permanent lock bits.

        If the *password* argument is None, all memory pages will be
        protected by setting the relevant lock bits (note that lock
        bits can not be reset). If valid NDEF management data is
        found, protect() also sets the NDEF write flag to read-only.

        All Tags of the NTAG21x family can alternatively be protected
        by password. If a *password* argument is provided, the
        protect() method writes the first 4 byte of the *password*
        string into the Tag's password (PWD) memory bytes and the
        following 2 byte of the *password* string into the password
        acknowledge (PACK) memory bytes. Factory default values are
        used if the *password* argument is an empty string. Lock bits
        are not set for password protection.

        The *read_protect* and *protect_from* arguments are only
        evaluated if *password* is not None. If *read_protect* is
        True, the memory protection bit (PROT) is set to require
        password verification also for reading of protected memory
        pages. The value of *protect_from* determines the first
        password protected memory page (one page is 4 byte) with the
        exception that the smallest set value is page 3 even if
        *protect_from* is smaller.

        """
        args = (password, read_protect, protect_from)
        return super(NTAG21x, self).protect(*args)

    def _protect(self, password, read_protect, protect_from):
        if password is None:
            return self._protect_with_lockbits()
        else:
            args = (password, read_protect, protect_from)
            return self._protect_with_password(*args)

    def _protect_with_lockbits(self):
        try:
            ndef_cc = self.read(3)[0:4]
            if ndef_cc[0] == 0xE1 and ndef_cc[1] >> 4 == 1:
                ndef_cc[3] = 0x0F
                self.write(3, ndef_cc)
            self.write(2, b"\x00\x00\xFF\xFF")
            if self._cfgpage > 16:
                self.write(self._cfgpage - 1, b"\xFF\xFF\xFF\x00")
            cfgdata = self.read(self._cfgpage)
            if cfgdata[4] & 0x40 == 0:
                cfgdata[4] |= 0x40  # set CFGLCK bit
                self.write(self._cfgpage + 1, cfgdata[4:8])
            return True
        except tt2.Type2TagCommandError:
            return False

    def _protect_with_password(self, password, read_protect, protect_from):
        if password and len(password) < 6:
            raise ValueError("password must be at least 6 bytes")

        key = password[0:6] if password != b"" else b"\xFF\xFF\xFF\xFF\0\0"
        log.debug("protect with key %s", hexlify(key).decode())

        # read CFG0, CFG1, PWD and PACK
        cfg = self.read(self._cfgpage)

        # set password and acknowledge
        cfg[8:14] = key

        # start protection from page
        cfg[3] = max(3, min(protect_from, 255))

        # set read protection bit
        cfg[4] = cfg[4] | 0x80 if read_protect else cfg[4] & 0x7F

        # write configuration to tag
        for i in range(4):
            self.write(self._cfgpage + i, cfg[i*4:(i+1)*4])

        # Set NDEF read/write permissions if protection starts at page
        # 3 and the tag is formatted for NDEF. We set the read/write
        # permission flags to 8, thus indicating proprietary access.
        if protect_from <= 3:
            ndef_cc = self.read(3)[0:4]
            if ndef_cc[0] == 0xE1 and ndef_cc[1] & 0xF0 == 0x10:
                ndef_cc[3] |= (0x88 if read_protect else 0x08)
                self.write(3, ndef_cc)

        # Reactivate the tag to have the key effective and
        # authenticate with the same key
        self._target = self.clf.sense(self.target)
        return self.authenticate(key) if self.target else False

    def authenticate(self, password):
        """Authenticate with password to access protected memory.

        An NTAG21x implements a simple password protection scheme. The
        reader proofs possession of a share secret by sending a 4-byte
        password and the tag proofs possession of a shared secret by
        returning a 2-byte password acknowledge. Because password and
        password acknowledge are transmitted in plain text special
        considerations should be given to under which conditions
        authentication is performed. If, for example, an attacker is
        able to mount a relay attack both secret values are easily
        lost.

        The *password* argument must be a string of length zero or at
        least 6 byte characters. If the *password* length is zero,
        authentication is performed with factory default values. If
        the *password* contains at least 6 bytes, the first 4 byte are
        send to the tag as the password secret and the following 2
        byte are compared against the password acknowledge that is
        received from the tag.

        The authentication result is True if the password was
        confirmed and False if not.

        """
        return super(NTAG21x, self).authenticate(password)

    def _authenticate(self, password):
        if password and len(password) < 6:
            raise ValueError("password must be at least 6 bytes")

        key = password[0:6] if password != b"" else b"\xFF\xFF\xFF\xFF\0\0"
        log.debug("authenticate with key %s", hexlify(key).decode())

        try:
            rsp = self.transceive(b"\x1B" + key[0:4])
            return rsp == key[4:6]
        except tt2.Type2TagCommandError:
            return False

    def _dump(self, stop, footer):
        lines = super(NTAG21x, self)._dump(stop)
        for i in sorted(footer.keys()):
            try:
                data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            lines.append(tt2.pagedump(i, data, footer[i]))
        return lines


class NTAG210(NTAG21x):
    """The NTAG210 provides 48 bytes user data memory, password
    protection, originality signature and a UID mirror function.

    """
    def __init__(self, clf, target):
        super(NTAG210, self).__init__(clf, target)
        self._product = "NXP NTAG210"
        self._cfgpage = 16

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x03\x00\xFE\x00')
            self.write(5, b'\x00\x00\x00\x00')
        return super(NTAG210, self)._format(version, wipe)

    def dump(self):
        footer = dict(zip(range(16, 20),
                          ("MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0",
                           "ACCESS", "PWD0-PWD3", "PACK0-PACK1")))
        return super(NTAG210, self)._dump(16, footer)


class NTAG212(NTAG21x):
    """The NTAG212 provides 128 bytes user data memory, password
    protection, originality signature and a UID mirror function.

    """
    def __init__(self, clf, target):
        super(NTAG212, self).__init__(clf, target)
        self._product = "NXP NTAG212"
        self._cfgpage = 37

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x01\x03\x90\x0A')
            self.write(5, b'\x34\x03\x00\xFE')
        return super(NTAG212, self)._format(version, wipe)

    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(36, 36+len(text)), text))
        return super(NTAG212, self)._dump(36, footer)


class NTAG213(NTAG21x):
    """The NTAG213 provides 144 bytes user data memory, password
    protection, originality signature, a tag read counter and a mirror
    function for the tag unique identifier and the read counter.

    """
    def __init__(self, clf, target):
        super(NTAG213, self).__init__(clf, target)
        self._product = "NXP NTAG213"
        self._cfgpage = 41

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x01\x03\xA0\x0C')
            self.write(5, b'\x34\x03\x00\xFE')
        return super(NTAG213, self)._format(version, wipe)

    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(40, 40+len(text)), text))
        return super(NTAG213, self)._dump(40, footer)


class NTAG215(NTAG21x):
    """The NTAG215 provides 504 bytes user data memory, password
    protection, originality signature, a tag read counter and a mirror
    function for the tag unique identifier and the read counter.

    """
    def __init__(self, clf, target):
        super(NTAG215, self).__init__(clf, target)
        self._product = "NXP NTAG215"
        self._cfgpage = 131

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x03\x00\xFE\x00')
            self.write(5, b'\x00\x00\x00\x00')
        return super(NTAG215, self)._format(version, wipe)

    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(130, 130+len(text)), text))
        return super(NTAG215, self)._dump(130, footer)


class NTAG216(NTAG21x):
    """The NTAG216 provides 888 bytes user data memory, password
    protection, originality signature, a tag read counter and a mirror
    function for the tag unique identifier and the read counter.

    """
    def __init__(self, clf, target):
        super(NTAG216, self).__init__(clf, target)
        self._product = "NXP NTAG216"
        self._cfgpage = 227

    def _format(self, version, wipe):
        if self.ndef is None:
            log.debug("no management data, writing factory defaults")
            self.write(4, b'\x03\x00\xFE\x00')
            self.write(5, b'\x00\x00\x00\x00')
        return super(NTAG216, self)._format(version, wipe)

    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(226, 226+len(text)), text))
        return super(NTAG216, self)._dump(226, footer)


class MifareUltralightEV1(NTAG21x):
    """Mifare Ultralight EV1

    """
    def __init__(self, clf, target, product):
        super(MifareUltralightEV1, self).__init__(clf, target)
        self._product = "Mifare Ultralight EV1 ({0})".format(product)

    def _dump_ul11(self):
        text = ("MOD, RFU, RFU, AUTH0", "ACCESS, VCTID, RFU, RFU",
                "PWD0, PWD1, PWD2, PWD3", "PACK0, PACK1, RFU, RFU")
        footer = dict(zip(range(16, 16+len(text)), text))
        return super(MifareUltralightEV1, self)._dump(16, footer)

    def _dump_ul21(self):
        text = ("LOCK2, LOCK3, LOCK4, RFU",
                "MOD, RFU, RFU, AUTH0", "ACCESS, VCTID, RFU, RFU",
                "PWD0, PWD1, PWD2, PWD3", "PACK0, PACK1, RFU, RFU")
        footer = dict(zip(range(36, 36+len(text)), text))
        return super(MifareUltralightEV1, self)._dump(36, footer)


class MF0UL11(MifareUltralightEV1):
    def __init__(self, clf, target):
        super(MF0UL11, self).__init__(clf, target, "MF0UL11")

    def dump(self):
        return self._dump_ul11()


class MF0ULH11(MifareUltralightEV1):
    def __init__(self, clf, target):
        super(MF0ULH11, self).__init__(clf, target, "MF0ULH11")

    def dump(self):
        return self._dump_ul11()


class MF0UL21(MifareUltralightEV1):
    def __init__(self, clf, target):
        super(MF0UL21, self).__init__(clf, target, "MF0UL21")

    def dump(self):
        return self._dump_ul21()


class MF0ULH21(MifareUltralightEV1):
    def __init__(self, clf, target):
        super(MF0ULH21, self).__init__(clf, target, "MF0ULH21")

    def dump(self):
        return self._dump_ul21()


class NTAGI2C(tt2.Type2Tag):
    def _dump(self, stop):
        s = super(NTAGI2C, self)._dump(stop)

        data = self.read(stop)[0:4]
        s.append(tt2.pagedump(stop, data, "LOCK2-LOCK4, CHK"))

        data = self.read(232)
        s.append("")
        s.append("Configuration registers:")
        s.append(tt2.pagedump(stop & 256 | 232, data[0:4],
                              "NC, LD, SM, WDT0"))
        s.append(tt2.pagedump(stop & 256 | 233, data[4:8],
                              "WDT1, CLK, LOCK, RFU"))

        self.sector_select(3)
        data = self.read(248)
        s.append("")
        s.append("Session registers:")
        s.append(tt2.pagedump(0x3F8, data[0:4], "NC, LD, SM, WDT0"))
        s.append(tt2.pagedump(0x3F9, data[4:8], "WDT1, CLK, NS, RFU"))

        self.sector_select(0)
        return s


class NT3H1101(NTAGI2C):
    """NTAG I2C 1K.

    """
    def __init__(self, clf, target):
        super(NT3H1101, self).__init__(clf, target)
        self._product = "NTAG I2C 1K (NT3H1101)"

    def dump(self):
        return super(NT3H1101, self)._dump(226)


class NT3H1201(NTAGI2C):
    """NTAG I2C 2K.

    """
    def __init__(self, clf, target):
        super(NT3H1201, self).__init__(clf, target)
        self._product = "NTAG I2C 2K (NT3H1201)"

    def dump(self):
        return super(NT3H1201, self)._dump(480)


VERSION_MAP = {
    b"\x00\x04\x03\x01\x01\x00\x0B\x03": MF0UL11,
    b"\x00\x04\x03\x02\x01\x00\x0B\x03": MF0ULH11,
    b"\x00\x04\x03\x01\x01\x00\x0E\x03": MF0UL21,
    b"\x00\x04\x03\x02\x01\x00\x0E\x03": MF0ULH21,
    b"\x00\x04\x04\x01\x01\x00\x0B\x03": NTAG210,
    b"\x00\x04\x04\x01\x01\x00\x0E\x03": NTAG212,
    b"\x00\x04\x04\x02\x01\x00\x0F\x03": NTAG213,
    b"\x00\x04\x04\x02\x01\x00\x11\x03": NTAG215,
    b"\x00\x04\x04\x02\x01\x00\x13\x03": NTAG216,
    b"\x00\x04\x04\x05\x02\x01\x13\x03": NT3H1101,
    b"\x00\x04\x04\x05\x02\x01\x15\x03": NT3H1201,
    # b"\x00\x04\x04\x05\x02\x02\x13\x03": NT3H2111,
    # b"\x00\x04\x04\x05\x02\x02\x15\x03": NT3H2211,
}


def activate(clf, target):
    log.debug("check if authenticate command is available")
    try:
        rsp = clf.exchange(b'\x1A\x00', timeout=0.01)
        if clf.sense(target) is None:
            return
        if rsp.startswith(b"\xAF"):
            return MifareUltralightC(clf, target)
    except nfc.clf.TimeoutError:
        if clf.sense(target) is None:
            return
    except nfc.clf.CommunicationError as error:
        log.debug(repr(error))
        return

    log.debug("check if version command is available")
    try:
        rsp = bytes(clf.exchange(b'\x60', timeout=0.01))
        if rsp in VERSION_MAP:
            return VERSION_MAP[rsp](clf, target)
        if rsp == b"\x00":
            if clf.sense(target) is None:
                return None
            else:
                return NTAG203(clf, target)
        log.debug("no match for version %s", hexlify(rsp).decode().upper())
        return
    except nfc.clf.TimeoutError:
        if clf.sense(target) is None:
            return
    except nfc.clf.CommunicationError as error:
        log.debug(repr(error))
        return

    return MifareUltralight(clf, target)
