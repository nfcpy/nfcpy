# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

import logging
log = logging.getLogger(__name__)

import os

import nfc.tag
from . import tt2

def activate(clf, target):
    try:
        log.debug("check if authenticate command is available")
        rsp = clf.exchange('\x1A\x00', timeout=0.01)
        clf.sense([nfc.clf.TTA(uid=target.uid)])
        clf.set_communication_mode('', check_crc='OFF')
        if rsp.startswith("\xAF"):
            return MifareUltralightC(clf, target)
        if rsp == "\x00":
            return NTAG203(clf, target)
    except nfc.clf.TimeoutError:
        log.debug("nope, authenticate command is not supported")

    clf.sense([nfc.clf.TTA(uid=target.uid)])
    clf.set_communication_mode('', check_crc='OFF')

    try:
        log.debug("check if version command is available")
        version = clf.exchange('\x60', timeout=0.01)
        log.debug("version = " + ' '.join(["%02X" % x for x in version]))
        if version[0:3] == "\x00\x04\x03" and version[4] == 0x01:
            return MifareUltralightEV1(clf, target, version)
        elif version.startswith("\x00\x04\x04\x01\x01\x00\x0B\x03"):
            return NTAG210(clf, target)
        elif version.startswith("\x00\x04\x04\x01\x01\x00\x0E\x03"):
            return NTAG212(clf, target)
        elif version.startswith("\x00\x04\x04\x02\x01\x00\x0F\x03"):
            return NTAG213(clf, target)
        elif version.startswith("\x00\x04\x04\x02\x01\x00\x11\x03"):
            return NTAG215(clf, target)
        elif version.startswith("\x00\x04\x04\x02\x01\x00\x13\x03"):
            return NTAG216(clf, target)
        else:
            log.debug("no match for this version number")
    except nfc.clf.TimeoutError:
        log.debug("nope, version command is not supported")

    clf.sense([nfc.clf.TTA(uid=target.uid)])
    clf.set_communication_mode('', check_crc='OFF')

    return MifareUltralight(clf, target)

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
    def __init__(self, clf, target):
        super(MifareUltralightC, self).__init__(clf, target)
        self._product = "Mifare Ultralight C (MF01CU2)"
        
    def dump(self):
        oprint = lambda o: ' '.join(['??' if x < 0 else '%02x'%x for x in o])
        s = super(MifareUltralightC, self)._dump(stop=40)
        
        footer = dict(zip(range(40, 44), (
            "LOCK2-LOCK3", "CTR0-CTR1", "AUTH0", "AUTH1")))
        
        for i in sorted(footer.keys()):
            try: data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            s.append("{0:3}: {1} ({2})".format(i, oprint(data), footer[i]))

        return s

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect a Mifare Ultralight C Tag.

        A Mifare Ultrlight C Tag can be provisioned with a custom
        password (or the default manufacturer key if the password is
        an empty string or bytearray). Read protection is not
        supported.
        
        A non-empty *password* must provide at least 128 bit key
        material, in other words it must be a string or bytearray of
        length 16 or more.
        
        The memory unit for the value of *protect_from* is 16 byte,
        thus with ``protect_from=2`` bytes 0 to 31 are not protected.

        .. warning:: If protect is called without a password, the
            default Type 2 Tag protection method will set the lock
            bits to readonly. This process is not reversible.

        """
        return super(MifareUltralightC, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        assert protect_from >= 0
        
        if password is not None:
            # The first 16 password character bytes are taken as key
            # unless the password is empty. If it's empty we use the
            # factory default password.
            key = password[0:16] if password != "" else "IEMKAERB!NACUOYF"
            
            if len(key) != 16:
                raise ValueError("password must be at least 16 byte")
            
            log.debug("protect with key " + key.encode("hex"))
            
            # split the key and reverse
            key1, key2 = key[7::-1], key[15:7:-1]
            self.write(44, key1[0:4])
            self.write(45, key1[4:8])
            self.write(46, key2[0:4])
            self.write(47, key2[4:8])
            
            # protect from memory page
            self.write(42, chr(max(3, min(protect_from, 0x30))) + "\0\0\0")
            
            # set or unset read protection
            self.write(43, "\0\0\0\0" if read_protect else "\x01\0\0\0")
            return True
        else:
            return super(MifareUltralightC, self)._protect(
                password, read_protect, protect_from)

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
        from pyDes import triple_des, CBC

        # The first 16 password character bytes are taken as key
        # unless the password is empty. If it's empty we use the
        # factory default password.
        key = password[0:16] if password != "" else "IEMKAERB!NACUOYF"
        
        if len(key) != 16:
            raise ValueError("password must be at least 16 byte")
        
        log.debug("authenticate with key " + str(key).encode("hex"))
        
        rsp = self.transceive("\x1A\x00", rlen=9)
        m1 = str(rsp[1:9])
        iv = "\x00\x00\x00\x00\x00\x00\x00\x00"
        rb = triple_des(key, CBC, iv).decrypt(m1)
        
        log.debug("received challenge")
        log.debug("iv = " + str(iv).encode("hex"))
        log.debug("m1 = " + str(m1).encode("hex"))
        log.debug("rb = " + str(rb).encode("hex"))
        
        ra = os.urandom(8)
        iv = str(rsp[1:9])
        m2 = triple_des(key, CBC, iv).encrypt(ra + rb[1:8] + rb[0])
        
        log.debug("sending response")
        log.debug("ra = " + str(ra).encode("hex"))
        log.debug("iv = " + str(iv).encode("hex"))
        log.debug("m2 = " + str(m2).encode("hex"))
        try:
            rsp = self.transceive("\xAF" + m2, rlen=9)
        except tt2.Type2TagCommandError:
            return False
        
        m3 = str(rsp[1:9])
        iv = m2[8:16]
        log.debug("received confirmation")
        log.debug("iv = " + str(iv).encode("hex"))
        log.debug("m3 = " + str(m3).encode("hex"))

        return triple_des(key, CBC, iv).decrypt(m3) == ra[1:9] + ra[0]
        
class MifareUltralightEV1(tt2.Type2Tag):
    def __init__(self, clf, target):
        super(MifareUltralightEV1, self).__init__(clf, target)
        self._product = "Mifare Ultralight EV1"
        version_map = {
            "\x00\x04\x03\x01\x01\x00\x0B\x03": "MF0UL11",
            "\x00\x04\x03\x02\x01\x00\x0B\x03": "MF0ULH11",
            "\x00\x04\x03\x01\x01\x00\x0E\x03": "MF0UL21",
            "\x00\x04\x03\x02\x01\x00\x0E\x03": "MF0ULH21",
        }
        try:
            self._product += " ({0})".format(version_map[version])
        except KeyError: pass

    @property
    def signature(self):
        log.debug("tag signature")
        return self.transceive("\x3C\x00", rlen=32)

class NTAG203(tt2.Type2Tag):
    def __init__(self, clf, target):
        super(NTAG203, self).__init__(clf, target)
        self._product = "NXP NTAG203"
        
    def dump(self):
        oprint = lambda o: ' '.join(['??' if x < 0 else '%02x'%x for x in o])
        s = super(NTAG203, self)._dump(40)

        footer = dict(zip(range(40, 42), ("LOCK2-LOCK3", "CNTR0-CNTR1")))
        
        for i in sorted(footer.keys()):
            try:
                data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            s.append("{0:3}: {1} ({2})".format(i, oprint(data), footer[i]))

        return s
    
class NTAG21x(tt2.Type2Tag):
    @property
    def signature(self):
        log.debug("tag signature")
        return self.transceive("\x3C\x00", rlen=32)

    def authenticate(self, password):
        if password == "":
            # try with the factory key
            key = bytearray.fromhex("FF FF FF FF 00 00")
        else:
            key = bytearray(password[0:6])
            assert len(key) == 6
        
        log.debug("authenticate with key " + str(key).encode("hex"))
        try:
            rsp = self.transceive("\x1b" + key[0:4], rlen=2)
            return rsp == key[4:6]
        except nfc.clf.TimeoutError:
            return False

    def protect(self, password=None, read_protect=False, protect_from=0):
        assert protect_from >= 0
        log.debug("protect tag")
        if password is not None:
            if password == "":
                # try with the factory key
                key = bytearray.fromhex("FF FF FF FF 00 00")
            else:
                key = bytearray(password[0:6])
                assert len(key) == 6
        
            log.debug("protect with key " + str(key).encode("hex"))

            cfgaddr = self._usermem.stop + (0, 4)[self._usermem.stop > 64]
            # write PWD and PACK
            for i in range(6):
                self[cfgaddr+8+i] = key[i]
            # start protection from page
            self[cfgaddr+3] = min(protect_from, 255)
            # set/clear protection bit
            self[cfgaddr+4] = (self[cfgaddr+4] & 0x7F) | (read_protect << 7)
            self.synchronize()
            return True
        return False

    def _dump(self, stop, footer):
        oprint = lambda o: ' '.join(['??' if x < 0 else '%02x'%x for x in o])
        s = super(NTAG21x, self)._dump(stop)
        for i in sorted(footer.keys()):
            try:
                data = self.read(i)[0:4]
            except tt2.Type2TagCommandError:
                data = [None, None, None, None]
            s.append("{0:3}: {1} ({2})".format(i, oprint(data), footer[i]))
        return s

class NTAG210(NTAG21x):
    def __init__(self, clf, target):
        super(NTAG210, self).__init__(clf, target)
        self._product = "NXP NTAG210"
        
    def dump(self):
        footer = dict(zip(range(16, 20),
                          ("MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0",
                           "ACCESS", "PWD0-PWD3", "PACK0-PACK1")))
        return super(NTAG210, self)._dump(16, footer)

class NTAG212(NTAG21x):
    def __init__(self, clf, target):
        super(NTAG212, self).__init__(clf, target)
        self._product = "NXP NTAG212"
        
    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR_BYTE, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(36, 36+len(text)), text))
        return super(NTAG212, self)._dump(36, footer)

class NTAG213(NTAG21x):
    def __init__(self, clf, target):
        super(NTAG213, self).__init__(clf, target)
        self._product = "NXP NTAG213"
        
    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(40, 40+len(text)), text))
        return super(NTAG213, self)._dump(40, footer)

class NTAG215(NTAG21x):
    def __init__(self, clf, target):
        super(NTAG215, self).__init__(clf, target)
        self._product = "NXP NTAG215"
        
    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(130, 130+len(text)), text))
        return super(NTAG215, self)._dump(130, footer)

class NTAG216(NTAG21x):
    def __init__(self, clf, target):
        super(NTAG216, self).__init__(clf, target)
        self._product = "NXP NTAG216"

    def dump(self):
        text = ("LOCK2-LOCK4", "MIRROR, RFU, MIRROR_PAGE, AUTH0",
                "ACCESS", "PWD0-PWD3", "PACK0-PACK1")
        footer = dict(zip(range(226, 226+len(text)), text))
        return super(NTAG216, self)._dump(226, footer)
