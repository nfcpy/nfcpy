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
from . import tt1

import logging
log = logging.getLogger(__name__)


class Topaz(tt1.Type1Tag):
    """The Broadcom Topaz is a small memory tag that can hold up to 94
    byte ndef message data.

    """
    def __init__(self, clf, target):
        super(Topaz, self).__init__(clf, target)
        self._product = "Topaz (BCM20203T96)"

    def dump(self):
        return super(Topaz, self)._dump(stop=15)

    def format(self, version=None, wipe=None):
        """Format a Topaz tag for NDEF use.

        The implementation of :meth:`nfc.tag.Tag.format` for a Topaz
        tag creates a capability container and an NDEF TLV with length
        zero. Data bytes of the NDEF data area are left untouched
        unless the wipe argument is set.

        """
        return super(Topaz, self).format(version, wipe)

    def _format(self, version, wipe):
        tag_memory = tt1.Type1TagMemoryReader(self)
        tag_memory[8:14] = b"\xE1\x10\x0E\x00\x03\x00"

        if version is not None:
            if version >> 4 == 1:
                tag_memory[9] = version
            else:
                log.warning("can not format with major version != 1")
                return False

        if wipe is not None:
            tag_memory[14:104] = bytearray([wipe & 0xFF]) * 90

        tag_memory.synchronize()
        return True

    def protect(self, password=None, read_protect=False, protect_from=0):
        """In addtion to :meth:`nfc.tag.tt1.Type1Tag.protect` this method
        tries to set the lock bits to irreversibly protect the tag
        memory. However, it appears that tags sold have the lock bytes
        write protected, so this additional effort most likely doesn't
        have any effect.

        """
        return super(Topaz, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if super(Topaz, self)._protect(password, read_protect, protect_from):
            self.write_byte(112, 0xFF, erase=False)
            self.write_byte(113, 0xFF, erase=False)
            return True
        else:
            return False


class Topaz512(tt1.Type1Tag):
    """The Broadcom Topaz-512 is a memory enhanced version that can hold
    up to 462 byte ndef message data.

    """
    def __init__(self, clf, target):
        super(Topaz512, self).__init__(clf, target)
        self._product = "Topaz 512 (BCM20203T512)"

    def dump(self):
        return super(Topaz512, self)._dump(stop=64)

    def format(self, version=None, wipe=None):
        """Format a Topaz-512 tag for NDEF use.

        The implementation of :meth:`nfc.tag.Tag.format` for a
        Topaz-512 tag creates a capability container, a Lock Control
        and a Memory Control TLV, and an NDEF TLV with length
        zero. Data bytes of the NDEF data area are left untouched
        unless the wipe argument is set.

        """
        return super(Topaz512, self).format(version, wipe)

    def _format(self, version, wipe):
        tag_memory = tt1.Type1TagMemoryReader(self)
        tag_memory[8:16] = bytearray.fromhex("E1103F000103F230")
        tag_memory[16:24] = bytearray.fromhex("330203F002030300")

        if version is not None:
            if version >> 4 == 1:
                tag_memory[9] = version
            else:
                log.warning("can not format with major version != 1")
                return False

        if wipe is not None:
            tag_memory[24:104] = bytearray([wipe & 0xFF]) * 80
            tag_memory[128:512] = bytearray([wipe & 0xFF]) * 384

        tag_memory.synchronize()
        return True

    def protect(self, password=None, read_protect=False, protect_from=0):
        """In addtion to :meth:`nfc.tag.tt1.Type1Tag.protect` this method
        tries to set the lock bits to irreversibly protect the tag
        memory. However, it appears that tags sold have the lock bytes
        write protected, so this additional effort most likely doesn't
        have any effect.

        """
        return super(Topaz512, self).protect(
            password, read_protect, protect_from)

    def _protect(self, password, read_protect, protect_from):
        if super(Topaz512, self)._protect(
                password, read_protect, protect_from):
            self.write_byte(112, 0xFF, erase=False)
            self.write_byte(113, 0xFF, erase=False)
            self.write_byte(120, 0xFF, erase=False)
            self.write_byte(121, 0xFF, erase=False)
            return True
        else:
            return False


def activate(clf, target):
    hrom = target.rid_res[0:2]
    if hrom == b"\x11\x48":
        return Topaz(clf, target)
    if hrom == b"\x12\x4C":
        return Topaz512(clf, target)
