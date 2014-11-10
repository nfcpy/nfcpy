# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2014 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import nfc.tag
from . import tt2

NTAG_VERSION_MAP = {
    "\x00\x04\x04\x01\x01\x00\x0B\x03": "NTAG210",
    "\x00\x04\x04\x01\x01\x00\x0E\x03": "NTAG212",
    "\x00\x04\x04\x02\x01\x00\x0F\x03": "NTAG213",
    "\x00\x04\x04\x02\x01\x00\x11\x03": "NTAG215",
    "\x00\x04\x04\x02\x01\x00\x13\x03": "NTAG216",
}

class ConfigData:
    def __init__(self, offset):
        self.CONFIG = offset
        self.MIRROR = offset
        self.M_PAGE = offset + 2
        self.AUTH0  = offset + 3
        self.ACCESS = offset + 4
        self.PWD    = offset + 8
        self.PACK   = offset + 12

NTAG_CONFIG_ADDR_MAP = {
    "NTAG210": 64,
    "NTAG212": 148,
    "NTAG213": 164,
    "NTAG215": 524,
    "NTAG216": 908,
}
        
class Tag(tt2.Type2Tag):
    def __init__(self, clf, target, product):
        super(Tag, self).__init__(clf, target)
        self._cfgaddr = NTAG_CONFIG_ADDR_MAP[product]
        self._product = "NXP " + product
        
    def __str__(self):
        return nfc.tag.Tag.__str__(self)

    @property
    def signature(self):
        log.debug("read tag signature")
        return self.transceive("\x3C\x00", rlen=32)

    def protect(self, password=None, read_protect=False):
        log.debug("protect tag")
        if password is not None:
            password = bytearray(password)
            assert len(password) >= 6
            # write PWD and PACK
            for i in range(6):
                self[self._cfgaddr+8+i] = password[i]
            # protect from page 0
            self[self._cfgaddr+3] = 0x00
            # set/clear protection bit
            if read_protect is True:
                self[self._cfgaddr+4] |= 0x80
            else:
                self[self._cfgaddr+4] &= 0x7F
            self.synchronize()

    def authenticate(self, password):
        log.debug("authenticate")
        password = bytearray(password)
        assert len(password) >= 6
        try:
            rsp = self.transceive("\x1b" + password[0:4], rlen=2)
            return rsp == password[4:6]
        except nfc.clf.TimeoutError:
            return False
