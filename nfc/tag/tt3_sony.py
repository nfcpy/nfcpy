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
from . import tt3

def activate(clf, target):
    if target.sys == "\x88\xB4":
        if target.pmm[1] == 0xF0:
            return FelicaLite(clf, target)
        if target.pmm[1] == 0xF1:
            return FelicaLiteS(clf, target)
    return None

class FelicaLite(tt3.Type3Tag):
    def __init__(self, clf, target):
        super(FelicaLite, self).__init__(clf, target)
        self._product = "FeliCa Lite (RC-S965)"
        
    def dump(self):
        ispchr = lambda x: x >= 32 and x <= 126
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        cprint = lambda o: ''.join([chr(x) if ispchr(x) else '.' for x in o])
        
        s = list()
        
        userblocks = list()
        for i in range(0, 14):
            data = bytearray(self.read(i))
            if data is None:
                unreadable_pages = self._userblocks.stop - i
                userblocks.extend(["?? ?? ?? ?? |....|"] * unreadable_pages)
                break
            userblocks.append("{0} |{1}|".format(
                oprint(data), cprint(data)))

        last_block = None; same_blocks = False
        for i, block in enumerate(userblocks):
            if block == last_block:
                same_blocks = True
                continue
            if same_blocks:
                s.append(" *")
                same_blocks = False
            s.append("{0:3}: ".format(i) + block)
            last_block = block
        if same_blocks:
            s.append("  *")
            s.append("{0:3}: ".format(i) + block)
        
        data = bytearray(self.read(14))
        s.append(" 14: {0} ({1})".format(
            oprint(data), "REGA[4]B[4]C[8]"))

        text = ("RC1[8], RC2[8]", "MAC[8]", "IDD[8], DFC[2]",
                "IDM[8], PMM[8]", "SERVICE_CODE[2]",
                "SYSTEM_CODE[2]", "CKV[2]", "CK1[8], CK2[8]",
                "MEMORY_CONFIG")
        config = dict(zip(range(0x80, 0x80+len(text)), text))
        
        for i in sorted(config.keys()):
            data = bytearray(self.read(i))
            if data is None:
                s.append("{0:3}: {1}({2})".format(
                    i, 16 * "?? ", config[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(
                    i, oprint(data), config[i]))
        
        return s

    def protect(self, password=None, read_protect=False, protect_from=0):
        if password is not None:
            if password == "":
                # set the factory key
                key = "IEMKAERB!NACUOYF"
            else:
                key = password[0:16]
                assert len(key) == 16
            log.debug("protect with key " + key.encode("hex"))            

    def authenticate(self, password):
        from pyDes import triple_des, CBC
        if password == "":
            # try with the factory key
            key = "\x00" * 16
        else:
            key = password[0:16]
            assert len(key) == 16
        
        log.debug("authenticate with key " + str(key).encode("hex"))

        # write random challenge to rc block
        rc = os.urandom(16)
        log.debug("rc1 = " + rc[:8].encode("hex"))
        log.debug("rc2 = " + rc[8:].encode("hex"))
        self.write(rc[7::-1] + rc[15:7:-1], 0x80)

        # generate session key (iv is all zero)
        sk = triple_des(key, CBC, 8 * '\0').encrypt(rc)
        log.debug("sk1 = " + sk[:8].encode("hex"))
        log.debug("sk2 = " + sk[8:].encode("hex"))

        # read the id block and mac
        data = self.read([0x82, 0x81])
        txt = data[7::-1] + data[15:7:-1]
        mac = data[-9:-17:-1]
        
        if mac == triple_des(sk, CBC, rc[0:8]).encrypt(txt)[8:]:
            log.debug("tag is authenticated")
            self._sk = sk; self._iv = rc[:8]
            return True
        else:
            log.debug("tag not authenticated")
            return False

class FelicaLiteS(FelicaLite):
    def __init__(self, clf, target):
        super(FelicaLite, self).__init__(clf, target)
        self._product = "FeliCa Lite-S (RC-S966)"

    def dump(self):
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        s = super(FelicaLiteS, self).dump()
        
        text = ("WCNT[3]",)#, "MAC_A[8], WCNT[3]", "STATE")
        config = dict(zip(range(0x90, 0x90+len(text)), text))
        
        for i in sorted(config.keys()):
            data = bytearray(self.read([i]))
            if data is None:
                s.append("{0:3}: {1}({2})".format(
                    i, 16 * "?? ", config[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(
                    i, oprint(data), config[i]))
        
        return s

