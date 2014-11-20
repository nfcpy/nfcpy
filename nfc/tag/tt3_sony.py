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
from struct import pack, unpack
from pyDes import triple_des, CBC

import nfc.tag
from . import tt3

def activate(clf, target):
    if target.sys == "\x88\xB4":
        if target.pmm[1] == 0xF0:
            return FelicaLite(clf, target)
        if target.pmm[1] == 0xF1:
            return FelicaLiteS(clf, target)
    return None

def generate_mac(data, key, iv):
    # data is first split into tuples of 8 character bytes, each tuple then
    # reversed and joined, finally all joined back to one string that is
    # then triple des encrypted with key and initialization vector iv. The
    # mac is the last 8 bytes and returned in reversed order.
    txt = ''.join([''.join(reversed(x)) for x in zip(*[iter(data)]*8)])
    return triple_des(key, CBC, iv).encrypt(txt)[:-9:-1]
        
class FelicaLite(tt3.Type3Tag):
    def __init__(self, clf, target):
        super(FelicaLite, self).__init__(clf, target)
        self._product = "FeliCa Lite (RC-S965)"
        self._mc = bytearray(self.read(0x88))
        self._id = bytearray(self.read(0x82))
        
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
        
        data = bytearray(tt3.Type3Tag.read(self, 14))
        s.append(" 14: {0} ({1})".format(
            oprint(data), "REGA[4]B[4]C[8]"))

        text = ("RC1[8], RC2[8]", "MAC[8]", "IDD[8], DFC[2]",
                "IDM[8], PMM[8]", "SERVICE_CODE[2]",
                "SYSTEM_CODE[2]", "CKV[2]", "CK1[8], CK2[8]",
                "MEMORY_CONFIG")
        config = dict(zip(range(0x80, 0x80+len(text)), text))
        
        for i in sorted(config.keys()):
            data = bytearray(tt3.Type3Tag.read(self, i))
            if data is None:
                s.append("{0:3}: {1}({2})".format(
                    i, 16 * "?? ", config[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(
                    i, oprint(data), config[i]))
        
        return s

    def protect(self, password=None, read_protect=False, protect_from=0):
        log.debug("protect(password={0!r}, read_protect={1}, protect_from={2})"
                  .format(password, read_protect, protect_from))
        assert protect_from >= 0
        
        if password is not None:
            if self._mc[2] != 0xFF:
                log.debug("system block protected, can't write key")
                return False
                
            if password == "":
                # set the factory key
                key = 16 * "\x00"
            else:
                key = password[0:16]
                assert len(key) == 16

            log.debug("protect with key " + key.encode("hex"))
            self.write(key[7::-1] + key[15:7:-1], 0x87)

            if read_protect and protect_from < 14:
                log.debug("encrypt data blocks {0} to 13".format(protect_from))
                for block in range(protect_from, 14):
                    data = self.read(block)
                    data = triple_des(key, CBC, 8*chr(block)).encrypt(data)
                    self.write(data, block)
                log.debug("record encrypted blocks in ID[10-11]")
                self._id[10:12] = pack(">H", 2**14 - 2**protect_from)
                self.write(self._id, 0x82)

        if protect_from < 14:
            log.debug("set blocks {0} to 13 to readonly".format(protect_from))
            self._mc[0:2] = pack("<H", 0x7FFF ^ (2**14 - 2**protect_from))

        log.debug("set system blocks to readonly")
        self._mc[2] = 0x00
        self.write(self._mc, 0x88)
        return True

    def authenticate(self, password):
        # Perform internal authentication, i.e. ensure that the tag has the
        # same card key as in password. If the password is an empty string we
        # try with the factory key of all zero.
        # Internal authentication starts with a random challenge (rc1 || rc2)
        # that we write to the tag. Because the tag works little endian, we
        # reverse the order of rc1 and rc2 bytes when writing. The session key
        # becomes the triple_des encryption of the random challenge under the
        # card key and with an initialization vector of all zero.
        if password == "":
            # try with the factory key
            key = 16 * "\x00"
        else:
            key = password[0:16]
            assert len(key) == 16
        
        log.debug("authenticate with key " + str(key).encode("hex"))
        self._authenticated = False
        
        # Internal authentication starts with a random challenge (rc1 || rc2)
        # that we write to the rc block. Because the tag works little endian,
        # we reverse the order of rc1 and rc2 bytes when writing.
        rc = os.urandom(16)
        log.debug("rc1 = " + rc[:8].encode("hex"))
        log.debug("rc2 = " + rc[8:].encode("hex"))
        self.write(rc[7::-1] + rc[15:7:-1], 0x80)

        # The session key becomes the triple_des encryption of the random
        # challenge under the card key and with an initialization vector of
        # all zero.
        sk = triple_des(key, CBC, 8 * '\0').encrypt(rc)
        log.debug("sk1 = " + sk[:8].encode("hex"))
        log.debug("sk2 = " + sk[8:].encode("hex"))

        # By reading the id and mac block together we get the mac that the
        # tag has generated over the id block data under it's session key
        # generated the same way as we did) and with rc1 as the
        # initialization vector.
        data = self.read([0x82, 0x81])

        # Now we check if we calculate the same mac with our session key.
        # Note that, because of endianess, data must be reversed in chunks
        # of 8 bytes as does the 8 byte mac - this is all done within the
        # generate_mac() function.
        if data[-16:-8] == generate_mac(data[0:-16], sk, iv=rc[0:8]):
            log.debug("tag authentication completed")
            self._sk = sk; self._iv = rc[0:8]; self._ck = key
            self._authenticated = True
        else:
            log.debug("tag authentication failed")

        return self._authenticated

    def format(self):
        attr = bytearray.fromhex("10040100 0D000000 00000100 00000000")
        attr[14:16] = pack(">H", sum(attr[0:14]))
        self.write(attr, 0)
        
    def read(self, blocks):
        if not self._authenticated:
            return tt3.Type3Tag.read(self, blocks)
            
        if type(blocks) is int: blocks = [blocks]
        log.debug("read blocks {0} with mac".format(blocks))
        
        data = str()
        encrypted_blocks = unpack(">H", self._id[10:12])[0]
        for i in range(0, len(blocks), 3):
            rsp = tt3.Type3Tag.read(self, blocks[i:i+3] + [0x81])
            if rsp[-16:-8] == generate_mac(rsp[0:-16], self._sk, self._iv):
                for k in range(len(rsp)//16-1):
                    if encrypted_blocks & (1<<blocks[i+k]):
                        log.debug("decrypt block {0}".format(blocks[i+k]))
                        tdea = triple_des(self._ck, CBC, 8*chr(blocks[i+k]))
                        data += tdea.decrypt(rsp[k*16:(k+1)*16])
                    else:
                        data += rsp[k*16:(k+1)*16]
            else:
                log.warning("mac verification failed")

        return data

class FelicaLiteS(FelicaLite):
    def __init__(self, clf, target):
        super(FelicaLiteS, self).__init__(clf, target)
        self._product = "FeliCa Lite-S (RC-S966)"

    def dump(self):
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        s = super(FelicaLiteS, self).dump()
        
        text = ("WCNT[3]", "MAC_A[8]", "STATE")
        config = dict(zip(range(0x90, 0x90+len(text)), text))
        
        for i in sorted(config.keys()):
            try:
                data = bytearray(tt3.Type3Tag.read(self, [i]))
            except Exception as e:
                log.debug(e)
                s.append("{0:3}: {1}({2})".format(i, 16 * "?? ", config[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(i, oprint(data), config[i]))
        
        return s

    def authenticate(self, password):
        if super(FelicaLiteS, self).authenticate(password):
            # At this point we have achieved internal authentication, i.e we
            # know that the tag has the same card key as in password. We now
            # reset the authentication status and do external authentication
            # to assure the tag that we have the right card key.
            self._authenticated = False

            # The write count is the first three byte of the wcnt block.
            wcnt = self.read(0x90)[0:3]
            log.debug("write count is 0x{0}".format(wcnt[::-1].encode("hex")))

            # We must generate the mac_a block to write 01h into the ext_auth
            # byte of the state block. The mac for write is generated with 
            # a flipped session key (sk = sk2 || sk1). The data to encrypt for
            # the mac is composed of write count and block numbers (8 byte)
            # and the state block data we want to write (01h for ext_auth plus
            # 15 zero bytes).
            flip = lambda sk: sk[8:16] + sk[0:8]
            data = wcnt + "\x00\x92\x00\x91\x00" + "\x01" + 15 * "\x00"
            maca = generate_mac(data, flip(self._sk), self._iv) + wcnt + 5*"\0"
            self.write(data[8:24] + maca, [0x92, 0x91])

            # To check if mutual authentication succeeded we read the state
            # block and look at the value of the ext_auth byte. If it's 01h
            # then we are authenticated, any other value say's we're not.
            if self.read(0x92)[0] == "\x01":
                log.debug("mutual authentication completed")
                self._authenticated = True
            else:
                log.debug("mutual authentication failed")

            return self._authenticated
