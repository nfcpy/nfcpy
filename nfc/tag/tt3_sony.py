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
    # http://www.sony.net/Products/felica/business/tech-support/list.html
    if target.pmm[1] == 0xF0:
        return FelicaLite(clf, target)
    if target.pmm[1] == 0xF1:
        return FelicaLiteS(clf, target)
    if target.pmm[1] in FelicaStandard.IC_CODE_MAP.keys():
        return FelicaStandard(clf, target)
    if target.pmm[1] in (0x06, 0x07) + tuple(range(0x10, 0x1F)):
        return FelicaMobile(clf, target)
    return None

class FelicaStandard(tt3.Type3Tag):
    IC_CODE_MAP = {
        # IC    IC-NAME    NBR NBW
        0x00: ("RC-S830",    8,  8), # RC-S831/833
        0x01: ("RC-S915",   12,  8), # RC-S860/862/863/864/891
        0x02: ("RC-S919",    1,  1), # RC-S890
        0x08: ("RC-S952",   12,  8),
        0x09: ("RC-S953",   12,  8),
        0x0C: ("RC-S954",   12,  8),
        0x0D: ("RC-S960",   12, 10), # RC-S880/889
        0x20: ("RC-S962",   12, 10), # RC-S885/888
        0x32: ("RC-SA00/1",  1,  1),
        0x35: ("RC-SA00/2",  1,  1),
    }
    def __init__(self, clf, target):
        super(FelicaStandard, self).__init__(clf, target)
        self._product = "FeliCa Standard ({0})".format(
            FelicaStandard.IC_CODE_MAP[target.pmm[1]][0])
        self._nbr, self._nbw = FelicaStandard.IC_CODE_MAP[target.pmm[1]][1:3]

class FelicaMobile(tt3.Type3Tag):
    def __init__(self, clf, target):
        super(FelicaMobile, self).__init__(clf, target)
        self._product = "FeliCa Mobile " + \
                        "1.0" if self.pmm[1] < 0x10 else \
                        "2.0" if self.pmm[1] < 0x14 else "3.0"

def generate_mac(data, key, iv, flip_key=False):
    # Data is first split into tuples of 8 character bytes, each tuple then
    # reversed and joined, finally all joined back to one string that is
    # then triple des encrypted with key and initialization vector iv. If
    # flip_key is True then the key halfs will be exchanged (this is used
    # to generate a mac for write). The resulting mac is the last 8 bytes
    # returned in reversed order.
    assert len(data) % 8 == 0 and len(key) == 16 and len(iv) == 8
    if flip_key is True: key = key[8:] + key[:8]
    txt = ''.join([''.join(reversed(x)) for x in zip(*[iter(data)]*8)])
    return triple_des(key, CBC, iv).encrypt(txt)[:-9:-1]
        
class FelicaLite(tt3.Type3Tag):
    def __init__(self, clf, target):
        super(FelicaLite, self).__init__(clf, target)
        self._product = "FeliCa Lite (RC-S965)"
        self._nbr = 4
        self._mc = bytearray(self.read(0x88))
        self._id = bytearray(self.read(0x82))
        
    def dump(self):
        ispchr = lambda x: x >= 32 and x <= 126
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        cprint = lambda o: ''.join([chr(x) if ispchr(x) else '.' for x in o])
        
        s = list()
        
        userblocks = list()
        for i in range(0, 14):
            try:
                data = bytearray(self.read(i))
            except Exception as e:
                log.debug(e)
                userblocks.append("{0}|{1}|".format(16*"?? ", 16*"."))
            else:
                userblocks.append("{0} |{1}|".format(
                    oprint(data), cprint(data)))

        last_block = None; same_blocks = 0
        for i, block in enumerate(userblocks):
            if block == last_block:
                same_blocks += 1
                continue
            if same_blocks:
                if same_blocks > 1: s.append("  *")
                same_blocks = 0
            s.append("{0:3}: ".format(i) + block)
            last_block = block
        if same_blocks:
            if same_blocks > 1: s.append("  *")
            s.append("{0:3}: ".format(i) + block)
        
        data = bytearray(self._read_command(14))
        s.append(" 14: {0} ({1})".format(
            oprint(data), "REGA[4]B[4]C[8]"))

        text = ("RC1[8], RC2[8]", "MAC[8]", "IDD[8], DFC[2]",
                "IDM[8], PMM[8]", "SERVICE_CODE[2]",
                "SYSTEM_CODE[2]", "CKV[2]", "CK1[8], CK2[8]",
                "MEMORY_CONFIG")
        config = dict(zip(range(0x80, 0x80+len(text)), text))
        
        for i in sorted(config.keys()):
            data = bytearray(self._read_command(i))
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
                log.debug("encrypt blocks {0}--13".format(protect_from))
                for block in range(protect_from, 14):
                    data = self.read(block)
                    data = triple_des(key, CBC, 8*chr(block)).encrypt(data)
                    self.write(data, block)
                log.debug("record encrypted blocks in ID[10-11]")
                self._id[10:12] = pack(">H", 2**14 - 2**protect_from)
                self.write(self._id, 0x82)

        if protect_from < 14:
            log.debug("write protect blocks {0}--13".format(protect_from))
            self._mc[0:2] = pack("<H", 0x7FFF ^ (2**14 - 2**protect_from))

        log.debug("write protect system blocks 82,83,84,86,87")
        self._mc[2] = 0x00
        self.write(self._mc, 0x88)
        return True

    def authenticate(self, password):
        # Perform internal authentication, i.e. ensure that the tag has the
        # same card key as in password. If the password is an empty string we
        # try with the factory key of all zero.
        key = 16 * "\0" if password == "" else password[0:16]
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

    def format(self, wipe=False):
        if self._mc[3] != 0x01:
            if self._mc[2] == 0xFF:
                self._mc[3] = 0x01; self.write(self._mc, 0x88)
                self._sys = bytearray.fromhex("12FC")
            else:
                log.error("this tag can no longer be formatted for ndef")

        if self._mc[3] == 0x01:
            attr = bytearray.fromhex("10040100 0D000000 00000100 00000000")
            attr[14:16] = pack(">H", sum(attr[0:14]))
            self.write(attr, 0)
            if wipe is True:
                self.write(13 * 16 * "\0", range(1, 14))
        
    def read(self, blocks):
        # Read a list of data blocks. If we are not authenticated than
        # this will simply call the base read method. Otherwise, we
        # iterate over the block list and read up to 3 blocks with
        # mac. The block list may also be an integer. If the user
        # blocks are read protected, i.e. were encrypted with
        # protect(.., read_protect=True,..), then we decrypt the data
        # before return.
        if not self._authenticated:
            return super(FelicaLite, self).read(blocks)

        assert self._ck != None
        if type(blocks) is int: blocks = [blocks]

        data = ""
        encrypted_blocks = unpack(">H", self._id[10:12])[0]
        for i in range(0, len(blocks), self._nbr-1):
            part = self.read_with_mac(blocks[i:i+self._nbr-1])
            for k in range(len(part)//16):
                if encrypted_blocks & (1<<blocks[i+k]):
                    log.debug("decrypt block {0}".format(blocks[i+k]))
                    tdea = triple_des(self._ck, CBC, 8*chr(blocks[i+k]))
                    data += tdea.decrypt(part[k*16:k*16+16])
                else:
                    data += part[k*16:k*16+16]

        return data

    def read_with_mac(self, blocks):
        assert self._sk != None and self._iv != None
        if type(blocks) is int: blocks = [blocks]
        log.debug("read {0} block(s) with mac".format(len(blocks)))
        
        data = self._read_command(blocks + [0x81])
        data, mac = data[0:-16], data[-16:-8]
        if mac == generate_mac(data, self._sk, self._iv):
            return data
        else: log.warning("mac verification failed")

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
                data = bytearray(self._read_command(i))
            except Exception as e:
                log.debug(e)
                s.append("{0:3}: {1}({2})".format(i, 16 * "?? ", config[i]))
            else:
                s.append("{0:3}: {1} ({2})".format(i, oprint(data), config[i]))
        
        return s

    def authenticate(self, password):
        if super(FelicaLiteS, self).authenticate(password):
            # At this point we have achieved internal authentication,
            # i.e we know that the tag has the same card key as in
            # password. We now reset the authentication status and do
            # external authentication to assure the tag that we have
            # the right card key.
            self._authenticated = False

            # To authenticate to the tag we write a 01h into the
            # ext_auth byte of the state block (block 0x92). The other
            # bytes of the state block can be all set to zero.
            self.write_with_mac("\x01" + 15*"\0", 0x92)
            
            # Now read the state block and check the value of the
            # ext_auth to see if we are authenticated. If it's 01h
            # then we are, otherwise not.
            if self.read(0x92)[0] == "\x01":
                log.debug("mutual authentication completed")
                self._authenticated = True
            else:
                log.debug("mutual authentication failed")

        return self._authenticated

    def write(self, data, blocks):
        # Write a list of data blocks. If we are not authenticated
        # than this will simply call the base write method. Otherwise,
        # we iterate over the block list and write each block with
        # mac. For convinience, the block list can also be an integer.
        if not self._authenticated:
            return super(FelicaLiteS, self).write(data, blocks)

        if type(blocks) is int: blocks = [blocks]
        assert len(data) == len(blocks) * 16
        
        for i, block in enumerate(blocks):
            self.write_with_mac(data[i*16:i*16+16], block)

    def write_with_mac(self, data, block):
        # Write a single data block protected with a mac. The tag will
        # only accept the write if it generated the same mac value.
        assert self._sk != None and self._iv != None
        assert len(data) == 16 and type(block) is int
        log.debug("write {0} block with mac".format(1))

        # The write count is the first three byte of the wcnt block.
        wcnt = self._read_command(0x90)[0:3]
        log.debug("write count is 0x{0}".format(wcnt[::-1].encode("hex")))
        
        # We must generate the mac_a block to write the data. The data
        # to encrypt to the mac is composed of write count and block
        # numbers (8 byte) and the data we want to write. The mac for
        # write must be generated with the key flipped (sk2 || sk1).
        flip = lambda sk: sk[8:16] + sk[0:8]
        data = wcnt + "\x00" + chr(block) + "\x00\x91\x00" + data
        maca = generate_mac(data, flip(self._sk), self._iv) + wcnt + 5*"\0"
        self._write_command(data[8:24] + maca, [block, 0x91])

    def protect(self, password=None, read_protect=False, protect_from=0):
        log.debug("protect(password={0!r}, read_protect={1}, protect_from={2})"
                  .format(password, read_protect, protect_from))
        assert protect_from >= 0

        mc = self._mc
        if password is not None:
            if self._mc[2] != 255 and mc[5] == 0:
                log.debug("system block protected, can't write key")
                return False
                
            if password == "":
                # set the factory key
                key = 16 * "\x00"
            else:
                key = password[0:16]
                assert len(key) == 16

            log.debug("protect with key " + key.encode("hex"))
            ckv = unpack("<H", self.read(0x86)[0:2])[0]
            self.write(pack("<H", min(ckv + 1, 0xFFFF)) + 14*"\0", 0x86)
            self.write(key[7::-1] + key[15:7:-1], 0x87)

            if read_protect and protect_from < 14:
                log.debug("read protect blocks {0}--13".format(protect_from))
                protect_mask = pack("<H", 2**14 - 2**protect_from)
                mc[6:8] = protect_mask

        if protect_from < 14:
            log.debug("write protect blocks {0}--13".format(protect_from))
            protect_mask = pack("<H", 2**14 - 2**protect_from)
            mc[8:10] = mc[10:12] = protect_mask
            
        log.debug("write protect system blocks 82,83,84,86,87")
        mc[2] = 0x00 # set system blocks 82,83,84,86,87 to read only
        mc[5] = 0x01 # but allow write with mac to ck and ckv block
        self._write_command(mc, 0x88)
        self._mc = bytearray(self._read_command(0x88))
        log.debug("MC: {0}".format(str(self._mc).encode("hex")))
        return True
