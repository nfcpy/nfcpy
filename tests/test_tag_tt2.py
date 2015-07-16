#!/usr/bin/python
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
import sys, os
sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc
import nfc.ndef
import nfc.tag.tt2
import nfc.tag.tt2_nxp

from binascii import hexlify
from nose.tools import raises
from nose.plugins.attrib import attr
from nose.plugins.skip import SkipTest

import logging
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt2").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)

def crca(data, size):
    reg = 0x6363
    for octet in data[:size]:
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit: reg = reg ^ 0x8408
    return bytearray([reg & 0xff, reg >> 8])

class Type2TagSimulator(nfc.clf.ContactlessFrontend):
    def __init__(self, tag_memory_layout):
        self.memory = tag_memory_layout
        self.sector = 0
        self.dev = nfc.dev.Device()
        self.uid = self.memory[0:7]
        self.tag_is_present = True # to simulate tag removal
        self.return_response = None
        self.command_counter = 0
        self.crc_error_after = 0

    def sense(self, targets):
        cfg = bytearray.fromhex("440000")
        return nfc.clf.TTA(106, cfg, self.uid)

    def exchange(self, data, timeout):
        data = bytearray(data)
        self.command_counter += 1
        if self.tag_is_present is False:
            raise nfc.clf.TimeoutError("mute tag")
        if self.crc_error_after == self.command_counter:
            raise nfc.clf.TransmissionError("crc error")
        if self.return_response is not None:
            return self.return_response

        if data[0] == 0x30: # READ COMMAND
            offset = self.sector * 1024 + data[1] * 4
            if offset < len(self.memory):
                data = self.memory[offset:offset+16]
                data.extend(self.memory[0:(16-len(data))])
                return data + crca(data, len(data))
            else: return bytearray([0x00]) # NAK
        elif data[0] == 0xA2: # WRITE COMMAND
            offset = self.sector * 1024 + data[1] * 4
            if offset + 4 <= len(self.memory):
                self.memory[offset:offset+4] = data[2:6]
                return bytearray([0x0A])
            else: return bytearray([0xA0])
        elif data == "\xC2\xFF": # SECTOR_SELECT 1
            return bytearray([0x0A if len(self.memory) > 1024 else 0xA0])
        elif len(data) == 4 and timeout == 0.001: # SECTOR_SELECT 2
            if data[0] * 1024 < len(self.memory):
                self.sector = data[0]
                raise nfc.clf.TimeoutError("sector select")
            else: return bytearray([0xA0])
        else:
            response = self.unknown_command(data, timeout)
            if response is not None: return response
            else: raise nfc.clf.TimeoutError("unknown command")

    def unknown_command(self, data, timeout):
        pass

    def set_communication_mode(self, brm, **kwargs):
        pass

###############################################################################
#
# TEST TYPE 2 TAG MEMORY READER
#
###############################################################################

class TestMemoryReader:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00"
        )
        self.clf = Type2TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_getitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == self.clf.memory[0]
        assert tag_memory[1] == self.clf.memory[1]
        
    def test_getitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0:8] == self.clf.memory[0:8]
        assert tag_memory[0:4] == self.clf.memory[0:4]
        assert tag_memory[4:8] == self.clf.memory[4:8]
        
    def test_setitem_byte(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xFF

    def test_setitem_slice(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:2] = bytearray("\x11\x22")
        tag_memory.synchronize()
        assert self.clf.memory[0:2] == bytearray("\x11\x22")

    @raises(ValueError)
    def test_setitem_slice_is_shorter(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:3] = bytearray("\x11\x22")

    @raises(ValueError)
    def test_setitem_slice_is_longer(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        tag_memory[0:1] = bytearray("\x11\x22")

    @raises(TypeError)
    def test_delitem(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        del tag_memory[0]

    @raises(IndexError)
    def test_read_from_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        self.clf.tag_is_present = False
        value = tag_memory[0]

    def test_write_to_mute_tag(self):
        tag_memory = nfc.tag.tt2.Type2TagMemoryReader(self.tag)
        assert tag_memory[0] == 0x01
        self.clf.tag_is_present = False
        tag_memory[0] = 0x00
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0x01

################################################################################
#
# TEST TYPE 2 TAG COMMANDS
#
################################################################################

class TestTagCommands:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00"
        ) + bytearray(2048 - 16)
        self.clf = Type2TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_read_with_args_keyword(self):
        assert self.tag.read(page=0) == self.clf.memory[0:16]

    def test_read_with_args_positional(self):
        assert self.tag.read(0) == self.clf.memory[0:16]

    def test_read_with_nak_response(self):
        for nak in (0, 1, 4, 5):
            yield self.check_read_with_nak_response, nak

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def check_read_with_nak_response(self, nak):
        self.clf.return_response = bytearray([nak])
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
            raise

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_read_with_invalid_response(self):
        self.clf.return_response = bytearray(15)
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
            raise

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_read_with_checksum_error(self):
        self.clf.return_response = bytearray(18)
        try: self.tag.read(0)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.CHECKSUM_ERROR
            raise

    def test_write_with_args_keyword(self):
        self.tag.write(page=0, data=bytearray(4))
        assert self.clf.memory[0:4] == bytearray(4)

    def test_write_with_args_positional(self):
        self.tag.write(0, bytearray(4))
        assert self.clf.memory[0:4] == bytearray(4)

    @raises(ValueError)
    def test_write_with_args_error(self):
        self.tag.write(0, data=bytearray(3))

    def test_write_with_nak_response(self):
        for nak in (0, 1, 4, 5):
            yield self.check_write_with_nak_response, nak

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def check_write_with_nak_response(self, nak):
        self.clf.return_response = bytearray([nak])
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_PAGE_ERROR
            raise

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_write_with_invalid_response(self):
        self.clf.return_response = bytearray(2)
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_RESPONSE_ERROR
            raise

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_write_to_mute_tag(self):
        self.clf.tag_is_present = False
        try: self.tag.write(0, bytearray(4))
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.TIMEOUT_ERROR
            raise

    def test_sector_select_same_sector(self):
        assert self.tag.sector_select(0) == 0

    def test_sector_select(self):
        assert self.tag.sector_select(1) == 1

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_sector_select_not_supported(self):
        self.clf.return_response = bytearray([0x00])
        try: self.tag.sector_select(1)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
            raise

    @raises(nfc.tag.tt2.Type2TagCommandError)
    def test_sector_select_invalid_sector(self):
        try: self.tag.sector_select(2)
        except nfc.tag.tt2.Type2TagCommandError as error:
            assert error.errno == nfc.tag.tt2.INVALID_SECTOR_ERROR
            raise

################################################################################
#
# TEST TYPE 2 TAG PROCEDURES
#
################################################################################

class TestTagProcedures:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "01 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00"
            "02 03 82 04  02 00 00 00  03 03 D0 00  00 FE 00 00"
        ) + bytearray(2048 - 32)
        self.clf = Type2TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_dump_args_default(self):
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == "511: 00 00 00 00 |....|"

    def test_dump_args_stop(self):
        lines = self.tag._dump(4)
        assert len(lines) == 4
        assert lines[3] == "  3: e1 10 fe 00 (OTP0-OTP3)"

    def test_dump_unreadable(self):
        self.clf.return_response = bytearray([0x00])
        lines = self.tag._dump(8)
        assert len(lines) == 7
        assert lines[3] == "  3: ?? ?? ?? ?? (OTP0-OTP3)"
        assert lines[6] == "  7: ?? ?? ?? ?? |....|"

    def test_is_present_if_present(self):
        assert self.tag.is_present is True

    def test_is_present_if_gone(self):
        self.clf.tag_is_present = False
        assert self.tag.is_present is False

    def test_is_present_if_error(self):
        self.clf.return_response = bytearray(18)
        assert self.tag.is_present is False

    def test_format_wrong_ndef_magic(self):
        self.clf.memory[12] = 0
        assert self.tag.format() is False

    def test_format_wrong_ndef_version(self):
        self.clf.memory[13] = 0
        assert self.tag.format() is False

    def test_format_no_user_data_area(self):
        self.clf.memory[14] = 0
        assert self.tag.format() is False

    def test_format_ndef_readonly(self):
        self.clf.memory[15] = 0xFF
        assert self.tag.format() is False

    def test_format_args_default(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format() is True
        assert self.clf.memory[24:32] == "0300FE0000FE0000".decode("hex")

    def test_format_wipe_ndef_data(self):
        assert self.clf.memory[24:32] == "0303D00000FE0000".decode("hex")
        assert self.tag.format(wipe=1) is True
        assert self.clf.memory[24:32] == "0300FE0101010101".decode("hex")
        assert self.clf.memory[32:40] == "0101000000000101".decode("hex")
        assert self.clf.memory[40:2048] == (2048-40) * "\x01"

    def test_protect_with_default_lock_bits(self):
        self.clf.memory += bytearray(32)
        assert self.tag.protect() is True
        assert self.clf.memory[   8:  16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[  16:  24] == "0203820402000000".decode("hex")
        assert self.clf.memory[  24:  32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[  32:2048] == 2016 * "\x00"
        assert self.clf.memory[2048:2082] == bytearray(31*"\xFF") + "\x00"
        assert self.tag.ndef.is_writeable is False

    def test_protect_with_lock_tlv_lock_bits(self):
        self.clf.memory[16:21] = bytearray.fromhex("01 03 82 1F 62")
        assert self.tag.protect() is True
        assert self.clf.memory[ 8:16] == "79C8FFFFE110FE0F".decode("hex")
        assert self.clf.memory[16:24] == "0103821F62000000".decode("hex")
        assert self.clf.memory[24:32] == "0303d00000FE0000".decode("hex")
        assert self.clf.memory[32:40] == "0000FFFFFF7F0000".decode("hex")
        assert self.tag.ndef.is_writeable is False

    def test_protect_with_password_argument(self):
        assert self.tag.protect("abcdefg") is False

    def test_protect_without_ndef_magic_byte(self):
        self.clf.memory[12] = 0
        assert self.tag.protect() is False

###############################################################################
#
# TEST TYPE 1 TAG NDEF
#
###############################################################################

class TestNdef:
    def setup(self):
        tag_memory = (bytearray.fromhex(
            "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00" # 000-003
            "00 00 00 01  03 50 10 24  FF 01 00 02  03 52 0E 04" # 004-007
            "03 FF 07 CC  C1 01 00 00  07 C5 55 01  6E 66 63 2E" # 008-011
            "63 6F 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 012-015
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 016-019
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 024-027
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D" # 028-031
        ) + bytearray(1904 * "\x6D") + bytearray.fromhex(        # 012-509
            "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  2E 63 6F 6D" # 508-511
        ))
        uri = "http://www.nfc.co{0}.com".format((2010-32) * "m")
        self.ndef_message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        self.ndef_capacity = 2048 - 52
        self.ndef_length = 2048 - 52

        self.clf = Type2TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_ndef_read(self):
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == self.ndef_length
        print self.tag.ndef.message.pretty()
        assert self.tag.ndef.message == self.ndef_message

    def test_ndef_read_no_ndef_magic_byte(self):
        self.clf.memory[12] = 0
        assert self.tag.ndef is None

    def test_ndef_read_unknown_major_version(self):
        self.clf.memory[13] = 0
        assert self.tag.ndef is None

    def test_ndef_read_unknown_minor_version(self):
        self.clf.memory[13] = 0x1F
        assert self.tag.ndef is not None

    def test_ndef_read_all_data_set_to(self):
        for value in (0, 1, 2, 4, 254, 255):
            yield self.check_ndef_read_all_data_set_to, value

    def check_ndef_read_all_data_set_to(self, value):
        self.clf.memory[16:2048] = bytearray(2032*chr(value))
        assert self.tag.ndef is None

    def test_ndef_write_before_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(1 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 16
        assert self.clf.memory[34:51] == "\xD1\x01\x0C\x55\x01nfc.com.com\xFE"

    def test_ndef_write_after_skip_bytes(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(33 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48
        assert self.clf.memory[32:40] == "\x03\x30\xD1\x01\x2C\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (33 * "m") + ".c"
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:99] == "om\xFE"

    def test_ndef_write_long_ndef_message(self):
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format((33+208) * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.capacity == self.ndef_capacity
        assert self.tag.ndef.length == 48+208
        assert self.clf.memory[32:40] == "\x03\xFF\x01\x00\xD1\x01\xFC\x55"
        assert self.clf.memory[40:80] == "\x01nfc.co" + (33 * "m")
        assert self.clf.memory[80:96] == bytearray(16)
        assert self.clf.memory[96:309] == (208 * "m") + ".com\xFE"

    def test_ndef_write_without_terminator(self):
        self.clf.memory[14] = 0x0A
        assert self.tag.ndef is not None
        uri = "http://www.nfc.co{0}.com".format(31 * "m")
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.tag.ndef.length == 46
        assert self.clf.memory[32:40] == "\x03\x2E\xD1\x01\x2A\x55\x01n"
        assert self.clf.memory[40:80] == "fc.co" + (31 * "m") + ".com"
        assert self.clf.memory[80:96] == bytearray(16)

################################################################################
#
# TEST MIFARE ULTRALIGHT
#
################################################################################

class MifareUltralightSimulator(Type2TagSimulator): pass

class TestUltralight:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 06 00" # 000-003
            "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00" # 004-007
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 008-011
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
        )
        self.clf = MifareUltralightSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralight)
        assert self.tag._product == "Mifare Ultralight (MF01CU1)"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == ' 15: 00 00 00 00 |....|'
        
################################################################################
#
# TEST MIFARE ULTRALIGHT C
#
################################################################################

class MifareUltralightCSimulator(Type2TagSimulator):
    def unknown_command(self, data, timeout):
        from nfc.tag.pyDes import triple_des, CBC
        if data == "\x1A\x00": # AUTHENTICATE COMMAND
            key = str(self.memory[176:192])
            key = key[7::-1] + key[15:7:-1]
            self.m1 = triple_des(key, CBC, 8*"\0").encrypt("\0\1\2\3\4\5\6\7")
            return bytearray("\xAF" + self.m1)
        if data[0] == 0xAF and len(data) == 17 and hasattr(self, "m1"):
            key = str(self.memory[176:192])
            key = key[7::-1] + key[15:7:-1]
            m2 = str(data[1:17])
            rndab = triple_des(key, CBC, self.m1).decrypt(m2)
            rnda, rndb = rndab[0:8], rndab[15] + rndab[8:15]
            if rndb == "\0\1\2\3\4\5\6\7":
                m3 = triple_des(key, CBC, m2[8:16]).encrypt(rnda[1:8]+rnda[0])
                return bytearray("\x00" + m3)
            return bytearray([0x00]) # nak

class TestUltralightC:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
            "01 03 A0 10  44 03 89 D1  01 85 55 01  6E 66 63 63" # 004-007
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 008-011
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 012-015
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 016-019
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 020-023
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 024-027
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 028-031
            "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63" # 032-035
            "63 63 63 63  63 63 63 63  63 57 4C 46  2E 63 6F 6D" # 036-039
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # PASSWORD
        )
        self.clf = MifareUltralightCSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralightC)
        assert self.tag._product == "Mifare Ultralight C (MF01CU2)"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 17
        assert lines[-1] == ' 43: 00 00 00 00 (AUTH1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-24:]
        lines = self.tag.dump()
        assert len(lines) == 17
        assert lines[-1] == ' 43: ?? ?? ?? ?? (AUTH1)'

    def test_read_ndef_with_unreadable_page(self):
        del self.clf.memory[80:]
        assert self.tag.ndef is None
        del self.clf.memory[15:]
        assert self.tag.ndef is None

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:176] == "\xFF\xFF" + 14 * "\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False

    def test_protect_with_lockbits_no_ndef_capabilities(self):
        self.clf.memory[12:16] = "\1\2\3\4"
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:176] == "\xFF\xFF" + 14 * "\x00"
        assert self.clf.memory[15] == 0x04

    def test_protect_with_lockbits_but_read_error(self):
        del self.clf.memory[12:]
        assert self.tag.protect() is False
        assert self.clf.memory[10:12] == "\x00\x00"

    @raises(ValueError)
    def test_protect_with_invalid_password(self):
        self.tag.protect("abc")

    def test_protect_with_default_password(self):
        assert self.tag.protect("") is True
        assert self.clf.memory[168:172] == "\3\0\0\0"
        assert self.clf.memory[172:176] == "\1\0\0\0"
        assert self.clf.memory[176:192] == "BREAKMEIFYOUCAN!"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_custom_password(self):
        assert self.tag.protect("0123456789abcdef") is True
        assert self.clf.memory[168:172] == "\3\0\0\0"
        assert self.clf.memory[172:176] == "\1\0\0\0"
        assert self.clf.memory[176:192] == "76543210fedcba98"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_protect_from_page_5(self):
        assert self.tag.protect("", protect_from=5) is True
        assert self.clf.memory[168:172] == "\5\0\0\0"
        assert self.clf.memory[172:176] == "\1\0\0\0"
        assert self.clf.memory[176:192] == "BREAKMEIFYOUCAN!"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_protect_from_page_100(self):
        assert self.tag.protect("", protect_from=100) is True
        assert self.clf.memory[168:172] == "\x30\0\0\0"
        assert self.clf.memory[172:176] == "\1\0\0\0"
        assert self.clf.memory[176:192] == "BREAKMEIFYOUCAN!"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_read_protect_true(self):
        assert self.tag.protect("", read_protect=True) is True
        assert self.clf.memory[168:172] == "\3\0\0\0"
        assert self.clf.memory[172:176] == "\0\0\0\0"
        assert self.clf.memory[176:192] == "BREAKMEIFYOUCAN!"
        assert self.clf.memory[15] == 0x88
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_authenticate_with_default_password(self):
        self.clf.memory[176:192] = "BREAKMEIFYOUCAN!"
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("") is True
        assert self.tag.is_authenticated is True

    def test_authenticate_with_custom_password(self):
        self.clf.memory[176:192] = "76543210fedcba98"
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("0123456789abcdef") is True
        assert self.tag.is_authenticated is True

    def test_authenticate_with_wrong_password(self):
        assert self.tag.authenticate("0123456789abcdef") is False
        assert self.tag.is_authenticated is False

    @raises(ValueError)
    def test_authenticate_with_invalid_password(self):
        self.tag.authenticate("abc")

################################################################################
#
# TEST NTAG 203
#
################################################################################

class NTAG203Simulator(Type2TagSimulator):
    def unknown_command(self, data, timeout):
        if data == "\x1A\x00": # AUTHENTICATE COMMAND
            return bytearray("\x00")

class TestNTAG203:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
            "01 03 A0 10  44 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(168 - 32)
        self.clf = NTAG203Simulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG203)
        assert self.tag._product == "NXP NTAG203"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == ' 41: 00 00 00 00 (CNTR0-CNTR1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-8:]
        lines = self.tag.dump()
        assert len(lines) == 11
        assert lines[-1] == ' 41: ?? ?? ?? ?? (CNTR0-CNTR1)'

    def test_protect_without_password(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\x01\x00\x00"
        assert self.tag.ndef.is_writeable is False

    def test_protect_unformatted_tag(self):
        self.clf.memory[12:16] = "\1\2\3\4"
        assert self.tag.protect() is True
        assert self.clf.memory[12:16] == "\1\2\3\4"
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\x01\x00\x00"

    def test_protect_with_password(self):
        assert self.tag.protect("123456") is False

    def test_protect_with_read_error(self):
        self.clf.tag_is_present = False
        assert self.tag.protect() is False

################################################################################
#
# TEST NTAG 21x
#
################################################################################

class NTAG21xSimulator(Type2TagSimulator):
    def __init__(self, tag_memory, version):
        super(NTAG21xSimulator, self).__init__(tag_memory)
        self.version = bytearray(version)

    def unknown_command(self, data, timeout):
        if data == "\x60": # GET_VERSION COMMAND
            return bytearray(self.version)
        if data == "\x3C\x00": # READ_SIG COMMAND
            return bytearray(32 * "\1")
        if data[0] == 0x1B: # PWD_AUTH COMMAND
            pwd = data[1:5]
            if pwd == self.memory[-8:-4]:
                return self.memory[-4:-2]
            else: return bytearray([0x00])

class TestNTAG21x:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 008-011
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
            "00 00 00 00  00 00 00 00  FF FF FF FF  00 00 00 00" # 016-019
        )
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0B\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG21x)
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG210)

    def test_signature_attribute_get(self):
        assert type(self.tag.signature) is str
        assert self.tag.signature == 32 * "\1"

    @raises(AttributeError)
    def test_signature_attribute_set(self):
        self.tag.signature = 32 * "\1"

    def test_signature_read_from_mute_tag(self):
        self.clf.tag_is_present = False
        assert self.tag.signature == 32 * "\0"

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[-12] == 0x40

    def test_protect_with_lockbits_no_ndef_capabilities(self):
        self.clf.memory[12:16] = "\0\0\0\0"
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x00
        assert self.clf.memory[-12] == 0x40

    def test_protect_with_lockbits_but_config_is_locked(self):
        self.clf.memory[-12] = 0x40
        assert self.tag.protect() is True

    def test_protect_with_lockbits_but_unreadable_config(self):
        del self.clf.memory[-16:]
        assert self.tag.protect() is False

    @raises(ValueError)
    def test_protect_with_invalid_password(self):
        self.tag.protect("abc")

    def test_protect_with_default_password(self):
        self.clf.memory[-16:] = bytearray(16)
        assert self.tag.protect("") is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\xFF\xFF\xFF\xFF"
        assert self.clf.memory[ -4:   ] == "\x00\x00\x00\x00"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_custom_password(self):
        assert self.tag.protect("123456") is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x08
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_protect_from_page_5(self):
        assert self.tag.protect("123456", protect_from=5) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x05"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_protect_from_page_256(self):
        assert self.tag.protect("123456", protect_from=256) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\xFF"
        assert self.clf.memory[-12: -8] == "\x00\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x00
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_protect_with_read_protect_true(self):
        assert self.tag.protect("123456", read_protect=True) is True
        assert self.clf.memory[-16:-12] == "\x00\x00\x00\x03"
        assert self.clf.memory[-12: -8] == "\x80\x00\x00\x00"
        assert self.clf.memory[ -8: -4] == "\x31\x32\x33\x34"
        assert self.clf.memory[ -4:   ] == "\x35\x36\x00\x00"
        assert self.clf.memory[15] == 0x88
        assert self.tag.is_authenticated
        assert self.tag.ndef.is_writeable

    def test_authenticate_with_default_password(self):
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("") is True
        assert self.tag.is_authenticated is True

    def test_authenticate_with_custom_password(self):
        self.clf.memory[-8:-2] = "012345"
        assert self.tag.is_authenticated is False
        assert self.tag.authenticate("0123456789abcdef") is True
        assert self.tag.is_authenticated is True

    def test_authenticate_with_wrong_password(self):
        assert self.tag.authenticate("0123456789abcdef") is False
        assert self.tag.is_authenticated is False

    @raises(ValueError)
    def test_authenticate_with_invalid_password(self):
        self.tag.authenticate("abc")

    def test_authenticate_with_command_error(self):
        self.clf.tag_is_present = False
        assert self.tag.authenticate("") is False

################################################################################
#
# TEST NTAG 210
#
################################################################################

class TestNTAG210:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(20*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0B\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG210)
        assert self.tag._product == "NXP NTAG210"
        assert self.tag._cfgpage == 16

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == ' 19: 00 00 00 00 (PACK0-PACK1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-8:]
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == ' 19: ?? ?? ?? ?? (PACK0-PACK1)'

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[17*4] == 0x40

################################################################################
#
# TEST NTAG 212
#
################################################################################

class TestNTAG212:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 10 00" # 000-003
            "01 03 90 0A  34 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(41*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\1\1\0\x0E\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        assert self.tag._cfgpage == 37

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG212)
        assert self.tag._product == "NXP NTAG212"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 40: 00 00 00 00 (PACK0-PACK1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 40: ?? ?? ?? ?? (PACK0-PACK1)'

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[144:148] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[38*4] == 0x40

################################################################################
#
# TEST NTAG 213
#
################################################################################

class TestNTAG213:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
            "01 03 A0 0C  34 03 00 FE  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(45*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x0F\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        assert self.tag._cfgpage == 41

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG213)
        assert self.tag._product == "NXP NTAG213"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 44: 00 00 00 00 (PACK0-PACK1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 14
        assert lines[-1] == ' 44: ?? ?? ?? ?? (PACK0-PACK1)'

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[160:164] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[42*4] == 0x40

################################################################################
#
# TEST NTAG 215
#
################################################################################

class TestNTAG215:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 3E 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(135*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x11\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        assert self.tag._cfgpage == 131

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG215)
        assert self.tag._product == "NXP NTAG215"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '134: 00 00 00 00 (PACK0-PACK1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '134: ?? ?? ?? ?? (PACK0-PACK1)'

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[520:524] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[132*4] == 0x40

################################################################################
#
# TEST NTAG 216
#
################################################################################

class TestNTAG216:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 6D 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(231*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\4\2\1\0\x13\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        assert self.tag._cfgpage == 227

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.NTAG216)
        assert self.tag._product == "NXP NTAG216"

    def test_dump_memory(self):
        self.clf.memory[14] = 0xFF
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '230: 00 00 00 00 (PACK0-PACK1)'
        
    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == '230: ?? ?? ?? ?? (PACK0-PACK1)'

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[904:908] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.tag.ndef.is_writeable is False
        assert self.clf.memory[228*4] == 0x40

################################################################################
#
# TEST MIFARE ULTRALIGHT EV1
#
################################################################################

class TestUltralightEV1UL11:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 06 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(20*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert self.tag._product == "Mifare Ultralight EV1 (MF0UL11)"
        assert self.tag._cfgpage == 16

    def test_activation_ulh11(self):
        self.clf.version = bytearray("\0\4\3\2\1\0\x0B\3")
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert tag._product == "Mifare Ultralight EV1 (MF0ULH11)"
        assert tag._cfgpage == 16

    def test_dump_memory(self):
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == " 19: 00 00 00 00 (PACK0, PACK1, RFU, RFU)"

    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 12
        assert lines[-1] == " 19: ?? ?? ?? ?? (PACK0, PACK1, RFU, RFU)"

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[15] == 0x0F
        assert self.clf.memory[68] == 0x40
        assert self.tag.ndef.is_writeable is False

class TestUltralightEV1UL21:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 10 00" # 000-003
            "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
        ) + bytearray(41*4 - 32)
        self.clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0E\3")
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_activation(self):
        assert isinstance(self.tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert self.tag._product == "Mifare Ultralight EV1 (MF0UL21)"
        assert self.tag._cfgpage == 37

    def test_activation_ulh21(self):
        self.clf.version = bytearray("\0\4\3\2\1\0\x0E\3")
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt2_nxp.MifareUltralightEV1)
        assert tag._product == "Mifare Ultralight EV1 (MF0ULH21)"
        assert tag._cfgpage == 37

    def test_dump_memory(self):
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == " 40: 00 00 00 00 (PACK0, PACK1, RFU, RFU)"

    def test_dump_memory_with_error(self):
        del self.clf.memory[-16:]
        lines = self.tag.dump()
        assert len(lines) == 13
        assert lines[-1] == " 40: ?? ?? ?? ?? (PACK0, PACK1, RFU, RFU)"

    def test_protect_with_lockbits(self):
        assert self.tag.protect() is True
        assert self.clf.memory[10:12] == "\xFF\xFF"
        assert self.clf.memory[144:148] == "\xFF\xFF\xFF\x00"
        assert self.clf.memory[15] == 0x0F
        assert self.clf.memory[152] == 0x40
        assert self.tag.ndef.is_writeable is False

class TestActivation:
    def test_activation_with_digital_error_for_authenticate(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 1
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag

    def test_activation_with_digital_error_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.crc_error_after = 2
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
        
    def test_activation_with_unknown_version_for_get_version(self):
        tag_memory = bytearray.fromhex(
            "04 51 7C A1  E1 ED 25 80  A9 48 00 00  00 00 00 00"
        )
        clf = NTAG21xSimulator(tag_memory, "\0\4\3\1\1\0\x0B\3")
        clf.return_response = bytearray(8)
        tag = clf.connect(rdwr={'on-connect': None})
        assert type(tag) == nfc.tag.tt2.Type2Tag
        
################################################################################
#
# NFC FORUM TEST DATA
#
################################################################################

tt2_memory_layout_1 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 06 00"   # 000-003
    "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 004-007
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 012-015

tt2_memory_layout_2 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 06 00"   # 000-003
    "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00"   # 004-007
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 012-015

tt2_memory_layout_3 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 06 0F"   # 000-003
    "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00"   # 004-007
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 012-015

tt2_memory_layout_4 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 12 06 00"   # 000-003
    "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00"   # 004-007
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 012-015

tt2_memory_layout_5 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 20 06 00"   # 000-003
    "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00"   # 004-007
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"   # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 012-015

tt2_memory_layout_6 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00"   # 000-003
    "03 00 FE 00  00 00 00 00  00 00 00 00  00 00 00 00")  # 004-007
    + bytearray(0xFE * 8 - 16) + bytearray(8 * 4))         # 008-519

tt2_memory_layout_7 = (bytearray.fromhex(
    "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 FE 00"   # 000-003
    "03 FF 07 EC  C1 01 00 00  07 E5 55 01  6E 66 63 2E"   # 004-007
    "63 6F 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D")  # 008-011
    + bytearray(1984 * "\x6D") + bytearray.fromhex(        # 012-509
    "6D 6D 6D 6D  6D 6D 6D 6D  6D 6D 6D 6D  2E 63 6F 6D")  # 508-511
    + bytearray(8 * 4))                                    # 512-519

tt2_memory_layout_8 = (bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00"   # 000-003
    "01 03 A0 10  44 03 00 FE  00 00 00 00  00 00 00 00")  # 004-007
    + bytearray(0x12 * 8 - 16) + bytearray(4 * 4))         # 008-043

tt2_memory_layout_9 = (bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00"   # 000-003
    "01 03 A0 10  44 03 89 D1  01 85 55 01  6E 66 63 63"   # 004-007
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 008-011
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 012-015
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 016-019
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 020-023
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 024-027
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 028-031
    "63 63 63 63  63 63 63 63  63 63 63 63  63 63 63 63"   # 032-035
    "63 63 63 63  63 63 63 63  63 57 4C 46  2E 63 6F 6D"   # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00")) # 040-043

################################################################################
#
# NFC FORUM TEST CASES
#
################################################################################

@attr("nfc-forum")
def test_read_from_static_memory_with_version_one_dot_two():
    "TC_T2T_NDA_BV_1"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord("http://www.n.com"))
    clf = Type2TagSimulator(tt2_memory_layout_4)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 10
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_read_from_static_memory_with_version_two_dot_zero():
    "TC_T2T_NDA_BV_2"
    msg = nfc.ndef.Message(nfc.ndef.Record())
    clf = Type2TagSimulator(tt2_memory_layout_5)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is None

@attr("nfc-forum")
def test_read_from_readwrite_static_memory():
    "TC_T2T_NDA_BV_3_0"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord("http://www.n.com"))
    clf = Type2TagSimulator(tt2_memory_layout_2)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 10
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_read_from_readwrite_dynamic_memory():
    "TC_T2T_NDA_BV_3_1"
    uri = "http://www.nfc.com{0}.com".format(2009 * "m")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_7)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 2028
    assert tag.ndef.length == 2028
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_read_from_readwrite_dynamic_memory_with_lock_control_tlv():
    "TC_T2T_NDA_BV_3_2"
    uri = "http://www.nfc{0}WLF.com".format(122 * "c")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_9)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 137
    assert tag.ndef.length == 137
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_initialized_static_memory():
    "TC_T2T_NDA_BV_4_0"
    uri = "http://www.n.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_1[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_2

@attr("nfc-forum")
def test_write_to_initialized_dynamic_memory():
    "TC_T2T_NDA_BV_4_1"
    uri = "http://www.nfc.com{0}.com".format(2009 * "m")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_6[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 2028
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_7

@attr("nfc-forum")
def test_write_to_initialized_dynamic_memory_with_lock_control():
    "TC_T2T_NDA_BV_4_2"
    uri = "http://www.nfc{0}WLF.com".format(122 * "c")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_8[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 137
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_9

@attr("nfc-forum")
@raises(AttributeError)
def test_write_to_readonly_static_memory():
    "TC_T2T_NDA_BV_5"
    msg = nfc.ndef.Message(nfc.ndef.TextRecord("must fail to write"))
    clf = Type2TagSimulator(tt2_memory_layout_3)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == False
    tag.ndef.message = msg

@attr("nfc-forum")
def test_transition_static_memory_to_readonly():
    "TC_T2T_NDA_BV_6_0"
    clf = Type2TagSimulator(tt2_memory_layout_2[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 10
    tag.protect()
    assert clf.memory[15] == 0x0F
    assert clf.memory[10] == 0xFF
    assert clf.memory[11] == 0xFF
    assert tag.ndef.is_writeable == False

@attr("nfc-forum")
def test_transition_dynamic_memory_to_readonly():
    "TC_T2T_NDA_BV_6_1"
    clf = Type2TagSimulator(tt2_memory_layout_7[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 2028
    assert tag.ndef.length == 2028
    tag.protect()
    assert clf.memory[15] == 0x0F
    assert clf.memory[10] == 0xFF
    assert clf.memory[11] == 0xFF
    assert clf.memory[2048:2048+32] == 31 * "\xFF" + "\x00"
    assert tag.ndef.is_writeable == False

@attr("nfc-forum")
def test_transition_dynamic_memory_with_lock_control_to_readonly():
    "TC_T2T_NDA_BV_6_2"
    clf = Type2TagSimulator(tt2_memory_layout_9[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 137
    assert tag.ndef.length == 137
    tag.protect()
    assert clf.memory[15] == 0x0F
    assert clf.memory[10] == 0xFF
    assert clf.memory[11] == 0xFF
    assert clf.memory[160] == 0xFF
    assert clf.memory[161] == 0xFF
    assert tag.ndef.is_writeable == False
