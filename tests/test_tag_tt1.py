#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
import nfc.tag.tt1

from binascii import hexlify
from nose.tools import raises
from nose.plugins.attrib import attr
from nose.plugins.skip import SkipTest

import logging
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt1").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)

class Type1TagSimulator(nfc.clf.ContactlessFrontend):
    def __init__(self, tag_memory, header_rom=None):
        self.header = bytearray([0x12 if len(tag_memory)>120 else 0x11, 0x00])\
                      if header_rom is None else bytearray(header_rom)
        self.memory = tag_memory
        self.dev = nfc.dev.Device()
        self.uid = bytearray.fromhex("31323334")
        self.tag_is_present = True # to simulate tag removal
        self.return_response = None # force specific response

    def sense(self, targets):
        cfg = bytearray.fromhex("000C")
        return nfc.clf.TTA(106, cfg, self.uid)

    def exchange(self, data, timeout):
        #print hexlify(data)
        if self.tag_is_present is False:
            raise nfc.clf.TimeoutError("mute tag")
        if self.return_response is not None:
            return self.return_response
        
        data = bytearray(data)
        if data[0] == 0x78 and data[1:] == "\0\0\0\0\0\0": # RID
            return self.header + self.uid
        if data[0] == 0x00 and data[1:] == "\0\0" + self.uid: # RALL
            return self.header + self.memory[0:120]
        if data[0] == 0x01 and data[2:] == "\0" + self.uid: # READ
            assert data[1] < 128
            return bytearray([data[1], self.memory[data[1]]])
        if data[0] == 0x53 and data[3:] == self.uid: # WRITE-E
            address, value = data[1:3]
            assert address < 128
            self.memory[address] = value
            return bytearray([address, self.memory[address]])
        if data[0] == 0x1A and data[3:] == self.uid: # WRITE-NE
            address, value = data[1:3]
            assert address < 128
            self.memory[address] |= value
            return bytearray([address, self.memory[address]])

        if len(self.memory) <= 120:
            raise nfc.clf.TimeoutError("invalid command for static memory")

        if data[0] == 0x02 and data[2:] == 8*"\0" + self.uid: # READ8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            if data_slice.stop <= len(self.memory):
                return bytearray([data[1]]) + self.memory[data_slice]
            else: return bytearray([data[1]]) + bytearray(8)
        if data[0] == 0x10 and data[2:] == 8*"\0" + self.uid: # RSEG
            data_slice = slice((data[1]>>4) * 128, ((data[1]>>4)+1) * 128)
            if data_slice.stop <= len(self.memory):
                return bytearray([data[1]]) + self.memory[data_slice]
            else: return bytearray([data[1]]) + bytearray(128)
        if data[0] == 0x54 and data[10:] == self.uid: # WRITE-E8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            if data_slice.stop <= len(self.memory):
                self.memory[data_slice] = data[2:10]
                return bytearray([data[1]]) + self.memory[data_slice]
            else: return bytearray([data[1]]) + bytearray(8)
        if data[0] == 0x1B and data[10:] == self.uid: # WRITE-NE8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            if data_slice.stop <= len(self.memory):
                for a, i in zip(range(*data_slice.indices(0x800)),range(2,10)):
                    self.memory[a] |= data[i]
                return bytearray([data[1]]) + self.memory[data_slice]
            else: return bytearray([data[1]]) + bytearray(8)

        raise nfc.clf.TimeoutError("invalid command for type 1 tag")
        
    def set_communication_mode(self, brm, **kwargs):
        pass

###############################################################################
#
# TEST TYPE 1 TAG NDEF
#
###############################################################################

class TestNdef:
    def setup(self):
        self.static_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 0E 00  03 2A D1 01"
            "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
            "01 60 00 00  00 00 00 00"
        )
        uri = 'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'
        self.static_ndef_message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        self.static_ndef_capacity = 90
        self.static_ndef_length = 42
        
        self.dynamic_memory = bytearray.fromhex(
            "00 11 22 33  44 55 66 77  E1 10 3F 00  01 03 F2 30"
            "33 02 03 F0  02 03 03 FF  01 CD C1 01  00 00 01 C6"
            "55 01 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  55 55 AA AA  12 49 06 00"
            "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 1
            "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
            "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
            "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
            "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
            # Segment 2
            "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
            "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
            "77 78 79 7A  61 62 63 64  65 66 67 68  69 6A 6B 6C"
            "6D 6E 6F 70  71 72 73 74  75 76 77 78  79 7A 61 62"
            "63 64 65 66  67 68 69 6A  6B 6C 6D 6E  6F 70 71 72"
            "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
            "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
            "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
            # Segment 3
            "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
            "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
            "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
            "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
            "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
            "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
            "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
            "77 78 79 7A  61 62 63 64  65 66 67 2E  63 6F 6D FE"
        )
        uri = "http://www." + (17*"abcdefghijklmnopqrstuvwxyz") + "abcdefg.com"
        self.dynamic_ndef_message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        self.dynamic_ndef_capacity = 462
        self.dynamic_ndef_length = 461

    def test_read_proprietary_memory(self):
        clf = Type1TagSimulator(self.static_memory, "\x00\x00")
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None
        assert tag.read_all() == "\x00\x00" + self.static_memory

    def test_read_unformatted_memory(self):
        self.static_memory[8] = 0
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None
        assert tag.read_all() == "\x11\x00" + self.static_memory

    def test_read_unknown_ndef_version(self):
        self.static_memory[9] = 0
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None
        assert tag.read_all() == "\x11\x00" + self.static_memory

    def test_read_from_static_memory(self):
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.is_readable == True
        assert tag.ndef.is_writeable == True
        assert tag.ndef.capacity == self.static_ndef_capacity
        assert tag.ndef.length == self.static_ndef_length
        assert tag.ndef.message == self.static_ndef_message

    def test_read_from_dynamic_memory(self):
        clf = Type1TagSimulator(self.dynamic_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.is_readable == True
        assert tag.ndef.is_writeable == True
        assert tag.ndef.capacity == self.dynamic_ndef_capacity
        assert tag.ndef.length == self.dynamic_ndef_length
        assert tag.ndef.message == self.dynamic_ndef_message

    def test_read_future_minor_version(self):
        self.static_memory[9] = 0x1F
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.message == self.static_ndef_message

    def test_read_ndef_after_null_tlv(self):
        self.static_memory[12:104] = "\x00" + self.static_memory[12:103]
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.message == self.static_ndef_message

    def test_read_ndef_after_unknown_tlv(self):
        self.static_memory[12:104] = "\xFD\x01\0" + self.static_memory[12:101]
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.message == self.static_ndef_message

    def test_read_wrong_ndef_data_length(self):
        self.static_memory[13] = self.static_ndef_length - 1
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None
        assert tag.ndef.capacity == self.static_ndef_capacity
        assert tag.ndef.length == self.static_ndef_length - 1
        assert tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())

    def test_read_until_terminator_tlv(self):
        self.static_memory[12:16] = "000000FE".decode("hex")
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None

    def test_read_until_end_of_memory(self):
        self.static_memory[8:104] = "E110010000000000".decode("hex") + \
                                    self.static_memory[12:100]
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None

    def test_read_beyond_end_of_memory(self):
        self.static_memory[8:104] = "E1100E000203215703".decode("hex") + \
                                    self.static_memory[12:99]
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None

    def test_write_to_static_memory(self):
        self.static_memory[12:104] = "\x03" + bytearray(91)
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef.length == 0
        tag.ndef.message = self.static_ndef_message
        assert tag.ndef.length == self.static_ndef_length
        assert self.static_memory[13] == self.static_ndef_length

    def test_write_to_dynamic_memory(self):
        self.dynamic_memory[22:512] = "\x03" + bytearray(489)
        clf = Type1TagSimulator(self.dynamic_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef.length == 0
        tag.ndef.message = self.dynamic_ndef_message
        assert tag.ndef.length == self.dynamic_ndef_length

    def test_write_terminator_after_skip(self):
        clf = Type1TagSimulator(self.dynamic_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        uri = 'http://www.' + (71 * 'x') + '.com'
        tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert self.dynamic_memory[128] == 0xFE

    def test_write_largest_possible_ndef(self):
        clf = Type1TagSimulator(self.static_memory)
        tag = clf.connect(rdwr={'on-connect': None})
        uri = 'http://www.' + (81 * 'x') + '.com'
        tag.ndef.message = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
        assert tag.ndef.length == tag.ndef.capacity

###############################################################################
#
# TEST TYPE 1 TAG COMMANDS
#
###############################################################################

class TestTagCommands:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 3F 00  01 03 F2 30"
            "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
            "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 1
            "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
            "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
            # Segment 2
            "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
            "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
            "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 3
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        )
        self.clf = Type1TagSimulator(tag_memory, "\x00\x00")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        
    def test_read_id(self):
        assert self.tag.read_id() == "\0\0" + self.clf.uid 

    def test_read_all(self):
        assert self.tag.read_all() == "\0\0" + self.clf.memory[0:120] 

    def test_read_byte(self):
        assert self.tag.read_byte(8) == 0xE1

    @raises(ValueError)
    def test_read_byte_invalid_address(self):
        self.tag.read_byte(128)

    def test_read_block(self):
        assert self.tag.read_block(1) == self.clf.memory[8:16]

    @raises(ValueError)
    def test_read_block_invalid_number(self):
        self.tag.read_block(256)

    def test_read_segment(self):
        assert self.tag.read_segment(1) == self.clf.memory[128:256]

    @raises(ValueError)
    def test_read_segment_invalid_number(self):
        self.tag.read_segment(16)

    @raises(nfc.tag.tt1.Type1TagCommandError)
    def test_read_segment_response_error(self):
        self.clf.return_response = "\x01" + bytearray(127)
        self.tag.read_segment(1)

    def test_write_byte_erase_true(self):
        self.tag.write_byte(8, 0xE0)
        assert self.clf.memory[8] == 0xE0

    def test_write_byte_erase_false(self):
        self.tag.write_byte(8, 0x02, erase=False)
        assert self.clf.memory[8] == 0xE3

    @raises(ValueError)
    def test_write_byte_invalid_address(self):
        self.tag.write_byte(128, 0xFF)

    def test_write_block_erase_true(self):
        self.tag.write_block(1, bytearray(8))
        assert self.clf.memory[8:16] == bytearray(8)

    def test_write_block_erase_false(self):
        self.tag.write_block(1, bytearray(8*chr(2)), erase=False)
        assert self.clf.memory[8:12] == "\xE3\x12\x3F\x02"

    @raises(ValueError)
    def test_write_block_invalid_number(self):
        self.tag.write_block(256, bytearray(8))

    @raises(nfc.tag.tt1.Type1TagCommandError)
    def test_write_block_response_error(self):
        self.clf.return_response = "\x01" + bytearray(7)
        self.tag.write_block(1, bytearray(8))

    @raises(nfc.tag.tt1.Type1TagCommandError)
    def test_write_block_write_error(self):
        self.clf.return_response = "\x01" + bytearray(8*chr(1))
        self.tag.write_block(1, bytearray(8))

    @raises(nfc.tag.tt1.Type1TagCommandError)
    def test_transceive_timeout_error(self):
        self.tag.transceive(bytearray(8))

###############################################################################
#
# TEST TYPE 1 TAG PROCEDURES
#
###############################################################################

class TestTagProcedures:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 3F 00  01 03 F2 30"
            "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
            "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 1
            "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
            "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
            # Segment 2
            "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
            "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
            "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 3
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        )
        self.clf = Type1TagSimulator(tag_memory, "\x12\x00")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        
    def test_is_present_with_tag_present(self):
        assert self.tag.is_present is True

    def test_is_present_with_mute_tag(self):
        self.clf.tag_is_present = False
        assert self.tag.is_present is False

    def test_dump_with_default_arguments(self):
        lines = self.tag.dump()
        assert len(lines) == 42

    def test_dump_with_earlier_stop(self):
        lines = self.tag._dump(17)
        assert len(lines) == 18

    def test_dump_with_later_stop(self):
        lines = self.tag._dump(256)
        print '\n'.join(lines)
        assert lines[-1] == "255: 00 00 00 00 00 00 00 00 |........|"

    def test_protect_with_default_arguments(self):
        assert self.tag.protect() is True
        assert self.clf.memory[11] & 0x0F == 0x0F

    def test_protect_with_password(self):
        assert self.tag.protect("abcdefg") is False

    def test_protect_with_non_ndef_tag(self):
        self.clf.memory[8] = 0
        assert self.tag.protect() is False

    def test_format(self):
        assert self.tag.format() is None

###############################################################################
#
# TEST TYPE 1 TAG TOPAZ
#
###############################################################################

class TestTopaz:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 0E 00  03 2A D1 01"
            "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
            "01 60 00 00  00 00 00 00"
        )
        self.clf = Type1TagSimulator(tag_memory, "\x11\x48")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        
    def test_dump(self):
        lines = self.tag.dump()
        print '\n'.join(lines)
        assert len(lines) == 16
        assert lines[-1].startswith(" 14: 01 60 00 00 00 00 00 00")

    def test_format_with_default_arguments(self):
        assert self.tag.format() is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.capacity == 90
        assert self.tag.ndef.length == 0
        assert self.tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())
        assert self.clf.memory[8:14] == "\xE1\x10\x0E\x00\x03\x00"

    def test_format_with_wipe_argument_zero(self):
        assert self.tag.format(wipe=0) is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.capacity == 90
        assert self.tag.ndef.length == 0
        assert self.tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())
        assert self.clf.memory[12:104] == "\x03" + bytearray(91)

    def test_format_with_invalid_version_number(self):
        assert self.tag.format(version=0xFF) is False

    def test_format_with_version_one_dot_fifteen(self):
        assert self.tag.format(version=0x1F) is True
        assert self.clf.memory[9] == 0x1F

    def test_protect_with_default_arguments(self):
        assert self.tag.protect() is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == False
        assert self.clf.memory[112] == 0xFF
        assert self.clf.memory[113] == 0xFF

    def test_protect_with_password_argument(self):
        assert self.tag.protect("abcdefg") is False

###############################################################################
#
# TEST TYPE 1 TAG TOPAZ 512
#
###############################################################################

class TestTopaz512:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 3F 00  01 03 F2 30"
            "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
            "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 1
            "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
            "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
            "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
            "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
            "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
            "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
            # Segment 2
            "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
            "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
            "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            # Segment 3
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        )
        self.clf = Type1TagSimulator(tag_memory, "\x12\x4C")
        self.tag = self.clf.connect(rdwr={'on-connect': None})
        
    def test_dump(self):
        lines = self.tag.dump()
        print '\n'.join(lines)
        assert len(lines) == 42
        assert lines[-1].startswith(" 63: 00 00 00 00 00 00 00 00")

    def test_format_with_default_arguments(self):
        assert self.tag.format() is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.capacity == 462
        assert self.tag.ndef.length == 0
        assert self.tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())
        assert self.clf.memory[ 8:12] == "\xE1\x10\x3F\x00"
        assert self.clf.memory[12:16] == "\x01\x03\xF2\x30"
        assert self.clf.memory[16:20] == "\x33\x02\x03\xF0"
        assert self.clf.memory[20:24] == "\x02\x03\x03\x00"

    def test_format_with_wipe_argument_zero(self):
        assert self.tag.format(wipe=0) is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.capacity == 462
        assert self.tag.ndef.length == 0
        assert self.tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())
        assert self.clf.memory[12:] == "0103F230330203F0020303".decode("hex")\
            + bytearray(81) + self.clf.memory[104:128] + bytearray(3*128)

    def test_format_with_invalid_version_number(self):
        assert self.tag.format(version=0xFF) is False

    def test_format_with_version_one_dot_fifteen(self):
        assert self.tag.format(version=0x1F) is True
        assert self.clf.memory[9] == 0x1F

    def test_protect_with_default_arguments(self):
        assert self.tag.protect() is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == False
        assert self.clf.memory[112] == 0xFF
        assert self.clf.memory[113] == 0xFF
        assert self.clf.memory[120] == 0xFF
        assert self.clf.memory[121] == 0xFF

    def test_protect_with_password_argument(self):
        assert self.tag.protect("abcdefg") is False

###############################################################################
#
# TEST TYPE 1 TAG MEMORY READER
#
###############################################################################

class TestMemoryReader:
    def setup(self):
        tag_memory = bytearray.fromhex(
            "31 32 33 34  35 36 37 00  E1 10 1F 00  03 2A D1 01"
            "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
            "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
            "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
            "01 60 00 00  00 00 00 00  12 00 00 00  00 00 00 00"
            # Segment 1
            "34 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
        )
        self.clf = Type1TagSimulator(tag_memory)
        self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_byte_access_at_offset_0(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[0] == self.clf.memory[0]
        
    def test_byte_access_at_offset_120(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[120] == self.clf.memory[120]
        
    def test_byte_access_at_offset_128(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[128] == self.clf.memory[128]
        
    def test_byte_assign_at_offset_0(self):
        self.clf.header = bytearray("\x11\x00")
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xFF

    def test_byte_assign_at_offset_120(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[120] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[120] == 0xFF

    def test_byte_assign_at_offset_128(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[128] = 0xFF
        tag_memory.synchronize()
        assert self.clf.memory[128] == 0xFF

    @raises(TypeError)
    def test_byte_delete(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        del tag_memory[0]
    
    def test_slice_access_at_offset_0(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[0:1] == self.clf.memory[0:1]
        
    def test_slice_access_at_offset_120(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[120:121] == self.clf.memory[120:121]
        
    def test_slice_access_at_offset_128(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        assert tag_memory[128:129] == self.clf.memory[128:129]
        
    def test_slice_assign_at_offset_0(self):
        self.clf.header = bytearray("\x11\x00")
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0:1] = "\xFF"
        tag_memory.synchronize()
        assert self.clf.memory[0:1] == "\xFF"

    def test_slice_assign_at_offset_120(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[120:121] = "\xFF"
        tag_memory.synchronize()
        assert self.clf.memory[120:121] == "\xFF"

    def test_slice_assign_at_offset_128(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[128:129] = "\xFF"
        tag_memory.synchronize()
        assert self.clf.memory[128:129] == "\xFF"

    @raises(ValueError)
    def test_slice_assign_with_mismatch_length(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0:2] = "\x00\x11\x22"

    @raises(TypeError)
    def test_slice_delete(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        del tag_memory[0:2]

    @raises(IndexError)
    def test_read_from_mute_tag_at_offset_0(self):
        self.clf.tag_is_present = False
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0]

    @raises(IndexError)
    def test_read_from_mute_tag_at_offset_120(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0]
        self.clf.tag_is_present = False
        tag_memory[120]

    @raises(IndexError)
    def test_read_from_mute_tag_at_offset_128(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[120]
        self.clf.tag_is_present = False
        tag_memory[128]

    def test_write_to_mute_tag(self):
        tag_memory = nfc.tag.tt1.Type1TagMemoryReader(self.tag)
        tag_memory[0] = 0xA5
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xA5
        self.clf.tag_is_present = False
        tag_memory[0] = 0x5A
        tag_memory.synchronize()
        assert self.clf.memory[0] == 0xA5

################################################################################
#
# NFC FORUM TEST DATA
#
################################################################################

tt1_memory_layout_1 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 0E 00  03 2A D1 01"
    "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
    "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
    "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
    "01 60 00 00  00 00 00 00"
)
tt1_memory_layout_2 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 0E 00  03 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
    "01 60 00 00  00 00 00 00"
)
tt1_memory_layout_3 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 0E 00  03 5A D1 01"
    "56 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
    "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
    "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
    "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
    "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
    "7A 61 62 63  2E 63 6F 6D  55 55 AA AA  00 00 00 00"
    "01 60 00 00  00 00 00 00"
)
tt1_memory_layout_4 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 3F 00  01 03 F2 30"
    "33 02 03 F0  02 03 03 FE  D1 01 FA 55  01 61 62 63"
    "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
    "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
    "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
    "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
    "70 71 72 73  74 75 76 77  55 55 AA AA  12 49 06 00"
    "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 1
    "78 79 7A 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
    "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
    "64 65 66 67  68 69 6A 6B  6C 6D 6E 6F  70 71 72 73"
    "74 75 76 77  78 79 7A 61  62 63 64 65  66 67 68 69"
    "6A 6B 6C 6D  6E 6F 70 71  72 73 74 75  76 77 78 79"
    "7A 61 62 63  64 65 66 67  68 69 6A 6B  6C 6D 6E 6F"
    "70 71 72 73  74 75 76 77  78 79 7A 61  62 63 64 65"
    "66 67 68 69  6A 6B 6C 6D  6E 6F 70 71  72 73 74 75"
    # Segment 2
    "76 77 78 79  7A 61 62 63  64 65 66 67  68 69 6A 6B"
    "6C 6D 6E 6F  70 71 72 73  74 75 76 77  78 79 7A 61"
    "62 63 64 65  66 67 68 69  6A 6B 2E 63  6F 6D FE 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 3
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)
tt1_memory_layout_5 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 3F 00  01 03 F2 30"
    "33 02 03 F0  02 03 03 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  55 55 AA AA  12 49 06 00"
    "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 1
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 2
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 3
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
)
tt1_memory_layout_6 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 3F 00  01 03 F2 30"
    "33 02 03 F0  02 03 03 FF  01 CD C1 01  00 00 01 C6"
    "55 01 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
    "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
    "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
    "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
    "6B 6C 6D 6E  6F 70 71 72  55 55 AA AA  12 49 06 00"
    "01 E0 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    # Segment 1
    "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
    "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
    "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
    "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
    "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
    "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
    "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
    "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
    # Segment 2
    "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
    "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
    "77 78 79 7A  61 62 63 64  65 66 67 68  69 6A 6B 6C"
    "6D 6E 6F 70  71 72 73 74  75 76 77 78  79 7A 61 62"
    "63 64 65 66  67 68 69 6A  6B 6C 6D 6E  6F 70 71 72"
    "73 74 75 76  77 78 79 7A  61 62 63 64  65 66 67 68"
    "69 6A 6B 6C  6D 6E 6F 70  71 72 73 74  75 76 77 78"
    "79 7A 61 62  63 64 65 66  67 68 69 6A  6B 6C 6D 6E"
    # Segment 3
    "6F 70 71 72  73 74 75 76  77 78 79 7A  61 62 63 64"
    "65 66 67 68  69 6A 6B 6C  6D 6E 6F 70  71 72 73 74"
    "75 76 77 78  79 7A 61 62  63 64 65 66  67 68 69 6A"
    "6B 6C 6D 6E  6F 70 71 72  73 74 75 76  77 78 79 7A"
    "61 62 63 64  65 66 67 68  69 6A 6B 6C  6D 6E 6F 70"
    "71 72 73 74  75 76 77 78  79 7A 61 62  63 64 65 66"
    "67 68 69 6A  6B 6C 6D 6E  6F 70 71 72  73 74 75 76"
    "77 78 79 7A  61 62 63 64  65 66 67 2E  63 6F 6D FE"
)
tt1_memory_layout_7 = bytearray.fromhex(
    "00 11 22 33  44 55 66 77  E1 10 0E 0F  03 2A D1 01"
    "26 55 01 61  62 63 64 65  66 67 68 69  6A 6B 6C 6D"
    "6E 6F 70 71  72 73 74 75  76 77 78 79  7A 61 62 63"
    "64 65 66 67  2E 63 6F 6D  FE 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00"
    "00 00 00 00  00 00 00 00  55 55 AA AA  00 00 00 00"
    "FF FF 00 00  00 00 00 00"
)

################################################################################
#
# NFC FORUM TEST CASES
#
################################################################################

@attr("nfc-forum")
def test_read_from_readwrite_static_memory_layout_1():
    "TC_T1T_READ_BV_1"
    uri = 'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_1)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 42
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_initialized_static_memory_layout_2():
    "TC_T1T_WRITE_BV_1"
    uri = 'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_2[:])
    tag = clf.connect(rdwr={'on-connect': None})
    tag.ndef.message = msg
    assert clf.memory == tt1_memory_layout_1
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 42
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_read_from_readwrite_static_memory_layout_3():
    "TC_T1T_READ_BV_2" # also TC_T1T_READ_BV_3
    uri = "http://www." + 3*"abcdefghijklmnopqrstuvwxyz" + "abc.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_3)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 90
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_readwrite_static_memory_layout_1():
    "TC_T1T_WRITE_BV_2"
    uri = "http://www." + 3*"abcdefghijklmnopqrstuvwxyz" + "abc.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_1[:])
    tag = clf.connect(rdwr={'on-connect': None})
    tag.ndef.message = msg
    assert clf.memory == tt1_memory_layout_3
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 90
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_readonly_static_memory_layout_7():
    "TC_T1T_WRITE_BV_3"
    uri = "http://www." + 3*"abcdefghijklmnopqrstuvwxyz" + "abc.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_7[:])
    tag = clf.connect(rdwr={'on-connect': None})
    try: tag.ndef.message = msg
    except AttributeError: pass
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == False
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 42

@attr("nfc-forum")
def test_read_from_readwrite_dynamic_memory_layout_4():
    "TC_T1T_READ_BV_4"
    uri = "http://www." + 9*"abcdefghijklmnopqrstuvwxyz" + "abcdefghijk.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_4)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 462
    assert tag.ndef.length == 254
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_initialized_static_memory_layout_5():
    "TC_T1T_WRITE_BV_4"
    uri = "http://www." + 9*"abcdefghijklmnopqrstuvwxyz" + "abcdefghijk.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_5[:])
    tag = clf.connect(rdwr={'on-connect': None})
    tag.ndef.message = msg
    assert clf.memory == tt1_memory_layout_4
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 462
    assert tag.ndef.length == 254

@attr("nfc-forum")
def test_read_from_readwrite_dynamic_memory_layout_6():
    "TC_T1T_READ_BV_5"
    uri = "http://www." + 17*"abcdefghijklmnopqrstuvwxyz" + "abcdefg.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_6)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 462
    assert tag.ndef.length == 461
    assert tag.ndef.message == msg

@attr("nfc-forum")
def test_write_to_initialized_static_memory_layout_4():
    "TC_T1T_WRITE_BV_5"
    uri = "http://www." + 17*"abcdefghijklmnopqrstuvwxyz" + "abcdefg.com"
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tt1_memory_layout_4[:])
    tag = clf.connect(rdwr={'on-connect': None})
    tag.ndef.message = msg
    assert clf.memory == tt1_memory_layout_6
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 462
    assert tag.ndef.length == 461

