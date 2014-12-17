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

from binascii import hexlify
from nose.tools import raises
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
        self.sector = 0
        self.dev = nfc.dev.Device()
        self.uid = bytearray.fromhex("31323334")

    def sense(self, targets):
        cfg = bytearray.fromhex("000C")
        return nfc.clf.TTA(106, cfg, self.uid)

    def exchange(self, data, timeout):
        print hexlify(data)
        data = bytearray(data)
        if data[0] == 0x78 and data[1:] == "\0\0\0\0\0\0": # RID
            return self.header + self.uid
        if data[0] == 0x00 and data[1:] == "\0\0" + self.uid: # RALL
            return self.header + self.memory[0:120]
        if data[0] == 0x01 and data[2:] == "\0" + self.uid: # READ
            assert data[1] < 128
            return bytearray([data[1], self.memory[data[1]]])
        if data[0] == 0x53 and data[3:] == self.uid: # WRITE-E
            assert data[1] < 128
            data_slice = slice(data[1], data[1] + 1)
            self.memory[data_slice] = data[2:3]
            return bytearray([data[1]]) + self.memory[data_slice]
        if data[0] == 0x1A and data[3:] == self.uid: # WRITE-NE
            assert data[1] < 128
            data_slice = slice(data[1], data[1] + 1)
            for offset, i in zip(range(data_slice), range(2, 3)):
                self.memory[offset] |= data[i]
            return bytearray([data[1]]) + self.memory[data_slice]

        if len(self.memory) <= 120:
            raise nfc.clf.TimeoutError("invalid command for static memory tag")

        if data[0] == 0x02 and data[2:] == 8*"\0" + self.uid: # READ8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            return bytearray([data[1]]) + self.memory[data_slice]
        if data[0] == 0x10 and data[2:] == 8*"\0" + self.uid: # RSEG
            data_slice = slice((data[1]>>4) * 128, ((data[1]>>4) + 1) * 128)
            return bytearray([data[1]]) + self.memory[data_slice]
        if data[0] == 0x54 and data[10:] == self.uid: # WRITE-E8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            self.memory[data_slice] = data[2:10]
            return bytearray([data[1]]) + self.memory[data_slice]
        if data[0] == 0x1B and data[10:] == self.uid: # WRITE-NE8
            data_slice = slice(data[1] * 8, (data[1] + 1) * 8)
            for offset, i in zip(range(data_slice), range(2, 10)):
                self.memory[offset] |= data[i]
            return bytearray([data[1]]) + self.memory[data_slice]

        raise nfc.clf.TimeoutError("invalid command for type 1 tag")
        
    def set_communication_mode(self, brm, **kwargs):
        pass

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

def test_read_from_readwrite_static_memory_layout_1():
    # TC_T1T_READ_BV_1
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

def test_write_to_initialized_static_memory_layout_2():
    # TC_T1T_WRITE_BV_1
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

def test_read_from_readwrite_static_memory_layout_3():
    # TC_T1T_READ_BV_2, TC_T1T_READ_BV_3
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

def test_write_to_readwrite_static_memory_layout_1():
    # TC_T1T_WRITE_BV_2
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

def test_write_to_readonly_static_memory_layout_7():
    # TC_T1T_WRITE_BV_3
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

def test_read_from_readwrite_dynamic_memory_layout_4():
    # TC_T1T_READ_BV_4
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

def test_write_to_initialized_static_memory_layout_5():
    # TC_T1T_WRITE_BV_4
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

def test_read_from_readwrite_dynamic_memory_layout_6():
    # TC_T1T_READ_BV_4
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

def test_write_to_initialized_static_memory_layout_4():
    # TC_T1T_WRITE_BV_5
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

def test_transition_to_readonly():
    # TC_T1T_TRANS_BV_1
    raise SkipTest()

################################################################################
#
# ADDITIONAL NFCPY TEST CASES
#
################################################################################

def test_read_from_static_memory_with_proprietary_header_rom():
    clf = Type1TagSimulator(tt1_memory_layout_1, header_rom="\0\0")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.read_all() == "\0\0" + tt1_memory_layout_1
    assert tag.read_byte(8) == 0xE1
    assert tag.read_byte(9) == 0x10
    assert tag.ndef is None

def test_read_from_static_memory_with_no_ndef_magic_byte():
    tag_memory = tt1_memory_layout_1[:]
    tag_memory[8] = 0x00 # overwrite ndef magic byte
    clf = Type1TagSimulator(tag_memory, "\x11\x00")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.read_all() == "\x11\x00" + tag_memory
    assert tag.read_byte(8) == 0x00
    assert tag.read_byte(9) == 0x10
    assert tag.ndef is None

def test_read_from_static_memory_with_version_zero_dot_one_tag():
    tag_memory = tt1_memory_layout_1[:]
    tag_memory[9] = 0x01 # overwrite ndef mapping version
    clf = Type1TagSimulator(tag_memory, "\x11\x00")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.read_all() == "\x11\x00" + tag_memory
    assert tag.read_byte(8) == 0xE1
    assert tag.read_byte(9) == 0x01
    assert tag.ndef is None

def test_read_from_static_memory_with_version_nine_dot_zero():
    tag_memory = tt1_memory_layout_1[:]
    tag_memory[9] = 0x90 # overwrite ndef mapping version
    clf = Type1TagSimulator(tag_memory, "\x11\x00")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.read_all() == "\x11\x00" + tag_memory
    assert tag.read_byte(8) == 0xE1
    assert tag.read_byte(9) == 0x90
    assert tag.ndef is None

def test_read_from_static_memory_with_version_one_dot_nine():
    tag_memory = tt1_memory_layout_1[:]
    tag_memory[9] = 0x19 # overwrite ndef mapping version
    uri = 'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type1TagSimulator(tag_memory, "\x11\x00")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.read_all() == "\x11\x00" + tag_memory
    assert tag.read_byte(8) == 0xE1
    assert tag.read_byte(9) == 0x19
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 42
    assert tag.ndef.message == msg

def test_read_from_static_memory_with_invalid_ndef_data():
    tag_memory = tt1_memory_layout_1[:]
    tag_memory[13] = 40 # shrink ndef message length
    clf = Type1TagSimulator(tag_memory, "\x11\x00")
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 90
    assert tag.ndef.length == 40
    assert tag.ndef.message == nfc.ndef.Message(nfc.ndef.Record())

