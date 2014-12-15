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

from binascii import hexlify
from nose.tools import raises

import logging
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt2").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)

class Type2TagSimulator(nfc.clf.ContactlessFrontend):
    def __init__(self, tag_memory_layout):
        self.memory = tag_memory_layout
        self.sector = 0
        self.dev = nfc.dev.Device()

    def sense(self, targets):
        cfg = bytearray.fromhex("440000")
        uid = bytearray.fromhex("31323334353637")
        return nfc.clf.TTA(106, cfg, uid)

    def exchange(self, data, timeout):
        data = bytearray(data)
        if data[0] == 0x30: # READ COMMAND
            offset = self.sector * 1024 + data[1] * 4
            if offset < len(self.memory):
                data = self.memory[offset:offset+16]
                data.extend(self.memory[0:(16-len(data))])
                return data
            else: return "\x00" # NAK
        if data[0] == 0xA2: # WRITE COMMAND
            offset = self.sector * 1024 + data[1] * 4
            self.memory[offset:offset+4] = data[2:6]
            return bytearray([0x0A])
        if data == "\xC2\xFF": # SECTOR_SELECT 1
            return bytearray([0x0A])
        if len(data) == 4 and timeout == 0.001: # SECTOR_SELECT 2
            self.sector = data[0]
        raise nfc.clf.TimeoutError("simulated")
        
    def set_communication_mode(self, brm, **kwargs):
        pass

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

def test_read_from_static_memory_with_version_one_dot_two():
    # TC_T2T_NDA_BV_1
    msg = nfc.ndef.Message(nfc.ndef.UriRecord("http://www.n.com"))
    clf = Type2TagSimulator(tt2_memory_layout_4)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 10
    assert tag.ndef.message == msg

def test_read_from_static_memory_with_version_two_dot_zero():
    # TC_T2T_NDA_BV_2
    msg = nfc.ndef.Message(nfc.ndef.Record())
    clf = Type2TagSimulator(tt2_memory_layout_5)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == False
    assert tag.ndef.is_writeable == False
    assert tag.ndef.capacity == 0
    assert tag.ndef.length == 0
    assert tag.ndef.message == msg

def test_read_from_readwrite_static_memory():
    # TC_T2T_NDA_BV_3_0
    msg = nfc.ndef.Message(nfc.ndef.UriRecord("http://www.n.com"))
    clf = Type2TagSimulator(tt2_memory_layout_2)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 46
    assert tag.ndef.length == 10
    assert tag.ndef.message == msg

def test_read_from_readwrite_dynamic_memory():
    # TC_T2T_NDA_BV_3_1
    uri = "http://www.nfc.com{0}.com".format(2009 * "m")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_7)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 2028
    assert tag.ndef.length == 2028
    assert tag.ndef.message == msg

def test_read_from_readwrite_dynamic_memory_with_lock_control_tlv():
    # TC_T2T_NDA_BV_3_2
    uri = "http://www.nfc{0}WLF.com".format(122 * "c")
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(uri))
    clf = Type2TagSimulator(tt2_memory_layout_9)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == True
    assert tag.ndef.capacity == 137
    assert tag.ndef.length == 137
    assert tag.ndef.message == msg

def test_write_to_initialized_static_memory():
    # TC_T2T_NDA_BV_4_0
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

def test_write_to_initialized_dynamic_memory():
    # TC_T2T_NDA_BV_4_1
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

def test_write_to_initialized_dynamic_memory_with_lock_control():
    # TC_T2T_NDA_BV_4_2
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

@raises(AttributeError)
def test_write_to_readonly_static_memory():
    # TC_T2T_NDA_BV_5
    msg = nfc.ndef.Message(nfc.ndef.TextRecord("must fail to write"))
    clf = Type2TagSimulator(tt2_memory_layout_3)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == False
    tag.ndef.message = msg

def test_transition_static_memory_to_readonly():
    # TC_T2T_NDA_BV_6_0 (incomplete)
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

def test_transition_dynamic_memory_to_readonly():
    # TC_T2T_NDA_BV_6_1 (incomplete)
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

def test_transition_dynamic_memory_with_lock_control_to_readonly():
    # TC_T2T_NDA_BV_6_2 (incomplete)
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

################################################################################
#
# ADDITIONAL NFCPY TEST CASES
#
################################################################################

tt2_memory_layout_10_initialized = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
    "00 00 03 00  FE 00 00 00  00 00 00 00  00 00 00 00" # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 024-027
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_10_readwrite = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 020-023
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 024-027
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_10_readonly = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 FF FF  E1 10 12 0F" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 020-023
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 024-027
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "FF 0F 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_11_initialized = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 02  03 50 10 04" # 004-007
    "00 00 03 00  FE 00 00 00  00 00 00 00  00 00 00 00" # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 024-027
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_11_readwrite = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 02  03 50 10 04" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 024-027
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_11_readonly = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 FF FF  E1 10 12 0F" # 000-003
    "00 00 00 00  00 00 00 00  00 00 00 02  03 50 10 04" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 024-027
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "FF 0F 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_12_initialized = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 01  03 50 10 24  00 00 00 02  03 52 0E 04" # 004-007
    "00 00 03 00  FE 00 00 00  00 00 00 00  00 00 00 00" # 008-011
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 012-015
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 024-027
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_12_readwrite = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 00 00  E1 10 12 00" # 000-003
    "00 00 00 01  03 50 10 24  00 00 00 02  03 52 0E 04" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 024-027
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)
tt2_memory_layout_12_readonly = bytearray.fromhex(
    "04 51 7C A1  E1 ED 25 80  A9 48 FF FF  E1 10 12 0F" # 000-003
    "00 00 00 01  03 50 10 24  00 00 00 02  03 52 0E 04" # 004-007
    "00 00 03 44  d1 02 3f 53  70 91 01 0a  55 03 6e 66" # 008-011
    "63 70 79 2e  6f 72 67 51  01 2d 54 02  65 6e 50 79" # 012-015
    "74 68 6f 6e  20 6d 6f 64  75 6c 65 20  66 6f 72 20" # 016-019
    "FF FF 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 020-023
    "6e 65 61 72  20 66 69 65  6c 64 20 63  6f 6d 6d 75" # 024-027
    "6e 69 63 61  74 69 6f 6e  FE 00 00 00  00 00 00 00" # 028-031
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 032-035
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 036-039
    "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 040-043
)

def test_read_from_readwrite_memory_with_null_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_10_readwrite)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 124
    assert tag.ndef.length == 68
    assert tag.ndef.message == msg

def test_read_from_readwrite_memory_with_memory_control_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_11_readwrite)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 68
    assert tag.ndef.message == msg

def test_read_from_readwrite_memory_with_memory_and_lock_control_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_12_readwrite)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 68
    assert tag.ndef.message == msg

def test_write_to_initialized_memory_with_null_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_10_initialized[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 124
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_10_readwrite

def test_write_to_initialized_memory_with_memory_control_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_11_initialized[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_11_readwrite

def test_write_to_initialized_memory_with_memory_and_lock_control_tlv():
    txt = "Python module for near field communication"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org", txt))
    clf = Type2TagSimulator(tt2_memory_layout_12_initialized[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 0
    tag.ndef.message = msg
    assert clf.memory == tt2_memory_layout_12_readwrite

def test_lock_readwrite_memory_with_null_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_10_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 124
    assert tag.ndef.length == 68
    assert tag.protect() == True
    assert clf.memory == tt2_memory_layout_10_readonly

def test_lock_readwrite_memory_with_memory_control_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_11_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 68
    assert tag.protect() == True
    assert clf.memory == tt2_memory_layout_11_readonly

def test_lock_readwrite_memory_with_memory_and_lock_control_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_12_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef.is_writeable == True
    assert tag.ndef.is_readable == True
    assert tag.ndef.capacity == 108
    assert tag.ndef.length == 68
    assert tag.protect() == True
    assert clf.memory == tt2_memory_layout_12_readonly

def test_format_readwrite_memory_with_null_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_10_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.format(wipe=0) == True
    assert clf.memory == tt2_memory_layout_10_initialized
    assert tag.ndef.length == 0

def test_format_readwrite_memory_with_memory_control_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_11_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.format(wipe=0) == True
    assert clf.memory == tt2_memory_layout_11_initialized
    assert tag.ndef.length == 0

def test_format_readwrite_memory_with_memory_and_lock_control_tlv():
    clf = Type2TagSimulator(tt2_memory_layout_12_readwrite[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.format(wipe=0) == True
    assert clf.memory == tt2_memory_layout_12_initialized
    assert tag.ndef.length == 0

def test_format_uninitialized_tag():
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00" # 000-003
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
    )
    clf = Type2TagSimulator(tag_memory[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.format() == False

def test_protect_with_password():
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  00 00 00 00" # 000-003
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00" # 004-007
    )
    clf = Type2TagSimulator(tag_memory[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.protect("password") == False

def test_valid_arguments_format_wipe():
    for wipe in (None, 0, 1, 255, 1000):
        yield check_valid_arguments_format_wipe, None, wipe

def check_valid_arguments_format_wipe(version, wipe):
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 02 00" # 000-003
        "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00" # 004-007
    )
    clf = Type2TagSimulator(tag_memory[:])
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.format(version, wipe) == True
    assert clf.memory[16:19] == "\x03\x00\xFE"
    if wipe is None: assert clf.memory[19:32] == tag_memory[19:32]
    else: assert clf.memory[19:32] == 13 * chr(wipe & 0xFF)

def test_invalid_arguments_format_wipe():
    for wipe in ("a", 1.0, (), (1,)):
        yield check_invalid_arguments_format_wipe, None, wipe

@raises(TypeError)
def check_invalid_arguments_format_wipe(version, wipe):
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 02 00" # 000-003
        "03 0A D1 01  06 55 01 6E  2E 63 6F 6D  FE 00 00 00" # 004-007
    )
    clf = Type2TagSimulator(tag_memory[:])
    tag = clf.connect(rdwr={'on-connect': None})
    tag.format(version, wipe)

ispchr = lambda x: x >= 32 and x <= 126
oprint = lambda o: ' '.join(['??' if x < 0 else '%02x'%x for x in o])

def test_dump_memory_with_stop_argument():
    for stop in (None, 4, 8, 100, 256, 512):
        yield check_dump_memory_with_stop_argument_smaller_than_memory, stop
    for stop in (513, 514, 515, 516):
        yield check_dump_memory_with_stop_argument_larger_than_memory, stop

def check_dump_memory_with_stop_argument_smaller_than_memory(stop):
    tag_memory = 4 * (bytearray(range(256)) + bytearray(range(255, -1, -1)))
    clf = Type2TagSimulator(tag_memory)
    tag = clf.connect(rdwr={'on-connect': None})
    lines = tag._dump(stop)
    print '\n'.join(lines)
    assert len(lines) == len(tag_memory) // 4 if stop is None else stop
    for page, line in enumerate(lines):
        data = tag_memory[page*4:(page+1)*4]
        assert line[0:16] == "{0:>3}: {1}".format(page, oprint(data))

def check_dump_memory_with_stop_argument_larger_than_memory(stop):
    tag_memory = 4 * (bytearray(range(256)) + bytearray(range(255, -1, -1)))
    assert stop > len(tag_memory)//4
    
    clf = Type2TagSimulator(tag_memory)
    tag = clf.connect(rdwr={'on-connect': None})
    lines = tag._dump(stop)
    assert len(lines) == min(stop, len(tag_memory)//4 + 3)
    if stop - len(tag_memory)//4 <= 2:
        data, lfmt = (4*[None], "{0:>3}: {1}")
        for page in range(len(tag_memory)//4, stop):
            assert lines[page][0:16] == lfmt.format(page, oprint(data))
    else:
        data, data_lfmt, same_lfmt = (4*[None], "{0:>3}: {1}", "{0:>3}  {1}")
        line, page = (len(tag_memory)//4, len(tag_memory)//4)
        assert lines[line][0:16] == data_lfmt.format(page, oprint(data))
        line, page = (len(tag_memory)//4 + 1, "*")
        assert lines[line][0:16] == same_lfmt.format(page, oprint(data))
        line, page = (len(tag_memory)//4 + 2, stop - 1)
        assert lines[line][0:16] == data_lfmt.format(page, oprint(data))

def test_dump_memory_with_identical_pages_1():
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 02 00" # 000-003
        "11 11 11 11  11 11 11 11  33 33 33 33  33 33 33 33" # 004-007
    )
    dump_lines = [
        "  0: 04 6f d5 36 (UID0-UID2, BCC0)",
        "  1: 11 12 7a 00 (UID3-UID6)",
        "  2: 79 c8 00 00 (BCC1, INT, LOCK0-LOCK1)",
        "  3: e1 10 02 00 (OTP0-OTP3)",
        "  4: 11 11 11 11 |....|",
        "  5: 11 11 11 11 |....|",
        "  6: 33 33 33 33 |3333|",
        "  7: 33 33 33 33 |3333|",
    ]
    clf = Type2TagSimulator(tag_memory)
    tag = clf.connect(rdwr={'on-connect': None})
    lines = tag._dump(8)
    assert len(lines) == len(dump_lines)
    for page, line in enumerate(lines):
        assert line == dump_lines[page]

def test_dump_memory_with_identical_pages_2():
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 02 00" # 000-003
        "11 11 11 11  11 11 11 11  11 11 11 11  11 11 11 11" # 004-007
    )
    dump_lines = [
        "  0: 04 6f d5 36 (UID0-UID2, BCC0)",
        "  1: 11 12 7a 00 (UID3-UID6)",
        "  2: 79 c8 00 00 (BCC1, INT, LOCK0-LOCK1)",
        "  3: e1 10 02 00 (OTP0-OTP3)",
        "  4: 11 11 11 11 |....|",
        "  *  11 11 11 11 |....|",
        "  7: 11 11 11 11 |....|",
    ]
    clf = Type2TagSimulator(tag_memory)
    tag = clf.connect(rdwr={'on-connect': None})
    lines = tag._dump(8)
    assert len(lines) == len(dump_lines)
    for page, line in enumerate(lines):
        assert line == dump_lines[page]

def test_dump_memory_with_identical_pages_3():
    tag_memory = bytearray.fromhex(
        "04 6F D5 36  11 12 7A 00  79 C8 00 00  E1 10 02 00" # 000-003
        "11 11 11 11  11 11 11 11  11 11 11 11  33 33 33 33" # 004-007
    )
    dump_lines = [
        "  0: 04 6f d5 36 (UID0-UID2, BCC0)",
        "  1: 11 12 7a 00 (UID3-UID6)",
        "  2: 79 c8 00 00 (BCC1, INT, LOCK0-LOCK1)",
        "  3: e1 10 02 00 (OTP0-OTP3)",
        "  4: 11 11 11 11 |....|",
        "  *  11 11 11 11 |....|",
        "  6: 11 11 11 11 |....|",
        "  7: 33 33 33 33 |3333|",
    ]
    clf = Type2TagSimulator(tag_memory)
    tag = clf.connect(rdwr={'on-connect': None})
    lines = tag._dump(8)
    print '\n'.join(lines)
    assert len(lines) == len(dump_lines)
    for page, line in enumerate(lines):
        assert line == dump_lines[page]

