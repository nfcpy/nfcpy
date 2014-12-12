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

from nose.tools import raises
from string import maketrans
from time import time, sleep
from operator import lt, le, eq, ne, ge, gt, itemgetter

tt1_memory_layout_1 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 0E 00 03 2A D1 01"
    "26 55 01 61 62 63 64 65"
    "66 67 68 69 6A 6B 6C 6D"
    "6E 6F 70 71 72 73 74 75"
    "76 77 78 79 7A 61 62 63"
    "64 65 66 67 2E 63 6F 6D"
    "FE 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "55 55 AA AA 00 00 00 00"
    "01 60 00 00 00 00 00 00"
    .split())

tt1_memory_layout_2 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 0E 00 03 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "55 55 AA AA 00 00 00 00"
    "01 60 00 00 00 00 00 00"
    .split())

tt1_memory_layout_3 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 0E 00 03 5A D1 01"
    "56 55 01 61 62 63 64 65"
    "66 67 68 69 6A 6B 6C 6D"
    "6E 6F 70 71 72 73 74 75"
    "76 77 78 79 7A 61 62 63"
    "64 65 66 67 68 69 6A 6B"
    "6C 6D 6E 6F 70 71 72 73"
    "74 75 76 77 78 79 7A 61"
    "62 63 64 65 66 67 68 69"
    "6A 6B 6C 6D 6E 6F 70 71"
    "72 73 74 75 76 77 78 79"
    "7A 61 62 63 2E 63 6F 6D"
    "55 55 AA AA 00 00 00 00"
    "01 60 00 00 00 00 00 00"
    .split())

tt1_memory_layout_4 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 3F 00 01 03 F2 30"
    "33 02 03 F0 02 03 03 FE"
    "D1 01 FA 55 01 61 62 63"
    "64 65 66 67 68 69 6A 6B"
    "6C 6D 6E 6F 70 71 72 73"
    "74 75 76 77 78 79 7A 61"
    "62 63 64 65 66 67 68 69"
    "6A 6B 6C 6D 6E 6F 70 71"
    "72 73 74 75 76 77 78 79"
    "7A 61 62 63 64 65 66 67"
    "68 69 6A 6B 6C 6D 6E 6F"
    "70 71 72 73 74 75 76 77"
    "55 55 AA AA 12 49 06 00"
    "01 E0 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 1
    "78 79 7A 61 62 63 64 65"
    "66 67 68 69 6A 6B 6C 6D"
    "6E 6F 70 71 72 73 74 75"
    "76 77 78 79 7A 61 62 63"
    "64 65 66 67 68 69 6A 6B"
    "6C 6D 6E 6F 70 71 72 73"
    "74 75 76 77 78 79 7A 61"
    "62 63 64 65 66 67 68 69"
    "6A 6B 6C 6D 6E 6F 70 71"
    "72 73 74 75 76 77 78 79"
    "7A 61 62 63 64 65 66 67"
    "68 69 6A 6B 6C 6D 6E 6F"
    "70 71 72 73 74 75 76 77"
    "78 79 7A 61 62 63 64 65"
    "66 67 68 69 6A 6B 6C 6D"
    "6E 6F 70 71 72 73 74 75"
    # Segment 2
    "76 77 78 79 7A 61 62 63"
    "64 65 66 67 68 69 6A 6B"
    "6C 6D 6E 6F 70 71 72 73"
    "74 75 76 77 78 79 7A 61"
    "62 63 64 65 66 67 68 69"
    "6A 6B 2E 63 6F 6D FE 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 3
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    .split())

tt1_memory_layout_5 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 3F 00 01 03 F2 30"
    "33 02 03 F0 02 03 03 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "55 55 AA AA 12 49 06 00"
    "01 E0 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 1
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 2
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 3
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    .split())

tt1_memory_layout_6 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 3F 00 01 03 F2 30"
    "33 02 03 F0 02 03 03 FF"
    "01 CD C1 01 00 00 01 C6"
    "55 01 61 62 63 64 65 66"
    "67 68 69 6A 6B 6C 6D 6E"
    "6F 70 71 72 73 74 75 76"
    "77 78 79 7A 61 62 63 64"
    "65 66 67 68 69 6A 6B 6C"
    "6D 6E 6F 70 71 72 73 74"
    "75 76 77 78 79 7A 61 62"
    "63 64 65 66 67 68 69 6A"
    "6B 6C 6D 6E 6F 70 71 72"
    "55 55 AA AA 12 49 06 00"
    "01 E0 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    # Segment 1
    "73 74 75 76 77 78 79 7A"
    "61 62 63 64 65 66 67 68"
    "69 6A 6B 6C 6D 6E 6F 70"
    "71 72 73 74 75 76 77 78"
    "79 7A 61 62 63 64 65 66"
    "67 68 69 6A 6B 6C 6D 6E"
    "6F 70 71 72 73 74 75 76"
    "77 78 79 7A 61 62 63 64"
    "65 66 67 68 69 6A 6B 6C"
    "6D 6E 6F 70 71 72 73 74"
    "75 76 77 78 79 7A 61 62"
    "63 64 65 66 67 68 69 6A"
    "6B 6C 6D 6E 6F 70 71 72"
    "73 74 75 76 77 78 79 7A"
    "61 62 63 64 65 66 67 68"
    "69 6A 6B 6C 6D 6E 6F 70"
    # Segment 2
    "71 72 73 74 75 76 77 78"
    "79 7A 61 62 63 64 65 66"
    "67 68 69 6A 6B 6C 6D 6E"
    "6F 70 71 72 73 74 75 76"
    "77 78 79 7A 61 62 63 64"
    "65 66 67 68 69 6A 6B 6C"
    "6D 6E 6F 70 71 72 73 74"
    "75 76 77 78 79 7A 61 62"
    "63 64 65 66 67 68 69 6A"
    "6B 6C 6D 6E 6F 70 71 72"
    "73 74 75 76 77 78 79 7A"
    "61 62 63 64 65 66 67 68"
    "69 6A 6B 6C 6D 6E 6F 70"
    "71 72 73 74 75 76 77 78"
    "79 7A 61 62 63 64 65 66"
    "67 68 69 6A 6B 6C 6D 6E"
    # Segment 3
    "6F 70 71 72 73 74 75 76"
    "77 78 79 7A 61 62 63 64"
    "65 66 67 68 69 6A 6B 6C"
    "6D 6E 6F 70 71 72 73 74"
    "75 76 77 78 79 7A 61 62"
    "63 64 65 66 67 68 69 6A"
    "6B 6C 6D 6E 6F 70 71 72"
    "73 74 75 76 77 78 79 7A"
    "61 62 63 64 65 66 67 68"
    "69 6A 6B 6C 6D 6E 6F 70"
    "71 72 73 74 75 76 77 78"
    "79 7A 61 62 63 64 65 66"
    "67 68 69 6A 6B 6C 6D 6E"
    "6F 70 71 72 73 74 75 76"
    "77 78 79 7A 61 62 63 64"
    "65 66 67 2E 63 6F 6D FE"
    .split())

tt1_memory_layout_7 = ''.join(
    "00 11 22 33 44 55 66 77"
    "E1 10 0E 0F 03 2A D1 01"
    "26 55 01 61 62 63 64 65"
    "66 67 68 69 6A 6B 6C 6D"
    "6E 6F 70 71 72 73 74 75"
    "76 77 78 79 7A 61 62 63"
    "64 65 66 67 2E 63 6F 6D"
    "FE 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00"
    "55 55 AA AA 00 00 00 00"
    "FF FF 00 00 00 00 00 00"
    .split())

def sequence(template):
    a, b, c = [int(s, 16) for s in itemgetter(0, 1, 3)(template.split())]
    return str(bytearray(range(a, c+1, b-a))).encode("hex")

def packet_generator(packets):
    for packet in packets:
        yield packet
        
def makemask(s):
    return s.translate(maketrans('0123456789ABCDEFX', 'FFFFFFFFFFFFFFFF0'))
    
class ContactlessFrontend(nfc.clf.ContactlessFrontend):
    def __init__(self, target, packets):
        self.target = target
        self.packets = packet_generator(packets)
        self.dev = nfc.dev.Device()

    def sense(self, targets):
        for target in targets:
            if (type(target) == type(self.target) and
                target.br == self.target.br):
                return self.target

    def exchange(self, data, timeout):
        send, wait, recv = self.packets.next()
        if send is not None:
            print ">> " + str(data).encode("hex")
            mask = bytearray.fromhex(makemask(send))
            data = bytearray(map(lambda x: x[0] & x[1], zip(data, mask)))
            assert data == bytearray.fromhex(send.replace('X', '0')), \
                "send data does not match"
        if wait is not None:
            to, op = wait
            assert op(timeout, to), \
                "timeout value does not match"
        if timeout > 0:
            if recv == "ProtocolError":
                raise nfc.clf.ProtocolError("simulated")
            if recv == "TransmissionError":
                raise nfc.clf.TransmissionError("simulated")
            if recv == "TimeoutError":
                raise nfc.clf.TimeoutError("simulated")
            recv = bytearray.fromhex(recv)
            print "<< " + str(recv).encode("hex")
            return recv

    def set_communication_mode(self, brm, **kwargs):
        pass

class TestReadMemoryLayout1:
    mem = tt1_memory_layout_1
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("78000000112233", None, "110000112233"),
               ("78000000112233", None, "TimeoutError")]
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def read_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 90
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        self.ndef_message = tag.ndef.message
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_READ_BV_1"""
        self.clf.connect(rdwr={'on-connect': self.read_ndef})
        assert self.ndef_message == self.msg
        self.clf.packets.next()

class TestWriteMemoryLayout1ToMemoryLayout2:
    mem = tt1_memory_layout_2
    out = bytearray.fromhex(tt1_memory_layout_1)
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("53080000112233", None, "0800"),
               ("53091000112233", None, "0910"),
               ("530B0000112233", None, "0B00")]
        for i in range(0x0D, 0x39):
            seq.append(
                ("53%02X%02X00112233" % (i, self.out[i]),
                 None, "%02X%02X" % (i, self.out[i])))
        seq.append(("5308E100112233", None, "08E1"))
        seq.append(("78000000112233", None, "110000112233"))
        seq.append(("78000000112233", None, "TimeoutError"))
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def write_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 90
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        tag.ndef.message = self.msg
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_WRITE_BV_1"""
        self.clf.connect(rdwr={'on-connect': self.write_ndef})
        self.clf.packets.next()

class TestReadMemoryLayout3:
    mem = tt1_memory_layout_3
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 3 * "abcdefghijklmnopqrstuvwxyz" + "abc.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("78000000112233", None, "110000112233"),
               ("78000000112233", None, "TimeoutError")]
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def read_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 90
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        self.ndef_message = tag.ndef.message
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_READ_BV_2"""
        self.clf.connect(rdwr={'on-connect': self.read_ndef})
        assert self.ndef_message == self.msg
        self.clf.packets.next()

class TestWriteMemoryLayout3ToMemoryLayout1:
    mem = tt1_memory_layout_1
    out = bytearray.fromhex(tt1_memory_layout_3)
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 3 * "abcdefghijklmnopqrstuvwxyz" + "abc.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("53080000112233", None, "0800"),
               ("53091000112233", None, "0910"),
               ("530B0000112233", None, "0B00")]
        for i in range(0x0D, 0x68):
            seq.append(
                ("53%02X%02X00112233" % (i, self.out[i]),
                 None, "%02X%02X" % (i, self.out[i])))
        seq.append(("5308E100112233", None, "08E1"))
        seq.append(("78000000112233", None, "110000112233"))
        seq.append(("78000000112233", None, "TimeoutError"))
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def write_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 90
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        tag.ndef.message = self.msg
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_WRITE_BV_2"""
        self.clf.connect(rdwr={'on-connect': self.write_ndef})
        self.clf.packets.next()

class TestWriteMemoryLayout3ToMemoryLayout7:
    mem = tt1_memory_layout_7
    out = bytearray.fromhex(tt1_memory_layout_3)
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 3 * "abcdefghijklmnopqrstuvwxyz" + "abc.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem)]
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def write_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 90
        assert tag.ndef.writeable == False
        assert tag.ndef.readable == True
        tag.ndef.message = self.msg
        return True
        
    @raises(nfc.tag.AccessError)
    def test(self):
        """TC_T1T_WRITE_BV_3"""
        self.clf.connect(rdwr={'on-connect': self.write_ndef})
        self.clf.packets.next()

class TestReadMemoryLayout4:
    mem = tt1_memory_layout_4 # format is printed hex
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 9 * "abcdefghijklmnopqrstuvwxyz" +
            "abcdefghijk.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem[0:256])]
        for b in range(0x10, 0x26):
            seq.append((
                "02" + hex(b)[2:4] + "000000000000000000112233",
                None, hex(b)[2:4] + self.mem[b*16:(b+1)*16]
                ))
        seq.append(("78000000112233", None, "110000112233"))
        seq.append(("78000000112233", None, "TimeoutError"))
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def read_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 462
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        self.ndef_message = tag.ndef.message
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_READ_BV_4"""
        self.clf.connect(rdwr={'on-connect': self.read_ndef})
        assert self.ndef_message == self.msg
        self.clf.packets.next()

class TestWriteMemoryLayout4ToMemoryLayout5:
    mem = tt1_memory_layout_5
    out = bytearray.fromhex(tt1_memory_layout_4)
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 9 * "abcdefghijklmnopqrstuvwxyz" +
            "abcdefghijk.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("540100103F000103F23000112233", None, "0100103F000103F230")]
        for i in range(0x02*8, 0x0D*8, 8):
            data = str(self.out[i:i+8]).encode("hex").upper()
            seq.append(("54%02X%s00112233" % (i/8, data),
                        None, "%02X%s" % (i/8, data)))
        for i in range(0x10*8, 0x26*8, 8):
            data = str(self.out[i:i+8]).encode("hex").upper()
            seq.append(("54%02X%s00112233" % (i/8, data),
                        None, "%02X%s" % (i/8, data)))
        seq.extend(
            [("5401E1103F000103F23000112233", None, "0100103F000103F230"),
             ("78000000112233", None, "110000112233"),
             ("78000000112233", None, "TimeoutError")])
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def write_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 462
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        tag.ndef.message = self.msg
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_WRITE_BV_4"""
        self.clf.connect(rdwr={'on-connect': self.write_ndef})
        self.clf.packets.next()

class TestReadMemoryLayout6:
    mem = tt1_memory_layout_6 # format is printed hex
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 17 * "abcdefghijklmnopqrstuvwxyz" +
            "abcdefg.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem[0:256])]
        for b in range(0x10, 0x40):
            seq.append((
                "02" + hex(b)[2:4] + "000000000000000000112233",
                None, hex(b)[2:4] + self.mem[b*16:(b+1)*16]
                ))
        seq.append(("78000000112233", None, "110000112233"))
        seq.append(("78000000112233", None, "TimeoutError"))
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def read_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 462
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        self.ndef_message = tag.ndef.message
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_READ_BV_5"""
        self.clf.connect(rdwr={'on-connect': self.read_ndef})
        assert self.ndef_message == self.msg
        self.clf.packets.next()

class TestWriteMemoryLayout6ToMemoryLayout4:
    mem = tt1_memory_layout_4
    out = bytearray.fromhex(tt1_memory_layout_6)
    msg = nfc.ndef.Message(nfc.ndef.UriRecord(
            "http://www." + 17 * "abcdefghijklmnopqrstuvwxyz" +
            "abcdefg.com"))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + self.mem),
               ("540100103F000103F23000112233", None, "0100103F000103F230")]
        for i in range(0x02*8, 0x0D*8, 8):
            data = str(self.out[i:i+8]).encode("hex").upper()
            seq.append(("54%02X%s00112233" % (i/8, data),
                        None, "%02X%s" % (i/8, data)))
        for i in range(0x10*8, 0x40*8, 8):
            data = str(self.out[i:i+8]).encode("hex").upper()
            seq.append(("54%02X%s00112233" % (i/8, data),
                        None, "%02X%s" % (i/8, data)))
        seq.extend(
            [("5401E1103F000103F23000112233", None, "0100103F000103F230"),
             ("78000000112233", None, "110000112233"),
             ("78000000112233", None, "TimeoutError")])
        cfg, uid = bytearray.fromhex("000C"), bytearray.fromhex("00112233")
        self.clf = ContactlessFrontend(nfc.clf.TTA(106, cfg, uid), seq)
        
    def write_ndef(self, tag):
        assert tag.ndef.version == "1.0"
        assert tag.ndef.capacity == 462
        assert tag.ndef.writeable == True
        assert tag.ndef.readable == True
        tag.ndef.message = self.msg
        return True
        
    @raises(StopIteration)
    def test(self):
        """TC_T1T_WRITE_BV_5"""
        self.clf.connect(rdwr={'on-connect': self.write_ndef})
        self.clf.packets.next()

