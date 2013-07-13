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

t1t_static_memory_layout_1 = (
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
    "01 60 00 00 00 00 00 00")

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

class TestWithStaticMemoryLayout1:
    uri = nfc.ndef.Message(nfc.ndef.UriRecord(
            'http://www.abcdefghijklmnopqrstuvwxyzabcdefg.com'))
    
    def setup(self):
        seq = [("00000000112233", None, "1100" + t1t_static_memory_layout_1),
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
    def test_tt1_read_bv_1(self):
        """TC_T1T_READ_BV_1"""
        self.clf.connect(rdwr={'on-connect': self.read_ndef})
        assert self.ndef_message == self.uri
        self.clf.packets.next()
