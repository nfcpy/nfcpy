#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

from nose.tools import raises
from string import maketrans
from time import time, sleep
from operator import lt, le, eq, ne, ge, gt, itemgetter

def sequence(template):
    a, b, c = [int(s, 16) for s in itemgetter(0, 1, 3)(template.split())]
    return str(bytearray(range(a, c+1, b-a))).encode("hex")

def packet_generator(packets):
    for packet in packets:
        yield packet
        
def makemask(s):
    return s.translate(maketrans('0123456789ABCDEFX', 'FFFFFFFFFFFFFFFF0'))
    
class ContactlessFrontend(nfc.clf.ContactlessFrontend):
    def __init__(self, packets):
        self.packets = packet_generator(packets)
        self.dev = nfc.dev.Device()

    @property
    def capabilities(self):
        return {}
    
    def listen(self, target, timeout):
        print target
        if type(target) is nfc.clf.DEP:
            if target.br is None:
                target.br = 106
            return target, bytearray.fromhex(self.packets.next())
    
    def sense(self, targets):
        for target in targets:
            if type(target) == nfc.clf.TTA and target.br == 106:
                uid = bytearray.fromhex("08112233")
                cfg = bytearray.fromhex("010C40")
                return nfc.clf.TTA(106, cfg, uid)
            if type(target) == nfc.clf.TTF and target.br == 212:
                idm = bytearray.fromhex("01FE000102030405")
                pmm = bytearray.fromhex("0000000000000000")
                sys = bytearray.fromhex("FFFF")
                return nfc.clf.TTF(212, idm, pmm, sys)

    def exchange(self, data, timeout):
        send, wait, recv = self.packets.next()
        if send is not None:
            print ">> " + str(data).encode("hex")
            print "   " + send
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
            if recv == "KeyboardInterrupt":
                raise KeyboardInterrupt("simulated")
            recv = bytearray.fromhex(recv)
            print "<< " + str(recv).encode("hex")
            return recv

    def set_communication_mode(self, brm, **kwargs):
        pass

@raises(StopIteration)
def test_p2p_pol_connect_and_terminate_locally():
    seq = [("F01ED40008112233XXXXXXXX00000000003246666d01011103020003070103",
            None, "F018D501081122330203040500000000000E3246666D010111"),
           ("F006D404001203", None, "F004D50500"),
           ("06D406000000", None, "06D507000000"),
           ("06D406010000", None, "06D507010000"),
           ("06D406020000", None, "06D507020000"),
           ("06D406030000", None, "06D507030000"),
           ("06D406000000", None, "KeyboardInterrupt"),
           ("06D406000140", None, "06D507000000"),
           ("03D40A", None, "03D50B")]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'initiator'}) == False
    clf.packets.next()

@raises(StopIteration)
def test_p2p_pol_connect_and_terminate_remotely():
    seq = [("F01ED40008112233XXXXXXXX00000000003246666d01011103020003070103",
            None, "F018D501081122330203040500000000000E3246666D010111"),
           ("F006D404001203", None, "F004D50500"),
           ("06D406000000", None, "06D507000000"),
           ("06D406010000", None, "06D507010000"),
           ("06D406020000", None, "06D507020000"),
           ("06D406030000", None, "06D507030000"),
           ("06D406000000", None, "06D507000140"),
           ("03D40A", None, "03D50B")]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'initiator'}) == True
    clf.packets.next()

@raises(StopIteration)
def test_p2p_pol_connect_and_terminate_disrupted():
    seq = [("F01ED40008112233XXXXXXXX00000000003246666d01011103020003070103",
            None, "F018D501081122330203040500000000000E3246666D010111"),
           ("F006D404001203", None, "F004D50500"),
           ("06D406000000", None, "06D507000000"),
           ("06D406010000", None, "06D507010000"),
           ("06D406020000", None, "06D507020000"),
           ("06D406030000", None, "06D507030000"),
           ("06D406000000", None, "TimeoutError"),
           ("04D40680", None, "TimeoutError"),
           ("04D40680", None, "TimeoutError")]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'initiator'}) == True
    clf.packets.next()

@raises(StopIteration)
def test_p2p_lis_connect_and_terminate_locally():
    seq = ["F01BD400081122334455667700000000003246666d01011103070103",
           ("F01FD50108112233XXXXXXXX0000000000093246666d01011103020003070103",
            None, "F006D404001203"),
           ("F004D50500", None, None), (None, None, "06D406000000"),
           ("06D507000000", None, "06D406010000"),
           ("06D507010000", None, "06D406020000"),
           ("06D507020000", None, "06D406030000"),
           ("06D507030000", None, "06D406000000"),
           ("06D507000000", None, "KeyboardInterrupt"),
           ("06D507000140", None, "03D40A"), ("03D50B", None, None)]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'target'}) == False
    clf.packets.next()

@raises(StopIteration)
def test_p2p_lis_connect_and_terminate_remotely():
    seq = ["F01BD400081122334455667700000000003246666d01011103070103",
           ("F01FD50108112233XXXXXXXX0000000000093246666d01011103020003070103",
            None, "F006D404001203"),
           ("F004D50500", None, None), (None, None, "06D406000000"),
           ("06D507000000", None, "06D406010000"),
           ("06D507010000", None, "06D406020000"),
           ("06D507020000", None, "06D406030000"),
           ("06D507030000", None, "06D406000000"),
           ("06D507000000", None, "06D406000140"),
           ("06D507000000", None, "03D40A"), ("03D50B", None, None)]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'target'}) == True
    clf.packets.next()

@raises(StopIteration)
def test_p2p_lis_connect_and_terminate_disrupted():
    seq = ["F01BD400081122334455667700000000003246666d01011103070103",
           ("F01FD50108112233XXXXXXXX0000000000093246666d01011103020003070103",
            None, "F006D404001203"),
           ("F004D50500", None, None), (None, None, "06D406000000"),
           ("06D507000000", None, "06D406010000"),
           ("06D507010000", None, "06D406020000"),
           ("06D507020000", None, "06D406030000"),
           ("06D507030000", None, "06D406000000"),
           ("06D507000000", None, "TimeoutError")]
    clf = ContactlessFrontend(seq)
    assert clf.connect(llcp={'role': 'target'}) == True
    clf.packets.next()

