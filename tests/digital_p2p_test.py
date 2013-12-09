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

#
# NFC Forum Test Cases for Digital Protocol
# Group 2: NFC Forum Device in Poll Mode
# Group 2.10: Peer2Peer with NFC-F
#
def test_bv_p2p_in_nfcf_exchange_deselect():
    """TC_POL_NFCF_P2P_BV_1_0_0_0"""
    seq  = [("11D40001FE000102030405XXXX000X0X30", None,
             "12D50101FE00010203040500000000000E00"),
            ("0CD40600 004000011002010E", None, "0CD50700 0001020304050607"),
            ("0CD40601 0001020304050607", None, "0CD50701 08090A0B0C0D0E0F"),
            ("0CD40602 08090A0B0C0D0E0F", None, "0CD50702 1011121314151617"),
            ("0CD40603 1011121314151617", None, "0CD50703 0001020304050607"),
            ("0CD40600 0001020304050607", None, "0CD50700 08090A0B0C0D0E0F"),
            ("0CD40601 08090A0B0C0D0E0F", None, "0CD50701 1011121314151617"),
            ("0CD40602 1011121314151617", None, "09D50702 FFFFFF0102"),
            ("03D408", None, "03D509")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "08090A0B0C0D0E0F"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "08090A0B0C0D0E0F", "1011121314151617"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "1011121314151617", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "08090A0B0C0D0E0F"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "08090A0B0C0D0E0F", "1011121314151617"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "1011121314151617", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate(release=False)

def test_bv_p2p_in_nfcf_exchange_release():
    """TC_POL_NFCF_P2P_BV_1_1_0_0"""
    seq  = [("11D40001FE000102030405XXXX000X0X30", None,
             "12D50101FE00010203040500000000000E00"),
            ("0CD40600 004000011002010E", None, "0CD50700 0001020304050607"),
            ("0CD40601 0001020304050607", None, "0CD50701 08090A0B0C0D0E0F"),
            ("0CD40602 08090A0B0C0D0E0F", None, "0CD50702 1011121314151617"),
            ("0CD40603 1011121314151617", None, "0CD50703 0001020304050607"),
            ("0CD40600 0001020304050607", None, "0CD50700 08090A0B0C0D0E0F"),
            ("0CD40601 08090A0B0C0D0E0F", None, "0CD50701 1011121314151617"),
            ("0CD40602 1011121314151617", None, "09D50702 FFFFFF0102"),
            ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "08090A0B0C0D0E0F"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "08090A0B0C0D0E0F", "1011121314151617"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "1011121314151617", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "08090A0B0C0D0E0F"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "08090A0B0C0D0E0F", "1011121314151617"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "1011121314151617", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_atr_res_wt_14():
    """TC_POL_NFCF_P2P_BV_3_0_0"""
    rwt = 4096/13.56E6 * 2**14
    seq  = [("11D40001FE000102030405XXXX000X0X30", None,
             "12D50101FE00010203040500000000000E00"),
            ("0CD40600 004000011002010E", (rwt, eq),
             "09D50700 FFFFFF0102"),
            ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 5) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_atr_res_wt_15():
    """TC_POL_NFCF_P2P_BV_3_1_0"""
    rwt = 4096/13.56E6 * 2**14
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000F00"),
           ("0CD40600 004000011002010E", (rwt, eq),
            "09D50700 FFFFFF0102"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 5) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_psl_req_res_min_time():
    """TC_POL_NFCF_P2P_BV_4_0"""
    seq  = [("11D40001FE000102030405XXXX000X0X30", None,
             "12D50101FE00010203040500000000000E00"),
            ("06D404001203", None, "04D50500"),
            ("0CD40600 004000011002010E", None, "09D50700 FFFFFF0102"),
            ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=(1, 2), timeout=1.0) == ""
    send, recv = "004000011002010E", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_exchange_with_did():
    """TC_POL_NFCF_P2P_BV_5_0"""
    seq = [("11D40001FE000102030405XXXX010X0X30", None,
            "12D50101FE00010203040500000100000E00"),
           ("0DD4060401 004000011002010E", None, "0DD5070401 0001020304050607"),
           ("0DD4060501 0001020304050607", None, "0AD5070501 FFFFFF0102"),
           ("04D40A01", None, "04D50B01")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, did=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "FFFFFF0102"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_rtox_handle_rtox():
    """TC_POL_NFCF_P2P_BV_6_0_0"""
    rwt = 4096/13.56E6 * 2**8
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000800"),
           ("0CD40600 004000011002010E", (rwt, eq), "05D5079001"),
           ("05D4069001", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "05D507903B"),
           ("05D406903B", None, "0CD50701 0001020304050607"),
           ("0CD40602 0001020304050607", None, "0CD50702 0001020304050607"),
           ("0CD40603 0001020304050607", None, "0CD50703 004000011002010E"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "004000011002010E"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_rtox_rwt_max():
    """TC_POL_NFCF_P2P_BV_6_1_0"""
    rwt = 4096/13.56E6 * 2**14
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E00"),
           ("0CD40600 004000011002010E", (rwt, eq), "05D5079001"),
           ("05D4069001", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "0CD50701 004000011002010E"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 5) == recv.decode("hex")
    send, recv = "0001020304050607", "004000011002010E"
    assert dep.exchange(send.decode("hex"), 5) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_dsl_req_no_did():
    """TC_POL_NFCF_P2P_BV_7_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E00"),
           ("0CD40600 004000011002010E", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "08D50701 FFFF0101"),
           ("03D408", None, "03D509")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "FFFF0101"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate(release=False)

def test_bv_p2p_in_nfcf_dsl_req_with_did():
    """TC_POL_NFCF_P2P_BV_7_1_0"""
    seq = [("11D40001FE000102030405XXXX010X0X30", None,
            "12D50101FE00010203040500000100000E00"),
           ("0DD4060401 004000011002010E", None, "0DD5070401 0001020304050607"),
           ("0DD4060501 0001020304050607", None, "09D5070501 FFFF0101"),
           ("04D40801", None, "04D50901")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, did=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "FFFF0101"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate(release=False)

def test_bv_p2p_in_nfcf_rls_req_with_did():
    """TC_POL_NFCF_P2P_BV_8_0"""
    seq = [("11D40001FE000102030405XXXX010X0X30", None,
            "12D50101FE00010203040500000100000E00"),
           ("0DD4060401 004000011002010E", None, "0DD5070401 0001020304050607"),
           ("0DD4060501 0001020304050607", None, "09D5070501 FFFF0101"),
           ("04D40A01", None, "04D50B01")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, did=1) == ""
    send, recv = "004000011002010E", "0001020304050607"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    send, recv = "0001020304050607", "FFFF0101"
    assert dep.exchange(send.decode("hex"), 1) == recv.decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_chaining_lr_0():
    """TC_POL_NFCF_P2P_BV_9_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X00", None,
            "12D50101FE00010203040500000000000E00"),
           ("0CD40600 004000011002010E", None,
            "06D50710" + str(bytearray(range(0x01, 0x03))).encode("hex")),
           ("04D40641", None,
            "0AD50711" + str(bytearray(range(0x03, 0x09))).encode("hex")),
           ("04D40642", None,
            "0CD50712" + str(bytearray(range(0x09, 0x11))).encode("hex")),
           ("04D40643", None,
            "13D50713" + str(bytearray(range(0x11, 0x20))).encode("hex")),
           ("04D40640", None,
            "22D50700" + str(bytearray(range(0x20, 0x3E))).encode("hex")),
           ("41D40601" + str(bytearray(range(0x01, 0x3E))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=0) == ""
    loop = dep.exchange("\x00\x40\x00\x01\x10\x02\x01\x0E", 1)
    assert dep.exchange(loop, 1) == "\xFF\xFF\x01\x01"
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_chaining_lr_1():
    """TC_POL_NFCF_P2P_BV_9_1_0"""
    seq = [("11D40001FE000102030405XXXX000X0X10", None,
            "12D50101FE00010203040500000000000E10"),
           ("0CD40600 004000011002010E", None,
            "08D50710" + str(bytearray(range(0x01, 0x05))).encode("hex")),
           ("04D40641", None,
            "0CD50711" + str(bytearray(range(0x05, 0x0D))).encode("hex")),
           ("04D40642", None,
            "14D50712" + str(bytearray(range(0x0D, 0x1D))).encode("hex")),
           ("04D40643", None,
            "24D50713" + str(bytearray(range(0x1D, 0x3D))).encode("hex")),
           ("04D40640", None,
            "45D50700" + str(bytearray(range(0x3D, 0x7E))).encode("hex")),
           ("81D40601" + str(bytearray(range(0x01, 0x7E))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=1) == ""
    loop = dep.exchange("\x00\x40\x00\x01\x10\x02\x01\x0E", 1)
    assert dep.exchange(loop, 1) == "\xFF\xFF\x01\x01"
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_chaining_lr_2():
    """TC_POL_NFCF_P2P_BV_9_2_0"""
    seq = [("11D40001FE000102030405XXXX000X0X20", None,
            "12D50101FE00010203040500000000000E20"),
           ("0CD40600 004000011002010E", None,
            "0AD50710" + str(bytearray(range(0x01, 0x07))).encode("hex")),
           ("04D40641", None,
            "10D50711" + str(bytearray(range(0x07, 0x13))).encode("hex")),
           ("04D40642", None,
            "1DD50712" + str(bytearray(range(0x13, 0x2C))).encode("hex")),
           ("04D40643", None,
            "33D50713" + str(bytearray(range(0x2C, 0x5B))).encode("hex")),
           ("04D40640", None,
            "67D50700" + str(bytearray(range(0x5B, 0xBE))).encode("hex")),
           ("C1D40601" + str(bytearray(range(0x01, 0xBE))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=2) == ""
    loop = dep.exchange("\x00\x40\x00\x01\x10\x02\x01\x0E", 1)
    assert dep.exchange(loop, 1) == "\xFF\xFF\x01\x01"
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_recv_chaining_lr_3():
    """TC_POL_NFCF_P2P_BV_9_3_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None,
            "0FD50710" + str(bytearray(range(0x01, 0x0C))).encode("hex")),
           ("04D40641", None,
            "14D50711" + str(bytearray(range(0x0C, 0x1C))).encode("hex")),
           ("04D40642", None,
            "24D50712" + str(bytearray(range(0x1C, 0x3C))).encode("hex")),
           ("04D40643", None,
            "44D50713" + str(bytearray(range(0x3C, 0x7C))).encode("hex")),
           ("04D40640", None,
            "84D50700" + str(bytearray(range(0x7C, 0xFC))).encode("hex")),
           ("FFD40601" + str(bytearray(range(0x01, 0xFC))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=3) == ""
    loop = dep.exchange("\x00\x40\x00\x01\x10\x02\x01\x0E", 1)
    assert dep.exchange(loop, 1) == "\xFF\xFF\x01\x01"
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_supervisory_request_rtox():
    """TC_POL_NFCF_P2P_BV_10_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "05D5079001"),
           ("05D4069001", None, "0CD50711 0001020304050607"),
           ("04D40642", None, "05D5079001"),
           ("05D4069001", None, "06D50702 0809"),
           ("0ED40603 00010203040506070809", None, "08D50703 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(loop, 1)
    assert loop == "00010203040506070809".decode("hex")
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_supervisory_request_attention():
    """TC_POL_NFCF_P2P_BV_10_1_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "TimeoutError"),
           ("04D40680", None, "04D50780"),
           ("0CD40601 0001020304050607", None, "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_max_payload_size_64():
    """TC_POL_NFCF_P2P_BV_11_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X00", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None,
            "41D50700" + str(bytearray(range(0x01, 0x3E))).encode("hex")),
           ("41D40601" + str(bytearray(range(0x01, 0x3E))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=0) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == str(bytearray(range(0x01, 0x3E)))
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_max_payload_size_128():
    """TC_POL_NFCF_P2P_BV_11_1_0"""
    seq = [("11D40001FE000102030405XXXX000X0X10", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None,
            "81D50700" + str(bytearray(range(0x01, 0x7E))).encode("hex")),
           ("81D40601" + str(bytearray(range(0x01, 0x7E))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=1) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == str(bytearray(range(0x01, 0x7E)))
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_max_payload_size_192():
    """TC_POL_NFCF_P2P_BV_11_2_0"""
    seq = [("11D40001FE000102030405XXXX000X0X20", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None,
            "C1D50700" + str(bytearray(range(0x01, 0xBE))).encode("hex")),
           ("C1D40601" + str(bytearray(range(0x01, 0xBE))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=2) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == str(bytearray(range(0x01, 0xBE)))
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_max_payload_size_254():
    """TC_POL_NFCF_P2P_BV_11_3_0"""
    seq = [("11D40001FE000102030405XXXX000X0X20", None,
            "12D50101FE00010203040500000000000E30"),
           ("0CD40600 004000011002010E", None,
            "FFD50700" + str(bytearray(range(0x01, 0xFC))).encode("hex")),
           ("FFD40601" + str(bytearray(range(0x01, 0xFC))).encode("hex"), None,
            "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1, lr=2) == ""
    loop = dep.exchange("004000011002010E".decode("hex"), 1)
    assert loop == str(bytearray(range(0x01, 0xFC)))
    assert dep.exchange(loop, 1) == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_timeout_error():
    """TC_POL_NFCF_P2P_BI_1_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E00"),
           ("0BD40600 4000011002010E", None, "TimeoutError"),
           ("04D40680", None, "TimeoutError"),
           ("04D40680", None, "04D50780"),
           ("0BD40600 4000011002010E", None, "08D50700 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    loop = dep.exchange("4000011002010E".decode("hex"), 1)
    assert loop == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_timeout_error_after_rtox():
    """TC_POL_NFCF_P2P_BI_2_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E00"),
           ("0BD40600 4000011002010E", None, "05D5079001"),
           ("05D4069001", None, "TimeoutError"),
           ("04D40680", None, "TimeoutError"),
           ("04D40680", None, "04D50780"),
           ("05D4069001", None, "08D50700 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    loop = dep.exchange("4000011002010E".decode("hex"), 1)
    assert loop == "FFFF0101".decode("hex")
    assert dep.deactivate()

def test_bv_p2p_in_nfcf_transmission_error_inf_no_chaining():
    """TC_POL_NFCF_P2P_BI_3_0_0"""
    seq = [("11D40001FE000102030405XXXX000X0X30", None,
            "12D50101FE00010203040500000000000E00"),
           ("0BD40600 4000011002010E", None, "0CD50700 0001020304050607"),
           ("0CD40601 0001020304050607", None, "TransmissionError"),
           ("04D40651", None, "0CD50701 08090A0B0C0D0E0F"),
           ("0CD40602 08090A0B0C0D0E0F", None, "TransmissionError"),
           ("04D40652", None, "0CD50702 1011121314151617"),
           ("0CD40603 1011121314151617", None, "TransmissionError"),
           ("04D40653", None, "0CD50703 18191A1B1C1D1E1F"),
           ("0CD40600 18191A1B1C1D1E1F", None, "TransmissionError"),
           ("04D40650", None, "0CD50700 2021222324252627"),
           ("0CD40601 2021222324252627", None, "08D50701 FFFF0101"),
           ("03D40A", None, "03D50B")]
    dep = nfc.dep.Initiator(ContactlessFrontend(seq))
    assert dep.activate(brs=1) == ""
    loop = dep.exchange("4000011002010E".decode("hex"), 1)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(loop, 1)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    loop = dep.exchange(loop, 1)
    assert loop == "1011121314151617".decode("hex")
    loop = dep.exchange(loop, 1)
    assert loop == "18191A1B1C1D1E1F".decode("hex")
    loop = dep.exchange(loop, 1)
    assert loop == "2021222324252627".decode("hex")
    loop = dep.exchange(loop, 1)    
    assert loop == "FFFF0101".decode("hex")
    assert dep.deactivate()

#
# NFC Forum Test Cases for Digital Protocol
# Group 3: NFC Forum Device in Listen Mode
# Group 3.8: Peer2Peer with NFC-F
#
def test_bv_p2p_tg_nfcf_frame_format_and_timing_with_dsl_req():
    """TC_LIS_NFCF_P2P_BV_3_0_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", (0.1, ge), "06D404001200"),
           ("04D50500", (0, eq), None),
           (None, (0.1, ge), "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "0CD40602 1011121314151617"),
           ("0CD50702 1011121314151617", None, "0CD40603 18191A1B1C1D1E1F"),
           ("0CD50703 18191A1B1C1D1E1F", None, "03D408"),
           ("03D509", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "1011121314151617".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "18191A1B1C1D1E1F".decode("hex")
    assert dep.exchange(loop, 1.0) == None

def test_bv_p2p_tg_nfcf_frame_format_and_timing_with_rls_req():
    """TC_LIS_NFCF_P2P_BV_3_1_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", (0.1, ge), "06D404001200"),
           ("04D50500", (0, eq), None),
           (None, (0.1, ge), "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "0CD40602 1011121314151617"),
           ("0CD50702 1011121314151617", None, "0CD40603 18191A1B1C1D1E1F"),
           ("0CD50703 18191A1B1C1D1E1F", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "1011121314151617".decode("hex")
    loop = dep.exchange(loop, 1.0)
    assert loop == "18191A1B1C1D1E1F".decode("hex")
    assert dep.exchange(loop, 1.0) == None

def test_bv_p2p_tg_nfcf_attribute_request_parameters():
    """TC_LIS_NFCF_P2P_BV_4_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", (0.1, ge), "06D40600 0000"),
           ("06D50700 0000", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0000".decode("hex")
    assert dep.exchange(loop, 1.0) == None

@raises(nfc.clf.ProtocolError)
def _test_bv_p2p_tg_nfcf_atr_req_with_different_nfcid2():
    """TC_LIS_NFCF_P2P_BV_4_1"""
    seq = ["11D40001FE102030405060000000000000"]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    try: dep.activate(timeout=0.5, brs=1)
    except nfc.clf.ProtocolError as error:
        assert error.requirement == "14.6.2.1"; raise

def test_bv_p2p_tg_nfcf_psl_req_with_same_did():
    """TC_LIS_NFCF_P2P_BV_5_0"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", (0.1, ge), "06D404010900"),
           ("04D50501", (0, eq), None),
           (None, (0.1, ge), "0DD4060401 0001020304050607"),
           ("0DD5070401 0001020304050607", None, "04D40A01"),
           ("04D50B01", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(loop, 1.0) == None

def test_bv_p2p_tg_nfcf_psl_req_with_different_did():
    """TC_LIS_NFCF_P2P_BV_5_1"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", (0.1, ge), "06D404020900")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def test_bv_p2p_tg_nfcf_exchange_dep_with_incorrect_did_1():
    """TC_LIS_NFCF_P2P_BV_6_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0DD4060401 0001020304050607")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def test_bv_p2p_tg_nfcf_exchange_dep_with_incorrect_did_2():
    """TC_LIS_NFCF_P2P_BV_6_1"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", None,
            "0DD4060402 0001020304050607")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def test_bv_p2p_tg_nfcf_rtox_request():
    """TC_LIS_NFCF_P2P_BV_7"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "09D40600 FFFFFF0103"), # DTA Wait Command
           ("05D5079002", None, "05D4069002"),
           ("09D50700 FFFFFF0103", None, "0CD40601 0001020304050607"),
           ("0CD50701 0001020304050607", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "FFFFFF0103".decode("hex")
    assert dep.send_timeout_extension(rtox=2) == 2
    loop = dep.exchange(send_data=loop, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(loop, 1.0) == None

def test_bv_p2p_tg_nfcf_dsl_req_without_did():
    """TC_LIS_NFCF_P2P_BV_8_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "03D408"),
           ("03D509", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

@raises(nfc.clf.TimeoutError)
def test_bv_p2p_tg_nfcf_atr_with_did_0_dsl_with_did_1():
    """TC_LIS_NFCF_P2P_BV_8_1"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "04D40800"),
           (None, (0, gt), "TimeoutError")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_dsl_req_same_did():
    """TC_LIS_NFCF_P2P_BV_8_2"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", None,
            "0DD4060401 0001020304050607"),
           ("0DD5070401 0001020304050607", None, "04D40801"),
           ("04D50901", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

@raises(nfc.clf.TimeoutError)
def test_bv_p2p_tg_nfcf_atr_with_did_1_dsl_with_did_2():
    """TC_LIS_NFCF_P2P_BV_8_3"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", None,
            "0DD4060401 0001020304050607"),
           ("0DD5070401 0001020304050607", None, "04D40802"),
           (None, (0, gt), "TimeoutError")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_rls_req_without_did():
    """TC_LIS_NFCF_P2P_BV_9_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_rls_req_same_did():
    """TC_LIS_NFCF_P2P_BV_9_1"""
    seq = ["11D40001FE010203040506000001000000",
           ("12D50101FEXXXXXXXXXXXX00000100000830", None,
            "0DD4060401 0001020304050607"),
           ("0DD5070401 0001020304050607", None, "04D40A01"),
           ("04D50B01", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_chaining_lr_0():
    """TC_LIS_NFCF_P2P_BV_10_0"""
    seq = ["11D40001FE010203040506000000000000",
           (None,       None, "06D40610 0102"),
           ("04D50740", None, "0AD40611" + sequence("03 04 ... 08")),
           ("04D50741", None, "0CD40612" + sequence("09 0A ... 10")),
           ("04D50742", None, "13D40613" + sequence("11 12 ... 1F")),
           ("04D50743", None, "22D40600" + sequence("20 21 ... 3D")),
           ("41D50700" + sequence("01 02 ... 3D"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=0) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... 3D").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_chaining_lr_1():
    """TC_LIS_NFCF_P2P_BV_10_1"""
    seq = ["11D40001FE010203040506000000000010",
           (None, None, "08D40610" + sequence("01 02 ... 04")),
           ("04D50740", None, "0CD40611" + sequence("05 06 ... 0C")),
           ("04D50741", None, "14D40612" + sequence("0D 0E ... 1C")),
           ("04D50742", None, "24D40613" + sequence("1D 1E ... 3C")),
           ("04D50743", None, "45D40600" + sequence("3D 3E ... 7D")),
           ("81D50700" + sequence("01 02 ... 7D"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... 7D").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_chaining_lr_2():
    """TC_LIS_NFCF_P2P_BV_10_2"""
    seq = ["11D40001FE010203040506000000000020",
           (None, None, "0AD40610" + sequence("01 02 ... 06")),
           ("04D50740", None, "10D40611" + sequence("07 08 ... 12")),
           ("04D50741", None, "1DD40612" + sequence("13 14 ... 2B")),
           ("04D50742", None, "33D40613" + sequence("2C 2D ... 5A")),
           ("04D50743", None, "67D40600" + sequence("5B 5C ... BD")),
           ("C1D50700" + sequence("01 02 ... BD"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=2) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... BD").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_chaining_lr_3():
    """TC_LIS_NFCF_P2P_BV_10_3"""
    seq = ["11D40001FE010203040506000000000030",
           (None,       None, "0FD40610" + sequence("01 02 ... 0B")),
           ("04D50740", None, "14D40611" + sequence("0C 0D ... 1B")),
           ("04D50741", None, "24D40612" + sequence("1C 1D ... 3B")),
           ("04D50742", None, "44D40613" + sequence("3C 3D ... 7B")),
           ("04D50743", None, "84D40600" + sequence("7C 7D ... FB")),
           ("FFD50700" + sequence("01 02 ... FB"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=3) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... FB").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_numbering_rules_attention():
    """TC_LIS_NFCF_P2P_BV_11_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "04D40680"),
           ("04D50780", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(send_data=loop, timeout=1.0)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_numbering_rules_erroneous_transaction():
    """TC_LIS_NFCF_P2P_BV_11_1"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "0CD40610 0001020304050607"),
           ("04D50740", None, "0CD40611 08090A0B0C0D0E0F"),
           ("04D50741", None, "04D40680"),
           ("04D50780", None, "0CD40611 08090A0B0C0D0E0F"),
           ("04D50741", None, "0CD40602 1011121314151617"),
           ("1CD50702" + sequence("00 01 ... 17"), None,
            "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("00 01 ... 17").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_handling_rules_for_ack_pdu():
    """TC_LIS_NFCF_P2P_BV_12_0"""
    seq = ["11D40001FE010203040506000000000000",
           (None,       None, "41D40610" + sequence("01 02 ... 3D")),
           ("04D50740", None, "41D40611" + sequence("3E 3F ... 7A")),
           ("04D50741", None, "1DD40602" + sequence("7B 7C ... 93")),
           ("41D50712" + sequence("01 02 ... 3D"), None, "04D40643"),
           ("41D50713" + sequence("3E 3F ... 7A"), None, "04D40640"),
           ("1DD50700" + sequence("7B 7C ... 93"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... 93").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_handling_rules_for_inf_pdu():
    """TC_LIS_NFCF_P2P_BV_12_1"""
    seq = ["11D40001FE010203040506000000000000",
           (None, None, "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "09D40601 FFFFFF0103"),
           ("05D5079002", None, "05D4069002"),
           ("09D50701 FFFFFF0103", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(send_data=loop, timeout=1.0)
    assert loop == "FFFFFF0103".decode("hex")
    assert dep.send_timeout_extension(2) == 2
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_handling_rules_with_atn_pdu():
    """TC_LIS_NFCF_P2P_BV_12_2"""
    seq = ["11D40001FE010203040506000000000000",
           (None, None, "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "04D40680"),
           ("04D50780", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(send_data=loop, timeout=1.0)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_pdu_handling_rules_transmission_error():
    """TC_LIS_NFCF_P2P_BV_12_3"""
    seq = ["11D40001FE010203040506000000000000",
           (None, None, "0CD40600 0001020304050607"),
           ("0CD50700 0001020304050607", None, "TransmissionError"),
           (None, None, "04D40680"),
           ("04D50780", None, "0CD40601 08090A0B0C0D0E0F"),
           ("0CD50701 08090A0B0C0D0E0F", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0001020304050607".decode("hex")
    loop = dep.exchange(send_data=loop, timeout=1.0)
    assert loop == "08090A0B0C0D0E0F".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_max_min_payload_size_lr_0():
    """TC_LIS_NFCF_P2P_BV_13_0"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000800", None,
            "41D40600" + sequence("01 02 ... 3D")),
           ("41D50700" + sequence("01 02 ... 3D"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=0) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... 3D").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_max_min_payload_size_lr_1():
    """TC_LIS_NFCF_P2P_BV_13_1"""
    seq = ["11D40001FE010203040506000000000010",
           ("12D50101FEXXXXXXXXXXXX00000000000810", None,
            "81D40600" + sequence("01 02 ... 7D")),
           ("81D50700" + sequence("01 02 ... 7D"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... 7D").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_max_min_payload_size_lr_2():
    """TC_LIS_NFCF_P2P_BV_13_2"""
    seq = ["11D40001FE010203040506000000000020",
           ("12D50101FEXXXXXXXXXXXX00000000000820", None,
            "C1D40600" + sequence("01 02 ... BD")),
           ("C1D50700" + sequence("01 02 ... BD"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=2) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... BD").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bv_p2p_tg_nfcf_max_min_payload_size_lr_3():
    """TC_LIS_NFCF_P2P_BV_13_3"""
    seq = ["11D40001FE010203040506000000000030",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None,
            "FFD40600" + sequence("01 02 ... FB")),
           ("FFD50700" + sequence("01 02 ... FB"), None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1, lr=3) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == sequence("01 02 ... FB").decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def _test_bv_p2p_tg_nfcf_reactivation_after_deselect():
    """TC_LIS_NFCF_P2P_BV_14_0_0"""
    seq = ["11D40001FE010203040506000000000010",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "03D408"),
           ("03D509", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def _test_bv_p2p_tg_nfcf_reactivation_after_release():
    """TC_LIS_NFCF_P2P_BV_14_1_0"""
    seq = ["11D40001FE010203040506000000000010",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def _test_bi_p2p_tg_nfcf_transmission_error_with_atr_req():
    """TC_LIS_NFCF_P2P_BI_1_0"""
    seq = ["11D40001FE010203040506000000000010",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == None

def test_bi_p2p_tg_nfcf_transmission_error_with_psl_req():
    """TC_LIS_NFCF_P2P_BI_1_1"""
    seq = ["11D40001FE010203040506000000000010",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "TransmissionError"),
           (None, None, "0CD40600 0102030405060708"),
           ("0CD50700 0102030405060708", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0102030405060708".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bi_p2p_tg_nfcf_transmission_error_with_dep_req():
    """TC_LIS_NFCF_P2P_BI_1_2"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "TransmissionError"),
           (None, None, "0CD40600 0102030405060708"),
           ("0CD50700 0102030405060708", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0102030405060708".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bi_p2p_tg_nfcf_transmission_error_with_dsl_req():
    """TC_LIS_NFCF_P2P_BI_1_3"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "TransmissionError"),
           (None, None, "0CD40600 0102030405060708"),
           ("0CD50700 0102030405060708", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0102030405060708".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bi_p2p_tg_nfcf_transmission_error_with_rls_req():
    """TC_LIS_NFCF_P2P_BI_1_4"""
    seq = ["11D40001FE010203040506000000000000",
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "TransmissionError"),
           (None, None, "0CD40600 0102030405060708"),
           ("0CD50700 0102030405060708", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0102030405060708".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def _test_bi_p2p_tg_nfcf_protocol_error_atr_req():
    """TC_LIS_NFCF_P2P_BI_2"""
    seq = ["42D40001FE010203040506000000000002" + sequence("01 02 ... 31"),
           (None, None, "11D40001FE010203040506000000000000"),
           ("12D50101FEXXXXXXXXXXXX00000000000830", None, "04D40600")]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""

def test_bi_p2p_tg_nfcf_protocol_error_with_rtox():
    """TC_LIS_NFCF_P2P_BI_3"""
    seq = ["11D40001FE010203040506000000000000",
           (None, None, "09D40600 FFFFFF0103"),
           ("05D5079002", None, "05D4069003"),
           ("09D50700 FFFFFF0103", None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "FFFFFF0103".decode("hex")
    dep.send_timeout_extension(rtox=2)
    assert dep.exchange(send_data=loop, timeout=1.0) == None

def test_bi_p2p_tg_nfcf_protocol_error_with_payload_length():
    """TC_LIS_NFCF_P2P_BI_4"""
    seq = ["11D40001FE010203040506000000000000",
           (None, None, "02D4"),
           (None, None, "0CD40600 0102030405060708"),
           ("0CD50700 0102030405060708", None, "02D4"),
           (None, None, "03D40A"),
           ("03D50B", None, None)]
    dep = nfc.dep.Target(ContactlessFrontend(seq))
    assert dep.activate(timeout=0.5, brs=1) == ""
    loop = dep.exchange(send_data=None, timeout=1.0)
    assert loop == "0102030405060708".decode("hex")
    assert dep.exchange(send_data=loop, timeout=1.0) == None
