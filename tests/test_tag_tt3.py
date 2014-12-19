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
from struct import pack, unpack
from nose.tools import raises
from nose.plugins.skip import SkipTest

import logging
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag.tt3").setLevel(logging_level)
logging.getLogger("nfc.tag").setLevel(logging_level)

class Type3TagSimulator(nfc.clf.ContactlessFrontend):
    def __init__(self, tag_memory):
        self.dev = nfc.dev.Device()
        self.mem = tag_memory
        self.idm = bytearray.fromhex("02 FE 00 01 02 03 04 05")
        self.pmm = bytearray.fromhex("03 01 4B 02 4F 49 93 FF")
        self.sys = bytearray.fromhex("12 FC")
        self.cmd_counter = 0

    def sense(self, targets):
        return nfc.clf.TTF(424, self.idm, self.pmm, self.sys)

    def exchange(self, data, timeout):
        print hexlify(data)
        self.cmd_counter += 1
        data = bytearray(data)
        if data[1] == 0x06 and data[2:10] == self.idm: # READ W/O ENC
            block_list = self.parse_service_and_block_list(data[10:])
            maxt = self.calculate_timeout(self.pmm[5], len(block_list))
            assert timeout == maxt
            data = bytearray()
            for service, block, i in block_list:
                try:
                    data += self.mem[service][block]
                except IndexError:
                    return "\x0C\x07" + self.idm + "\x01\xA2"
            return self.encode(0x06, self.idm, chr(len(block_list)) + data)
        if data[1] == 0x08 and data[2:10] == self.idm: # WRITE W/O ENC
            block_list = self.parse_service_and_block_list(data[10:])
            maxt = self.calculate_timeout(self.pmm[6], len(block_list))
            assert timeout == maxt
            data = data[-len(block_list)*16:]
            for service, block, i in block_list:
                print hex(service), hex(block), i
                try:
                    self.mem[service][block][:] = data[i*16:(i+1)*16]
                except IndexError:
                    return "\x0C\x09" + self.idm + "\x01\xA2"
            return self.encode(0x08, self.idm, '')
            
        raise nfc.clf.TimeoutError("invalid command for type 3 tag")

    @staticmethod
    def encode(cmd, idm, data):
        return chr(12+len(data)) + chr(cmd+1) + idm + '\0\0' + data

    @staticmethod
    def calculate_timeout(pmm_byte, block_count):
        a, b, e = pmm_byte & 7, pmm_byte>>3 & 7, pmm_byte>>6
        return 302E-6 * ((b + 1) * block_count + a + 1) * 4**e

    @staticmethod
    def parse_service_and_block_list(data):
        service_list = [data[2*i+1] | (data[2*i+2]<<8) for i in range(data[0])]
        block_list_elements = data[1+data[0]*2]
        data = data[2+data[0]*2:]
        block_list = []
        for i in range(block_list_elements):
            if data[0] >> 7 == 1:
                service_index = data[0] & 0x0F
                block_number = data[1]
                del data[0:2]
            else:
                service_index = data[0] & 0x0F
                block_number = data[1] | (data[2] << 8)
                del data[0:3]
            block_list.append((service_list[service_index], block_number, i))
        return block_list
    
    def set_communication_mode(self, brm, **kwargs):
        pass

################################################################################
#
# EXTERNALLY DEFINED TEST CASES
#
################################################################################

def test_manufacture_parameter_and_maximum_timing():
    # TC_T3T_MEM_BV_1
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
        "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
    ]]
    tag_services = {
        0x0009: ndef_service_data,  0x000B: ndef_service_data,
    }
    clf = Type3TagSimulator(tag_services)
    tag = clf.connect(rdwr={'on-connect': None})
    send_data = bytearray("0123456789abcdef")
    tag.write_to_ndef_service(send_data, 1)
    rcvd_data = tag.read_from_ndef_service(1)
    assert send_data == rcvd_data
    tag.write_to_ndef_service(bytearray("\x0F"+15*"\0"), 1)

def test_frame_structure_and_communication_protocol():
    # TC_T3T_FTH_BV_1
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
        "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
    ]]
    tag_services = {
        0x0009: ndef_service_data,  0x000B: ndef_service_data,
    }
    clf = Type3TagSimulator(tag_services)
    tag = clf.connect(rdwr={'on-connect': None})
    send_data = bytearray("0123456789abcdef")
    tag.write_to_ndef_service(send_data, 1)
    rcvd_data = tag.read_from_ndef_service(1)
    assert send_data == rcvd_data
    tag.write_to_ndef_service(bytearray("\x0F"+15*"\0"), 1)

def test_update_command_and_check_command_with_different_services():
    # TC_T3T_CSE_BV_1
    memory_blocks = [bytearray(16) for i in range(15)]
    tag_services = {
        0x0009: [memory_blocks[0]],  0x000B: [memory_blocks[0]],
        0x1149: [memory_blocks[1]],  0x114B: [memory_blocks[1]],
        0x2289: [memory_blocks[2]],  0x228B: [memory_blocks[2]],
        0x33C9: [memory_blocks[3]],  0x33CB: [memory_blocks[3]],
        0x4409: [memory_blocks[4]],  0x440B: [memory_blocks[4]],
        0x5549: [memory_blocks[5]],  0x554B: [memory_blocks[5]],
        0x6689: [memory_blocks[6]],  0x668B: [memory_blocks[6]],
        0x77C9: [memory_blocks[7]],  0x77CB: [memory_blocks[7]],
        0x8809: [memory_blocks[8]],  0x880B: [memory_blocks[8]],
        0x9949: [memory_blocks[9]],  0x994B: [memory_blocks[9]],
        0xAA89: [memory_blocks[10]], 0xAA8B: [memory_blocks[10]],
        0xBBC9: [memory_blocks[11]], 0xBBCB: [memory_blocks[11]],
        0xCC0B: [memory_blocks[12]],
        0xDD4B: [memory_blocks[13]],
        0xEE8B: [memory_blocks[14]],
    }
    clf = Type3TagSimulator(tag_services)
    tag = clf.connect(rdwr={'on-connect': None})
    service_code_list = list()
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0000000000, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0001000101, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0010001010, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0011001111, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0100010000, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0101010101, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0110011010, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0111011111, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1000100000, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1001100101, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1010101010, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1011101111, 0b001001))
    block_code_list = [nfc.tag.tt3.BlockCode(0, service=i) for i in range(12)]
    send_data = bytearray(''.join([16*c for c in '0123456789AB']))
    tag.write_without_encryption(service_code_list, block_code_list, send_data)

    service_code_list = list()
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0000000000, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0001000101, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0010001010, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0011001111, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0100010000, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0101010101, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0110011010, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0111011111, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1000100000, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1001100101, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1010101010, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1011101111, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1100110000, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1101110101, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b1110111010, 0b001011))
    block_code_list = [nfc.tag.tt3.BlockCode(0, service=i) for i in range(15)]
    rcvd_data = tag.read_without_encryption(service_code_list, block_code_list)
    assert rcvd_data[0:12*16] == send_data

def test_block_list_format():
    # TC_T3T_CSE_BV_2
    memory_blocks = [bytearray(16) for i in range(5*4)]
    tag_services = {
        0x0009: memory_blocks[ 0: 4],  0x000B: memory_blocks[ 0: 4],
        0x1149: memory_blocks[ 4: 8],  0x114B: memory_blocks[ 4: 8],
        0x2289: memory_blocks[ 8:12],  0x228B: memory_blocks[ 8:12],
        0x33C9: memory_blocks[12:16],  0x33CB: memory_blocks[12:16],
        0x4409: memory_blocks[16:20],  0x440B: memory_blocks[16:20],
    }
    clf = Type3TagSimulator(tag_services)
    tag = clf.connect(rdwr={'on-connect': None})
    service_code_list = list()
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0000000000, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0001000101, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0010001010, 0b001001))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0011001111, 0b001001))
    block_code_list = list()
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(3, service=3))
    send_data = bytearray(''.join([16*c for c in '0001112223333']))
    tag.write_without_encryption(service_code_list, block_code_list, send_data)

    service_code_list = list()
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0000000000, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0001000101, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0010001010, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0011001111, 0b001011))
    service_code_list.append(nfc.tag.tt3.ServiceCode(0b0100010000, 0b001011))
    block_code_list = list()
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=0))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=1))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=2))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=3))
    block_code_list.append(nfc.tag.tt3.BlockCode(0, service=4))
    block_code_list.append(nfc.tag.tt3.BlockCode(1, service=4))
    block_code_list.append(nfc.tag.tt3.BlockCode(2, service=4))
    rcvd_data = tag.read_without_encryption(service_code_list, block_code_list)
    assert rcvd_data[0:12*16] == send_data[0:12*16]
    # can't test 3-byte block elements as in test description when the
    # block address is below 256. The nfcpy implementation will always
    # use 2-byte format if it fits.

@raises(AttributeError)
def test_write_to_ndef_tag_with_rw_flag_zero():
    # TC_T3T_NDA_BV_1
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
        "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
    ]]
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.capacity == 16
    assert tag.ndef.length == 16
    assert tag.ndef.is_readable == True
    assert tag.ndef.is_writeable == False
    tag.ndef.message = nfc.ndef.Message(nfc.ndef.Record())

def test_ndef_versioning_tolerable_version_number_one_dot_zero():
    # TC_T3T_NDA_BV_2_0
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 01 AF",
        "d1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f",
        "72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46",
        "43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
    ]]
    uri = 'http://nfc-forum.org'; title = "NFC Forum"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri, title))
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.length == 240
    assert tag.ndef.message == msg

def test_ndef_versioning_tolerable_version_number_one_dot_one():
    # TC_T3T_NDA_BV_2_1
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "11 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 01 B0",
        "d1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f",
        "72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46",
        "43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
    ]]
    uri = 'http://nfc-forum.org'; title = "NFC Forum"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri, title))
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.length == 240
    assert tag.ndef.message == msg

def test_ndef_versioning_intolerable_version_number_two_dot_zero():
    # TC_T3T_NDA_BV_2_3
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "20 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 01 BF",
    ]]
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is None
    assert clf.cmd_counter == 1
    
def test_ndef_detection_and_read_sequence_with_a_correct_checksum_value():
    # TC_T3T_NDA_BV_3_0
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 01 AF",
        "d1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f",
        "72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46",
        "43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
    ]]
    uri = 'http://nfc-forum.org'; title = "NFC Forum"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri, title))
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.length == 240
    assert tag.ndef.message == msg

def test_ndef_detection_and_read_sequence_with_an_incorrect_checksum_value():
    # TC_T3T_NDA_BV_3_1
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 00 FF",
    ]]
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is None
    assert clf.cmd_counter == 1

def test_ndef_write_sequence():
    # TC_T3T_NDA_BV_4
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 0F 0C 00  93 00 00 00  00 00 01 00  00 F0 01 AF",
        "d1 02 22 53  70 91 01 0e  55 03 6e 66  63 2d 66 6f",
        "72 75 6d 2e  6f 72 67 51  01 0c 54 02  65 6e 4e 46",
        "43 20 46 6f  72 75 6d 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
    ]]
    tag_services = {
        0x0009: ndef_service_data,  0x000B: ndef_service_data,
    }
    uri = 'http://nfc-forum.org'; title = "NFC Forum Home"
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri, title))
    clf = Type3TagSimulator(tag_services)
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.length == 240
    tag.ndef.message = msg
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.length == 44
    assert tag.ndef.message == msg

################################################################################
#
# ADDITIONAL NFCPY TEST CASES
#
################################################################################

def test_read_from_ndef_service_with_zero_data_blocks():
    clf = Type3TagSimulator({0x000B: []})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is None

def test_read_from_ndef_service_with_only_attribute_block():
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 01 01 00  00 00 00 00  00 00 01 00  00 00 00 13",
    ]]
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.capacity == 0
    assert tag.ndef.length == 0

def test_read_from_ndef_service_with_two_data_blocks():
    ndef_service_data = [bytearray.fromhex(hexstr) for hexstr in [
        "10 01 01 00  01 00 00 00  00 00 01 00  00 10 00 24",
        "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
    ]]
    uri = 'http://ab.com'
    msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri))
    clf = Type3TagSimulator({0x000B: ndef_service_data})
    tag = clf.connect(rdwr={'on-connect': None})
    assert tag.ndef is not None
    assert tag.ndef.capacity == 16
    assert tag.ndef.length == 16
    assert tag.ndef.message == msg

