#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import nfc.ndef
import nfc.ndef.handover

from nose.tools import raises

# --------------------------------------------------- nfc.ndef.handover.Version
def test_version_args_none():
    version = nfc.ndef.handover.Version()
    assert version.major == 0
    assert version.minor == 0

def test_version_decode():
    version = nfc.ndef.handover.Version('\x12')
    assert version.major == 1
    assert version.minor == 2

def test_version_encode():
    version = nfc.ndef.handover.Version('\x12')
    assert str(version) == '\x12'
    
def test_version_equal():
    version = nfc.ndef.handover.Version('\x12')
    assert version == nfc.ndef.handover.Version('\x12')

def test_version_lower():
    version = nfc.ndef.handover.Version('\x12')
    assert version < nfc.ndef.handover.Version('\x13')
    assert version < nfc.ndef.handover.Version('\x21')

def test_version_higher():
    version = nfc.ndef.handover.Version('\x22')
    assert version > nfc.ndef.handover.Version('\x13')
    assert version > nfc.ndef.handover.Version('\x21')

# --------------------------------------------- nfc.ndef.handover.HandoverError
def test_handover_error_decode():
    def check((payload, reason, data)):
        error = nfc.ndef.handover.HandoverError(payload)
        assert error.reason == reason
        assert error.data == data
    for params in [("\x01\x10", 1, 16),
                   ("\x02\x00\x00\x04\x00", 2, 1024),
                   ("\x03\x0C", 3, 12)]:
        yield check, params

def test_handover_error_encode():
    def check((payload, reason, data)):
        error = nfc.ndef.handover.HandoverError()
        error.reason = reason
        error.data = data
        assert str(error) == payload
    for params in [("\x01\x10", 1, 16),
                   ("\x02\x00\x00\x04\x00", 2, 1024),
                   ("\x03\x0C", 3, 12)]:
        yield check, params

def test_handover_error_encode_invalid_reason():
    @raises(nfc.ndef.EncodeError)
    def check(reason):
        error = nfc.ndef.handover.HandoverError()
        error.reason = reason
        error.encode()
    for params in [0] + range(4, 256):
        yield check, params

# ------------------------------------- nfc.ndef.handover.HandoverCarrierRecord
def test_hc_message_args_none():
    record = nfc.ndef.handover.HandoverCarrierRecord('')
    assert record.type == 'urn:nfc:wkt:Hc'
    assert record.carrier_type == ''
    assert record.carrier_data == ''

def test_hc_message_decode():
    for p in [
        ('',
         '',
         '\x11\x02\x02\x48\x63\x00\x00'),
        ('application/vnd.bluetooth.ep.oob',
         '',
         '\x11\x02\x22Hc\x02\x20application/vnd.bluetooth.ep.oob'),
        ('application/vnd.bluetooth.ep.oob',
         'DATA',
         '\x11\x02\x26Hc\x02\x20application/vnd.bluetooth.ep.oobDATA'),
        ]:
        yield check_hc_message_decode, p[0], p[1], p[2]

def check_hc_message_decode(carrier_type, carrier_data, binary_data):
    record = nfc.ndef.Record(data=binary_data)
    record = nfc.ndef.handover.HandoverCarrierRecord(record)
    assert record.carrier_type == carrier_type
    assert record.carrier_data == carrier_data

def test_hc_message_encode():
    for p in [
        ('',
         '',
         '\x11\x02\x02\x48\x63\x00\x00'),
        ('application/vnd.bluetooth.ep.oob',
         '',
         '\x11\x02\x22Hc\x02\x20application/vnd.bluetooth.ep.oob'),
        ('application/vnd.bluetooth.ep.oob',
         'DATA',
         '\x11\x02\x26Hc\x02\x20application/vnd.bluetooth.ep.oobDATA'),
        ]:
        yield check_hc_message_encode, p[0], p[1], p[2]

def check_hc_message_encode(carrier_type, carrier_data, binary_data):
    record = nfc.ndef.handover.HandoverCarrierRecord(carrier_type)
    record.carrier_data = carrier_data
    assert str(record) == binary_data

# --------------------------------------------- nfc.ndef.HandoverRequestMessage
def test_hr_message_init_arg_message():
    message = nfc.ndef.Message("d10201487210".decode("hex"))
    message = nfc.ndef.HandoverRequestMessage(message=message)
    assert message.type == 'urn:nfc:wkt:Hr'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 0
    assert message.nonce == None
    assert message.carriers == list()
    assert str(message).encode("hex") == "d10201487210"
    
def test_hr_message_init_arg_version():
    message = nfc.ndef.HandoverRequestMessage(version="1.0")
    assert message.type == 'urn:nfc:wkt:Hr'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 0
    assert message.nonce == None
    assert message.carriers == list()
    assert str(message).encode("hex") == "d10201487210"
    
def test_hr_message_init_arg_version_range():
    def check_valid(version):
        nfc.ndef.HandoverRequestMessage(version=version)
    for minor in range(16):
        yield check_valid, "{0}.{1}".format(1, minor)
        
    @raises(ValueError)
    def check_invalid(version_string):
        nfc.ndef.HandoverRequestMessage(version=version_string)
    for major, minor in [(0,0), (0,1), (2,0), (2,15), (1,16), (16,0)]:
        yield check_invalid, "{0}.{1}".format(major, minor)
    
def test_hr_message_encode_version_1_1():
    message = nfc.ndef.HandoverRequestMessage(version="1.1")
    assert str(message).encode("hex") == "d10201487211"

@raises(nfc.ndef.EncodeError)
def test_hr_message_encode_version_1_2_missing_nonce():
    message = nfc.ndef.HandoverRequestMessage(version="1.2")
    assert str(message).encode("hex") == "d10201487212"
    
def test_hr_message_encode_version_1_2_with_nonce():
    message = nfc.ndef.HandoverRequestMessage(version="1.2")
    message.nonce = 1025
    assert str(message).encode("hex") == "d10208487212d1020263720401"
    
def test_hr_message_encode_one_carrier_record():
    message = nfc.ndef.HandoverRequestMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data"
    message.add_carrier(carrier, "active")
    assert message.carriers[0].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[0].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[0].record.carrier_data == "data"
    binary = "91020a487211d10204616301013000" + \
        "59020c014863300106782d7465737464617461"
    assert str(message).encode("hex") == binary
    
def test_hr_message_encode_two_carrier_record():
    message = nfc.ndef.HandoverRequestMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data1"
    message.add_carrier(carrier, "active")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data2"
    message.add_carrier(carrier, "active")
    assert message.carriers[0].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[0].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[0].record.carrier_data == "data1"
    assert message.carriers[1].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[1].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[1].record.carrier_data == "data2"
    binary = "910213487211910204616301013000510204616301013100" + \
        "19020d014863300106782d746573746461746131" + \
        "59020d014863310106782d746573746461746132"
    assert str(message).encode("hex") == binary
    
def test_hr_message_encode_auxiliary_data_records():
    message = nfc.ndef.HandoverRequestMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    text1 = nfc.ndef.TextRecord("nfcpy")
    text2 = nfc.ndef.TextRecord("ypcfn")
    message.add_carrier(carrier, "active", [text1, text2])
    assert len(message.carriers[0].auxiliary_data_records) == 2
    assert message.carriers[0].auxiliary_data_records[0].type == "urn:nfc:wkt:T"
    assert message.carriers[0].auxiliary_data_records[1].type == "urn:nfc:wkt:T"
    assert message.carriers[0].auxiliary_data_records[0].text == "nfcpy"
    assert message.carriers[0].auxiliary_data_records[1].text == "ypcfn"
    binary = \
        "910214487211d1020e61630101300204617578300461757831" + \
        "190208014863300106782d74657374" + \
        "19010804546175783002656e6e66637079" + \
        "59010804546175783102656e797063666e"
    assert str(message).encode("hex") == binary
    
def test_hr_message_decode_bt_example():
    message = nfc.ndef.Message(bluetooth_handover_request_message)
    message = nfc.ndef.HandoverRequestMessage(message)
    assert message.type == 'urn:nfc:wkt:Hr'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 2
    assert message.nonce == 0x0102
    assert message.carriers[0].record.type \
        == 'application/vnd.bluetooth.ep.oob'
    assert message.carriers[0].record.name == "0"
    assert message.carriers[0].power_state == 'active'
    assert message.carriers[0].auxiliary_data_records == list()

bluetooth_handover_request_message = bytearray([
        0x91, # NDEF Header: MB=1b, ME=0b, CF=0b, SR=1b, IL=0b, TNF=001b
        0x02, # Record Type Length: 2 octets
        0x11, # Payload Length: 17 octets
        0x48, # Record Type: 'Hr'
        0x72, 
        0x12, # Version Number: Major = 1, Minor = 2
        0x91, # NDEF Header: MB=1b, ME=0b, CF=0b, SR=1b, IL=0b, TNF=001b
        0x02, # Record Type Length: 2 octets
        0x02, # Payload Length: 2 octets
        0x63, # Record Type: 'cr'
        0x72, 
        0x01, # Random Number: 0x01 0x02
        0x02,
        0x51, # NDEF Header: MB=0b, ME=1b, CF=0b, SR=1b, IL=0b, TNF=001b
        0x02, # Record Type Length: 2 octets
        0x04, # Payload Length: 4 octets
        0x61, # Record Type: 'ac'
        0x63, 
        0x01, # Carrier Flags: CPS=1, 'active'
        0x01, # Carrier Data Reference Length: 1 octet
        0x30, # Carrier Data Reference: '0'
        0x00, # Auxiliary Data Reference Count: 0
        0x5A, # NDEF Header: MB=0b, ME=1b, CF=0b, SR=1b, IL=1b, TNF=010b
        0x20, # Record Type Length: 32 octets
        0x43, # Payload Length: 67 octets
        0x01, # Payload ID Length: 1 octet
        # Record Type Name: 'application/vnd.bluetooth.ep.oob'
        0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74,
        0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E,
        0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74,
        0x68, 0x2E, 0x65, 0x70, 0x2E, 0x6F, 0x6F, 0x62,
        0x30, # Payload ID: '0'
        0x43, # Bluetooth OOB Data Length: 67 octets
        0x00,
        # Bluetooth Device Address: A1:BF:80:80:07:01
        0x01, 0x07, 0x80, 0x80, 0xBF, 0xA1,
        0x04, # EIR Data Length: 4 octets
        0x0D, # EIR Data Type: Class of Device
        # Class of Device
        0x20, #  * 0x20 - Minor Device Class = Camera
        0x06, #  * 0x06 - Major Device Class = Imaging
        0x08, #  * 0x08 - Service Class = Capturing
        0x11, # EIR Data Length: 17 octets
        0x0E, # EIR Data Type: Simple Pairing Hash C
        # Simple Pairing Hash C: 0x000102030405060708090A0B0C0D0E0F
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x11, # EIR Data Length: 17 octets
        0x0F, # EIR Data Type: Simple Pairing Randomizer R
        # Simple Pairing Randomizer R: 0x000102030405060708090A0B0C0D0E0F
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x05, # EIR Data Length: 5 octets
        0x03, # EIR Data Type: 16-bit Service Class UUID list (complete)
        # 16-bit Service Class UUID list (complete)
        0x06, #  * 0x1106 - OBEX File Transfer
        0x11, #  
        0x20, #  * 0x1120 - Direct Printing Reference Object Service
        0x11, #  
        0x0B, # EIR Data Length: 11 octets
        0x09, # EIR Data Type: Complete Local Name
        # Bluetooth Local Name: DeviceName
        0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65])

# ---------------------------------------------- nfc.ndef.HandoverSelectMessage
def test_hs_message_init_arg_message():
    message = nfc.ndef.Message("d10201487310".decode("hex"))
    message = nfc.ndef.HandoverSelectMessage(message=message)
    assert message.type == 'urn:nfc:wkt:Hs'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 0
    assert message.error.reason == None
    assert message.carriers == list()
    
def test_hs_message_init_arg_version():
    message = nfc.ndef.HandoverSelectMessage(version="1.0")
    assert message.type == 'urn:nfc:wkt:Hs'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 0
    assert message.error.reason == None
    assert message.carriers == list()
    
def test_hs_message_init_arg_version_range():
    def check_valid(version_string):
        nfc.ndef.HandoverSelectMessage(version=version_string)
    for minor in range(16):
        yield check_valid, "{0}.{1}".format(1, minor)
        
    @raises(ValueError)
    def check_invalid(version_string):
        nfc.ndef.HandoverSelectMessage(version=version_string)
    for major, minor in [(0,0), (0,1), (2,0), (2,15), (1,16), (16,0)]:
        yield check_invalid, "{0}.{1}".format(major, minor)
    
def test_hs_message_encode_empty():
    message = nfc.ndef.HandoverSelectMessage(version="1.0")
    assert str(message).encode("hex") == "d10201487310"
    
def test_hs_message_encode_version():
    message = nfc.ndef.HandoverSelectMessage(version="1.1")
    assert str(message).encode("hex") == "d10201487311"

def test_hs_message_encode_error_reason_no_data():
    @raises(nfc.ndef.EncodeError)
    def check(reason):
        message = nfc.ndef.HandoverSelectMessage(version="1.0")
        message.error.reason = reason
        str(message).encode("hex")
    for reason in (1, 2, 3):
        yield check, reason
        
def test_hs_message_encode_error_reason_and_valid_data():
    def check((reason, data, result)):
        message = nfc.ndef.HandoverSelectMessage(version="1.2")
        message.error.reason = reason
        message.error.data = data
        assert str(message).encode("hex") == result
    for params in [(1, 100, "d10209487312d103026572720164"),
                   (2, 100, "d1020c487312d103056572720200000064"),
                   (3, 100, "d10209487312d103026572720364")]:
        yield check, params
        
def test_hs_message_encode_one_carrier_record():
    message = nfc.ndef.HandoverSelectMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data"
    message.add_carrier(carrier, "active")
    assert message.carriers[0].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[0].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[0].record.carrier_data == "data"
    binary = "91020a487311d10204616301013000" + \
        "59020c014863300106782d7465737464617461"
    assert str(message).encode("hex") == binary
    
def test_hs_message_encode_two_carrier_record():
    message = nfc.ndef.HandoverSelectMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data1"
    message.add_carrier(carrier, "active")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    carrier.carrier_data = "data2"
    message.add_carrier(carrier, "active")
    assert message.carriers[0].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[0].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[0].record.carrier_data == "data1"
    assert message.carriers[1].record.type == "urn:nfc:wkt:Hc"
    assert message.carriers[1].record.carrier_type == "urn:nfc:wkt:x-test"
    assert message.carriers[1].record.carrier_data == "data2"
    binary = "910213487311910204616301013000510204616301013100" + \
        "19020d014863300106782d746573746461746131" + \
        "59020d014863310106782d746573746461746132"
    assert str(message).encode("hex") == binary
    
def test_hs_message_encode_auxiliary_data_records():
    message = nfc.ndef.HandoverSelectMessage(version="1.1")
    carrier = nfc.ndef.HandoverCarrierRecord("urn:nfc:wkt:x-test")
    text1 = nfc.ndef.TextRecord("nfcpy")
    text2 = nfc.ndef.TextRecord("ypcfn")
    message.add_carrier(carrier, "active", [text1, text2])
    assert len(message.carriers[0].auxiliary_data_records) == 2
    assert message.carriers[0].auxiliary_data_records[0].type == "urn:nfc:wkt:T"
    assert message.carriers[0].auxiliary_data_records[1].type == "urn:nfc:wkt:T"
    assert message.carriers[0].auxiliary_data_records[0].text == "nfcpy"
    assert message.carriers[0].auxiliary_data_records[1].text == "ypcfn"
    binary = \
        "910214487311d1020e61630101300204617578300461757831" + \
        "190208014863300106782d74657374" + \
        "19010804546175783002656e6e66637079" + \
        "59010804546175783102656e797063666e"
    assert str(message).encode("hex") == binary
    
def test_hs_message_decode_bt_example():
    message = nfc.ndef.Message(bluetooth_handover_select_message)
    message = nfc.ndef.HandoverSelectMessage(message)
    assert message.type == 'urn:nfc:wkt:Hs'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 2
    assert len(message.carriers) == 1
    assert message.carriers[0].record.type \
        == 'application/vnd.bluetooth.ep.oob'
    assert message.carriers[0].record.name == "0"
    assert message.carriers[0].power_state == 'active'
    assert message.carriers[0].auxiliary_data_records == list()

bluetooth_handover_select_message = bytearray([
        0x91, # NDEF Record Header: MB=1b, ME=0b, CF=0b, SR=1b, IL=0b, TNF=001b
        0x02, # Record Type Length: 2 octets
        0x0A, # Record Type Length: 10 octets
        0x48, # Record Type: 'Hs'
        0x73, 
        0x12, # Version Number: Major = 1, Minor = 2
        0xD1, # NDEF Record Header: MB=1b, ME=1b, CF=0b, SR=1b, IL=0b, TNF=001b
        0x02, # Record Type Length: 2 octets
        0x04, # Payload Length: 4 octets
        0x61, # Record Type: 'ac'
        0x63,
        0x01, # Carrier Flags: CPS=1, 'active'
        0x01, # Carrier Data Reference Length: 1 octet
        0x30, # Carrier Data Reference: '0'
        0x00, # Auxiliary Data Reference Count: 0
        0x5A, # NDEF Record Header: MB=0b, ME=1b, CF=0b, SR=1b, IL=1b, TNF=010b
        0x20, # Record Type Length: 32 octets
        0x43, # Payload Length: 67 octets
        0x01, # Payload ID Length: 1 octet
        # Record Type Name: application/vnd.bluetooth.ep.oob
        0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 
        0x69, 0x6F, 0x6E, 0x2F, 0x76, 0x6E, 0x64, 0x2E, 
        0x62, 0x6C, 0x75, 0x65, 0x74, 0x6F, 0x6F, 0x74, 
        0x68, 0x2E, 0x65, 0x70, 0x2E, 0x6F, 0x6F, 0x62,
        0x30, # Payload ID: '0'
        0x43, # Bluetooth OOB Data Length: 67 octets
        0x00,
        # Bluetooth Device Address: 01:bf:88:80:07:03
        0x03, 0x07, 0x80, 0x88, 0xbf, 0x01,
        0x04, # EIR Data Length (4 octets)
        0x0D, # EIR Data Type: Class of Device
        # Class of device
        0x80, # * 0x80 - Minor Device class = Printer
        0x06, # * 0x06 - Major Device class = Imaging
        0x04, # * 0x04 - Service class = Rendering
        0x11, # EIR Data Length: 17 octets
        0x0E, # EIR Data Type:  Simple Pairing Hash C
        # Simple Pairing Hash C: 0x000102030405060708090A0B0C0D0E0F
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x11, # EIR Data Length: 17 octets
        0x0F, # EIR Data Type: Simple Pairing Randomizer R
        # Simple Pairing Randomizer R: 0x000102030405060708090A0B0C0D0E0F
        0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
        0x05, # EIR Data Length: 5 octets
        0x03, # EIR Data Type: 16-bit Service Class UUID list (complete)
        # 16-bit Service Class UUID list (complete)
        0x18, #  * 0x1118 - Direct Printing
        0x11, #  
        0x23, #  * 0x1123 - Printing Status
        0x11, #  
        0x0B, # EIR Data Length: 11 octets
        0x09, # EIR Data Type: Complete Local Name
        # Bluetooth Local Name: DeviceName
        0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
        ])

