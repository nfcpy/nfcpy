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
    version = nfc.ndef.handover.Version()
    version.major = 1
    version.minor = 2
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
    for p in [("\x01\x10", 1, 16),
              ("\x02\x00\x00\x04\x00", 2, 1024),
              ("\x03\x0C", 3, 12)]:
        yield check_handover_error_decode, p[0], p[1], p[2]

def check_handover_error_decode(payload, reason, data):
    error = nfc.ndef.handover.HandoverError(payload)
    assert error.reason == reason
    assert error.data == data

def test_handover_error_encode():
    for p in [("\x01\x10", 1, 16),
              ("\x02\x00\x00\x04\x00", 2, 1024),
              ("\x03\x0C", 3, 12),
              ("\x04reserved", 4, "reserved"),
              ]:
        yield check_handover_error_encode, p[0], p[1], p[2]

def check_handover_error_encode(payload, reason, data):
    error = nfc.ndef.handover.HandoverError()
    error.reason = reason
    error.data = data
    assert error.encode() == payload

# ------------------------------------- nfc.ndef.handover.HandoverCarrierRecord
def test_hc_message_args_none():
    record = nfc.ndef.handover.HandoverCarrierRecord()
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
    record = nfc.ndef.handover.HandoverCarrierRecord()
    record.carrier_type = carrier_type
    record.carrier_data = carrier_data
    assert str(record) == binary_data

# --------------------------------------------- nfc.ndef.HandoverRequestMessage
def test_hr_message_args_none():
    message = nfc.ndef.HandoverRequestMessage()
    assert message.type == 'urn:nfc:wkt:Hr'
    assert message.name == ''
    assert message.version.major == 0
    assert message.version.minor == 0
    assert message.nonce == None
    assert message.carriers == list()
    
def test_hr_message_decode():
    message = nfc.ndef.Message(bluetooth_handover_request_message)
    message = nfc.ndef.HandoverRequestMessage(message)
    assert message.type == 'urn:nfc:wkt:Hr'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 2
    assert message.nonce == 0x0102
    assert message.carriers[0].get('carrier-type') \
        == 'application/vnd.bluetooth.ep.oob'
    assert message.carriers[0].get('power-state') == 'active'
    assert len(message.carriers[0].get('config-data')) == 67

def test_hr_message_encode():
    message = nfc.ndef.Message(bluetooth_handover_request_message)
    message = nfc.ndef.HandoverRequestMessage(message)
    assert str(message) == str(bluetooth_handover_request_message)

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
def test_hs_message_args_none():
    message = nfc.ndef.HandoverSelectMessage()
    assert message.type == 'urn:nfc:wkt:Hs'
    assert message.name == ''
    assert message.version.major == 0
    assert message.version.minor == 0
    assert message.error == None
    assert message.carriers == list()
    
def test_hs_message_decode():
    message = nfc.ndef.Message(bluetooth_handover_select_message)
    message = nfc.ndef.HandoverSelectMessage(message)
    assert message.type == 'urn:nfc:wkt:Hs'
    assert message.name == ''
    assert message.version.major == 1
    assert message.version.minor == 2
    assert len(message.carriers) == 1
    assert message.carriers[0].get('carrier-type') \
        == 'application/vnd.bluetooth.ep.oob'
    assert message.carriers[0].get('power-state') == 'active'
    assert len(message.carriers[0].get('config-data')) == 67

def test_hs_message_encode():
    message = nfc.ndef.Message(bluetooth_handover_select_message)
    message = nfc.ndef.HandoverSelectMessage(message)
    assert str(message) == str(bluetooth_handover_select_message)

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

