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

from nose.tools import raises

def test_bt_config_record_args_none():
    record = nfc.ndef.BluetoothConfigRecord()
    assert record.type == 'application/vnd.bluetooth.ep.oob'
    assert record.name == ''
    assert record.eir == dict()
    assert record.device_address == "00:00:00:00:00:00"
    assert record.local_device_name == None
    assert record.simple_pairing_hash == None
    assert record.simple_pairing_rand == None
    assert record.service_class_uuid_list == list()
    assert record.class_of_device == None

def test_bt_config_record_decode():
    record = nfc.ndef.Record('application/vnd.bluetooth.ep.oob')
    record.data = bluetooth_config_data
    record = nfc.ndef.BluetoothConfigRecord(record)
    assert record.type == 'application/vnd.bluetooth.ep.oob'
    assert record.name == ''
    assert record.device_address == "A1:BF:80:80:07:01"
    assert record.local_device_name == "DeviceName"
    assert record.simple_pairing_hash == \
        bytearray.fromhex("0F0E0D0C0B0A09080706050403020100")
    assert record.simple_pairing_rand == \
        bytearray.fromhex("0F0E0D0C0B0A09080706050403020100")
    assert record.service_class_uuid_list == [
        "00001106-0000-1000-8000-00805f9b34fb",
        "00001120-0000-1000-8000-00805f9b34fb"]
    assert record.class_of_device == 0x080620

def test_bt_config_record_encode_device_address():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    assert record.data == "\x08\x00\x01\x07\x80\x80\xBF\xA1"

def test_bt_config_record_encode_class_of_device():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.class_of_device = 0x080620
    binary = "0D00 01078080BFA1 040D200608"
    assert record.data == str(bytearray.fromhex(binary))

def test_bt_config_record_encode_device_name():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.local_device_name = "DeviceName"
    binary = "1400 01078080BFA1 0B09 4465766963654e616d65"
    assert record.data == str(bytearray.fromhex(binary))

def test_bt_config_record_encode_sp_hash():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.simple_pairing_hash = \
        bytearray.fromhex("0F0E0D0C0B0A09080706050403020100")
    binary = "1A00 01078080BFA1 110E 0F0E0D0C0B0A09080706050403020100"
    assert record.data == str(bytearray.fromhex(binary))

@raises(nfc.ndef.EncodeError)
def test_bt_config_record_encode_invalid_sp_hash():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.simple_pairing_hash = \
        bytearray.fromhex("0706050403020100")

def test_bt_config_record_encode_sp_rand():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.simple_pairing_rand = \
        bytearray.fromhex("0F0E0D0C0B0A09080706050403020100")
    binary = "1A00 01078080BFA1 110F 0F0E0D0C0B0A09080706050403020100"
    assert record.data == str(bytearray.fromhex(binary))

@raises(nfc.ndef.EncodeError)
def test_bt_config_record_encode_invalid_sp_rand():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.simple_pairing_rand = \
        bytearray.fromhex("0706050403020100")

def test_bt_config_record_encode_uuid_16():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.service_class_uuid_list = [
        "00001106-0000-1000-8000-00805f9b34fb",
        "00001120-0000-1000-8000-00805f9b34fb"]
    binary = "0E00 01078080BFA1 0503 06112011"
    assert record.data == str(bytearray.fromhex(binary))

def test_bt_config_record_encode_uuid_32():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.service_class_uuid_list = [
        "11060000-0000-1000-8000-00805f9b34fb",
        "11200000-0000-1000-8000-00805f9b34fb"]
    binary = "1200 01078080BFA1 0905 0000061100002011"
    assert record.data == str(bytearray.fromhex(binary))

def test_bt_config_record_encode_uuid_128():
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "A1:BF:80:80:07:01"
    record.service_class_uuid_list = ["11060000-1111-1000-8000-00805f9b34fb"]
    binary = "1A00 01078080BFA1 1107 0000061111110010800000805f9b34fb"
    print record.data.encode("hex")
    assert record.data == str(bytearray.fromhex(binary))
    
bluetooth_config_data = bytearray([
        0x43, # Bluetooth OOB Data Length: 67 octets
        0x00,
        # Bluetooth Device Address: A1:BF:80:80:07:01
        0x01, 0x07, 0x80, 0x80, 0xBF, 0xA1,
        0x04, # EIR Data Length: 4 octets
        0x0D, # EIR Data Type: Class of Device
        # Class of Device 0x080620 (Imaging, Camera, Capturing)
        0x20, 0x06, 0x08, 
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
