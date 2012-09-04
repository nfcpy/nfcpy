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

def test_wifi_config_record_args_none():
    record = nfc.ndef.WifiConfigRecord()
    assert record.type == 'application/vnd.wfa.wsc'
    assert record.name == ''
    assert record.version == '2.0'
    assert len(record.credentials) == 1
    assert record.credential['network-name'] == ''
    assert record.credential['network-key'] == ''
    assert record.credential['authentication'] == 'Open'
    assert record.credential['encryption'] == 'None'
    assert record.credential['mac-address'] == 'ff:ff:ff:ff:ff:ff'
    assert record.credential.get('shareable') == None
    assert record.credential.get('other') == None
    assert record.other == list()

wifi_config_record = \
    "\xD2\x17\x56\x61\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x2F\x76" + \
    "\x6E\x64\x2E\x77\x66\x61\x2E\x77\x73\x63\x10\x4A\x00\x01\x10\x10" + \
    "\x0E\x00\x43\x10\x26\x00\x01\x01\x10\x45\x00\x08\x48\x6F\x6D\x65" + \
    "\x57\x4C\x41\x4E\x10\x03\x00\x02\x00\x20\x10\x0F\x00\x02\x00\x08" + \
    "\x10\x27\x00\x0E\x4D\x79\x50\x72\x65\x53\x68\x61\x72\x65\x64\x4B" + \
    "\x65\x79\x10\x20\x00\x06\xFF\xFF\xFF\xFF\xFF\xFF\x10\x49\x00\x06" + \
    "\x00\x37\x2A\x02\x01\x01\x10\x49\x00\x06\x00\x37\x2A\x00\x01\x20"

def test_wifi_config_record_decode():
    record = nfc.ndef.Record(data = wifi_config_record)
    record = nfc.ndef.WifiConfigRecord(record)
    assert record.version == '2.0'
    assert len(record.credentials) == 1
    assert record.credential['network-name'] == 'HomeWLAN'
    assert record.credential['network-key'] == 'MyPreSharedKey'
    assert record.credential['authentication'] == 'WPA2-Personal'
    assert record.credential['encryption'] == 'AES'
    assert record.credential['mac-address'] == 'ff:ff:ff:ff:ff:ff'
    assert record.credential['shareable'] == True
    assert record.credential.get('other') == None
    assert record.other == list()

wifi_config_record_encode_empty_result = ''.join([
    "12 17 36 61 70 70 6c 69  63 61 74 69 6f 6e 2f 76", # |..6application/v|
    "6e 64 2e 77 66 61 2e 77  73 63 10 4a 00 01 10 10", # |nd.wfa.wsc.J....|
    "0e 00 23 10 26 00 01 01  10 45 00 00 10 03 00 02", # |..#.&....E......|
    "00 01 10 0f 00 02 00 01  10 27 00 00 10 20 00 06", # |.........'... ..|
    "ff ff ff ff ff ff 10 49  00 06 00 37 2a 00 01 20", # |.......I...7*.. |
    ])
def test_wifi_config_record_encode_empty():
    result = str(bytearray.fromhex(wifi_config_record_encode_empty_result))
    record = nfc.ndef.WifiConfigRecord()
    print repr(str(record))
    assert str(record) == result

wifi_config_record_encode_all_result = ''.join([
    "12 17 56 61 70 70 6c 69  63 61 74 69 6f 6e 2f 76", # |..Vapplication/v|
    "6e 64 2e 77 66 61 2e 77  73 63 10 4a 00 01 10 10", # |nd.wfa.wsc.J....|
    "0e 00 43 10 26 00 01 01  10 45 00 08 48 6f 6d 65", # |..C.&....E..Home|
    "57 4c 41 4e 10 03 00 02  00 20 10 0f 00 02 00 08", # |WLAN..... ......|
    "10 27 00 0e 4d 79 50 72  65 53 68 61 72 65 64 4b", # |.'..MyPreSharedK|
    "65 79 10 20 00 06 ff ff  ff ff ff ff 10 49 00 06", # |ey. .........I..|
    "00 37 2a 02 01 01 10 49  00 06 00 37 2a 00 01 20", # |.7*....I...7*.. |
    ])
def test_wifi_config_record_encode_full():
    result = str(bytearray.fromhex(wifi_config_record_encode_all_result))
    record = nfc.ndef.WifiConfigRecord()
    record.credential['network-name'] = 'HomeWLAN'
    record.credential['network-key'] = 'MyPreSharedKey'
    record.credential['authentication'] = 'WPA2-Personal'
    record.credential['encryption'] = 'AES'
    record.credential['mac-address'] = 'ff:ff:ff:ff:ff:ff'
    record.credential['shareable'] = True
    print repr(str(record))
    assert str(record) == result

def test_wifi_config_record_auth_types():
    data = str(bytearray.fromhex(wifi_config_record_encode_empty_result))
    def check(value, name):
        record = nfc.ndef.Record(data = data[0:48] + value + data[50:])
        record = nfc.ndef.WifiConfigRecord(record)
        assert record.credential['authentication'] == name
        pass
    auth_type_names = {
        '\x00\x01': 'Open',
        '\x00\x02': 'WPA-Personal',
        '\x00\x04': 'Shared',
        '\x00\x08': 'WPA-Enterprise',
        '\x00\x10': 'WPA2-Enterprise',
        '\x00\x20': 'WPA2-Personal',
        '\x00\x22': 'WPA/WPA2-Personal',
        '\xaa\xbb': 'aabb',
        }
    for value, name in auth_type_names.iteritems():
        yield check, value, name

def test_wifi_config_record_crypt_types():
    data = str(bytearray.fromhex(wifi_config_record_encode_empty_result))
    def check(value, name):
        record = nfc.ndef.Record(data = data[0:54] + value + data[56:])
        record = nfc.ndef.WifiConfigRecord(record)
        assert record.credential['encryption'] == name
        pass
    crypt_type_names = {
        '\x00\x01': 'None',
        '\x00\x02': 'WEP',
        '\x00\x04': 'TKIP',
        '\x00\x08': 'AES',
        '\x00\x0C': 'AES/TKIP',
        '\xaa\xbb': 'aabb',
        }
    for value, name in crypt_type_names.iteritems():
        yield check, value, name

