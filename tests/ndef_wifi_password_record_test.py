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

def test_wifi_password_record_args_none():
    record = nfc.ndef.WifiPasswordRecord()
    assert record.type == 'application/vnd.wfa.wsc'
    assert record.name == ''
    assert record.version == '2.0'
    assert len(record.passwords) == 1
    assert record.password['public-key-hash'] == 20 * '\x00'
    assert record.password['password-id'] == 0
    assert record.password['password'] == ''
    assert record.other == list()

wifi_app_note_example = \
    "\xD2\x17\x39\x61\x70\x70\x6C\x69\x63\x61\x74\x69\x6F\x6E\x2F\x76" +\
    "\x6E\x64\x2E\x77\x66\x61\x2E\x77\x73\x63\x10\x4A\x00\x01\x10\x10" +\
    "\x2C\x00\x26\x02\x45\x67\x21\x23\x60\x40\x93\x84\xAF\xAD\x23\x24" +\
    "\x9A\x10\x3C\xDF\x3F\x66\x41\x01\x0F\x4C\x3B\x2B\x20\x6A\x21\x2B" +\
    "\x2C\x56\x41\x32\x51\x77\x42\x2B\x20\x10\x49\x00\x06\x00\x37\x2A" +\
    "\x00\x01\x20"

def test_wifi_password_record_encode():
    record = nfc.ndef.WifiPasswordRecord()
    record.password['public-key-hash'] = \
        "024567212360409384AFAD23249A103CDF3F6641".decode('hex')
    record.password['password-id'] = 271
    record.password['password'] = "L;+ j!+,VA2QwB+ "
    message = nfc.ndef.Message(record)
    binary = str(message); exampl = wifi_app_note_example
    assert str(message) == wifi_app_note_example
    
