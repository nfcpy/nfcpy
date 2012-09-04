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

import io
import nfc.ndef

def test_init_args_none():
    message = nfc.ndef.Message()
    assert isinstance(message, nfc.ndef.Message)

def test_method_length():
    message = nfc.ndef.Message()
    assert len(message) == 0

def test_method_getitem():
    message = nfc.ndef.Message()
    try: assert message[0]
    except IndexError: pass

def test_method_append():
    message = nfc.ndef.Message()
    message.append(nfc.ndef.Record())
    assert len(message) == 1
    assert isinstance(message[0], nfc.ndef.Record)
    
def test_method_extend():
    message = nfc.ndef.Message()
    message.extend([nfc.ndef.Record()])
    assert len(message) == 1
    assert isinstance(message[0], nfc.ndef.Record)

def test_method_insert():
    message = nfc.ndef.Message()
    message.insert(0, nfc.ndef.Record())
    assert len(message) == 1
    assert isinstance(message[0], nfc.ndef.Record)

def test_init_args_bytestr():
    message = nfc.ndef.Message(b"\xD0\x00\x00")
    assert len(message) == 1
    
def test_init_args_bytearray():
    message = nfc.ndef.Message(bytearray("\xD0\x00\x00"))
    assert len(message) == 1

def test_init_args_bytestream():
    message = nfc.ndef.Message(io.BytesIO(b"\xD0\x00\x00"))
    assert len(message) == 1

def test_generate_bytestr():
    message = nfc.ndef.Message(b"\xD0\x00\x00")
    assert str(message) == b"\xD0\x00\x00"

def test_init_args_one_record():
    record = nfc.ndef.Record()
    message = nfc.ndef.Message(record)
    assert str(message) == b"\xD0\x00\x00"
    
def test_init_args_two_records():
    record = nfc.ndef.Record()
    message = nfc.ndef.Message(record, record)
    assert str(message) == b"\x90\x00\x00\x50\x00\x00"
    
def test_failure_mb_not_set():
    try: message = nfc.ndef.Message(b"\x10\x00\x00")
    except nfc.ndef.FormatError: pass

def test_failure_length_error():
    try: message = nfc.ndef.Message(b"\x10\x01\x00")
    except nfc.ndef.LengthError: pass
