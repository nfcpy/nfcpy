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

def test_init_args_none():
    record = nfc.ndef.TextRecord()
    assert record.text == ''
    assert record.language == 'en'
    assert record.encoding == 'UTF-8'
    
def test_init_args_text():
    record = nfc.ndef.TextRecord("Hello World")
    assert record.text == "Hello World"
    assert record.language == "en"
    assert record.encoding == 'UTF-8'
    assert str(record) == b'\x11\x01\x0ET\x02enHello World'
    
def test_init_kwargs_text():
    record = nfc.ndef.TextRecord(text="Hello World")
    assert record.text == "Hello World"
    assert record.language == "en"
    assert record.encoding == 'UTF-8'
    assert str(record) == b'\x11\x01\x0ET\x02enHello World'
    
def test_init_kwargs_lang():
    record = nfc.ndef.TextRecord(language="de")
    assert record.text == ""
    assert record.language == "de"
    assert record.encoding == 'UTF-8'
    assert str(record) == b'\x11\x01\x03T\x02de'
    
def test_init_args_text_kwargs_lang():
    record = nfc.ndef.TextRecord("Hallo Welt", language="de")
    assert record.text == "Hallo Welt"
    assert record.language == "de"
    assert record.encoding == 'UTF-8'
    assert str(record) == b'\x11\x01\x0DT\x02deHallo Welt'
    
def test_init_kwargs_text_encoding():
    record = nfc.ndef.TextRecord(text="text", encoding="UTF-16")
    assert record.text == "text"
    assert record.language == "en"
    assert record.encoding == 'UTF-16'
    assert str(record) == b'\x11\x01\x0DT\x82en\xff\xfet\x00e\x00x\x00t\x00'
    
def test_init_arg_record():
    record = nfc.ndef.Record(data=b'\x11\x01\x0DT\x02deHallo Welt')
    record = nfc.ndef.TextRecord(record)
    assert record.text == "Hallo Welt"
    assert record.language == "de"
    assert record.encoding == 'UTF-8'
    assert str(record) == b'\x11\x01\x0DT\x02deHallo Welt'
    
def test_text_encode_utf8():
    record = nfc.ndef.TextRecord(text=u'\xa1\xa2')
    assert str(record) == b'\x11\x01\x07T\x02en\xc2\xa1\xc2\xa2'

def test_text_encode_utf16():
    record = nfc.ndef.TextRecord(text=u'\xa1\xa2', encoding="UTF-16")
    assert str(record) == b'\x11\x01\x09T\x82en\xff\xfe\xa1\x00\xa2\x00'

def test_text_decode_utf8():
    data=b'\x11\x01\x07T\x02fr\xc2\xa1\xc2\xa2'
    record = nfc.ndef.TextRecord(nfc.ndef.Record(data=data))
    assert record.text == u'\xa1\xa2'
    assert record.language == "fr"

def test_text_decode_utf16():
    data=b'\x11\x01\x09T\x82fr\xff\xfe\xa1\x00\xa2\x00'
    record = nfc.ndef.TextRecord(nfc.ndef.Record(data=data))
    assert record.text == u'\xa1\xa2'
    assert record.language == "fr"

def test_data_length_error():
    data=b'\x11\x01\x0DT\x0DdeHallo Welt'
    record = nfc.ndef.TextRecord(nfc.ndef.Record(data=data))
    assert record.language == "deHallo Welt"
    assert record.text == ""

