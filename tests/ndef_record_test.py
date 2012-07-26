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
from nose.tools import raises

def test_init_args_none():
    record = nfc.ndef.Record()
    assert record.type == ''
    assert record.name == ''
    assert record.data == ''

def test_init_args_type():
    record = nfc.ndef.Record('urn:nfc:wkt:T')
    assert record.type == 'urn:nfc:wkt:T'
    assert record.name == ''
    assert record.data == ''

def test_init_args_type_name():
    record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier')
    assert record.type == 'urn:nfc:wkt:T'
    assert record.name == 'identifier'
    assert record.data == ''

def test_init_args_type_name_data():
    record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier', 'Hello World')
    assert record.type == 'urn:nfc:wkt:T'
    assert record.name == 'identifier'
    assert record.data == 'Hello World'

def test_init_args_type_data():
    record = nfc.ndef.Record('urn:nfc:wkt:T', data='Hello World')
    assert record.type == 'urn:nfc:wkt:T'
    assert record.name == ''
    assert record.data == 'Hello World'

def test_init_args_name():
    record = nfc.ndef.Record(record_name='identifier')
    assert record.type == 'unknown'
    assert record.name == 'identifier'
    assert record.data == ''

def test_init_args_type_name_data():
    record = nfc.ndef.Record(record_name='identifier', data='Hello World')
    assert record.type == 'unknown'
    assert record.name == 'identifier'
    assert record.data == 'Hello World'

def test_init_args_data_string():
    data='\xDA\x0A\x0B\x01text/plain0Hello World' + 10*'\x00'
    record = nfc.ndef.Record(data=data)
    assert record.type == 'text/plain'
    assert record.name == '0'
    assert record.data == 'Hello World'

def test_init_args_data_bytearray():
    data=bytearray('\xDA\x0A\x0B\x01text/plain0Hello World' + 10*'\x00')
    record = nfc.ndef.Record(data=data)
    assert record.type == 'text/plain'
    assert record.name == '0'
    assert record.data == 'Hello World'

def test_init_args_data_bytestream():
    data=io.BytesIO('\xDA\x0A\x0B\x01text/plain0Hello World' + 10*'\x00')
    record = nfc.ndef.Record(data=data)
    assert record.type == 'text/plain'
    assert record.name == '0'
    assert record.data == 'Hello World'
    assert data.tell() - data.seek(0, 2) == -10

def test_init_args_data_invalid_type():
    try: record = nfc.ndef.Record(data=1)
    except TypeError: pass
    else: raise AssertionError("TypeError not raised")

def test_parse_record_type():
    record = nfc.ndef.Record(data='\xD0\x00\x00')
    assert record.type == ''
    record = nfc.ndef.Record(data='\xD1\x01\x00T')
    assert record.type == 'urn:nfc:wkt:T'
    record = nfc.ndef.Record(data='\xD2\x0A\x00text/plain')
    assert record.type == 'text/plain'
    record = nfc.ndef.Record(data='\xD3\x1B\x00http://example.com/type.dtd')
    assert record.type == 'http://example.com/type.dtd'
    record = nfc.ndef.Record(data='\xD4\x10\x00example.com:type')
    assert record.type == 'urn:nfc:ext:example.com:type'
    record = nfc.ndef.Record(data='\xD5\x00\x00')
    assert record.type == 'unknown'
    record = nfc.ndef.Record(data='\xD6\x00\x00')
    assert record.type == 'unchanged'

def test_set_record_type():
    record = nfc.ndef.Record()
    record.type = 'urn:nfc:wkt:T'
    assert record.type == 'urn:nfc:wkt:T'
    record.type = 'text/plain'
    assert record.type == 'text/plain'
    record.type = 'http://example.com/type.dtd'
    assert record.type == 'http://example.com/type.dtd'
    record.type = 'urn:nfc:ext:example.com:type'
    assert record.type == 'urn:nfc:ext:example.com:type'
    record.type = 'unknown'
    assert record.type == 'unknown'
    record.type = 'unchanged'
    assert record.type == 'unchanged'
    record.type = ''
    assert record.type == ''
    try: record.type = 1
    except ValueError: pass

def test_generate_string():
    record = nfc.ndef.Record()
    assert str(record) == '\x10\x00\x00'
    
def test_generate_bytearray():
    record = nfc.ndef.Record()
    assert bytearray(record) == bytearray('\x10\x00\x00')
    
def test_generate_list():
    record = nfc.ndef.Record()
    assert list(record) == list('\x10\x00\x00')
    
def test_generate_parsed():
    record = nfc.ndef.Record(data='\xD0\x00\x00')
    assert str(record) == '\xD0\x00\x00'
    record = nfc.ndef.Record(data='\xD1\x01\x00T')
    assert str(record) == '\xD1\x01\x00T'
    record = nfc.ndef.Record(data='\xD2\x0A\x00text/plain')
    assert str(record) == '\xD2\x0A\x00text/plain'
    record = nfc.ndef.Record(data='\xD3\x1B\x00http://example.com/type.dtd')
    assert str(record) == '\xD3\x1B\x00http://example.com/type.dtd'
    record = nfc.ndef.Record(data='\xD4\x10\x00example.com:type')
    assert str(record) == '\xD4\x10\x00example.com:type'
    record = nfc.ndef.Record(data='\xD5\x00\x00')
    assert str(record) == '\xD5\x00\x00'
    record = nfc.ndef.Record(data='\xD6\x00\x00')
    assert str(record) == '\xD6\x00\x00'

def test_generate_record_type():
    record = nfc.ndef.Record()
    assert str(record) == '\x10\x00\x00'
    record.type = 'urn:nfc:wkt:T'
    assert str(record) == '\x11\x01\x00T'
    record.type = 'text/plain'
    assert str(record) == '\x12\x0A\x00text/plain'
    record.type = 'http://example.com/type.dtd'
    assert str(record) == '\x13\x1B\x00http://example.com/type.dtd'
    record.type = 'urn:nfc:ext:example.com:type'
    assert str(record) == '\x14\x10\x00example.com:type'
    record.type = 'unknown'
    assert str(record) == '\x15\x00\x00'
    record.type = 'unchanged'
    assert str(record) == '\x16\x00\x00'

def test_generate_record_type_name():
    record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier')
    assert str(record) == '\x19\x01\x00\x0ATidentifier'

def test_generate_record_type_name_data():
    record = nfc.ndef.Record('urn:nfc:wkt:T', 'identifier', 'payload')
    assert str(record) == '\x19\x01\x07\x0ATidentifierpayload'

def test_generate_record_long_payload():
    record = nfc.ndef.Record('urn:nfc:wkt:T', 'id', bytearray(256))
    assert str(record) == '\x09\x01\x00\x00\x01\x00\x02Tid' + 256 * '\x00'

def test_decode_record_long_payload():
    data = '\x09\x01\x00\x00\x01\x00\x02Tid' + str(bytearray(256))
    record = nfc.ndef.Record(data=data)
    assert record.type == 'urn:nfc:wkt:T'
    assert record.name == 'id'
    assert record.data == str(bytearray(256))

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_01():
    nfc.ndef.Record(data='\x00')
    
@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_02():
    nfc.ndef.Record(data='\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_03():
    nfc.ndef.Record(data='\x00\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_04():
    nfc.ndef.Record(data='\x00\x00\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_05():
    nfc.ndef.Record(data='\x00\x00\x00\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_06():
    nfc.ndef.Record(data='\x10\x04\x00\x00\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_07():
    nfc.ndef.Record(data='\x10\x00\x04\x00\x00\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_08():
    nfc.ndef.Record(data='\x00\x00\x00\x00\x01\x00')

@raises(nfc.ndef.LengthError)
def test_decode_invalid_length_09():
    nfc.ndef.Record(data='\x00\x00\x00\x00\x00\x01')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_01():
    nfc.ndef.Record(data='\x10\x01\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_02():
    nfc.ndef.Record(data='\x15\x01\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_03():
    nfc.ndef.Record(data='\x16\x01\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_04():
    nfc.ndef.Record(data='\x11\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_05():
    nfc.ndef.Record(data='\x12\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_06():
    nfc.ndef.Record(data='\x13\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_07():
    nfc.ndef.Record(data='\x14\x00\x00')

@raises(nfc.ndef.FormatError)
def test_decode_invalid_format_08():
    nfc.ndef.Record(data='\x10\x00\x01\x00')

#------------------------------------------------------------------- RecordList

def test_bv_record_list_init():
    rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])

@raises(TypeError)
def test_bi_record_list_init():
    rl = nfc.ndef.record.RecordList(["invalid"])

def test_bv_record_list_append():
    rl = nfc.ndef.record.RecordList()
    rl.append(nfc.ndef.Record())
    assert len(rl) == 1

@raises(TypeError)
def test_bi_record_list_append():
    rl = nfc.ndef.record.RecordList()
    rl.append("invalid")

def test_bv_record_list_extend():
    rl = nfc.ndef.record.RecordList()
    rl.extend([nfc.ndef.Record(), nfc.ndef.Record()])
    assert len(rl) == 2

@raises(TypeError)
def test_bi_record_list_extend():
    rl = nfc.ndef.record.RecordList()
    rl.extend(["invalid", "invalid"])

def test_bv_record_list_setitem():
    rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])
    rl[0] = nfc.ndef.Record()
    assert len(rl) == 1

@raises(TypeError)
def test_bi_record_list_setitem():
    rl = nfc.ndef.record.RecordList([nfc.ndef.Record()])
    rl[0] = "invalid"

