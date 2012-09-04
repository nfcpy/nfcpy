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

def test_init_args_none():
    record = nfc.ndef.SmartPosterRecord('')
    assert record.uri == ''
    assert record.title == {}
    assert record.icons == {}
    assert record.action == 'default'
    assert record.resource_size == None
    assert record.resource_type == None
    
def test_init_args_uri():
    record = nfc.ndef.SmartPosterRecord("http://nfcpy.org")
    assert record.uri == 'http://nfcpy.org'

def test_encode_uri():
    record = nfc.ndef.SmartPosterRecord("http://nfcpy.org")
    assert str(record) == '\x11\x02\x0eSp\xd1\x01\x0aU\x03nfcpy.org'

def test_bv_attr_title():
    record = nfc.ndef.SmartPosterRecord('')
    record.title = "English"
    assert record.title["en"] == "English"
    record.title["de"] = "Deutsch"
    assert record.title == {"en": "English", "de": "Deutsch"}
    record.title = {"en": "English"}
    print record.title
    assert record.title == {"en": "English"}

def test_bv_attr_icons():
    record = nfc.ndef.SmartPosterRecord('')
    record.icons["jpeg"] = "\x00\x01"
    assert record.icons["jpeg"] == "\x00\x01"

@raises(TypeError)
def test_bi_attr_icons_set_wrong_type():
    record = nfc.ndef.SmartPosterRecord('')
    record.icons = "wrong"

def test_bv_attr_action():
    record = nfc.ndef.SmartPosterRecord('')
    record.action = "exec"
    assert record.action == "exec"
    record.action = "save"
    assert record.action == "save"
    record.action = "edit"
    assert record.action == "edit"

@raises(ValueError)
def test_bi_attr_action_set_none():
    record = nfc.ndef.SmartPosterRecord('')
    record.action = None

@raises(ValueError)
def test_bi_attr_action_set_empty_str():
    record = nfc.ndef.SmartPosterRecord('')
    record.action = ''

@raises(ValueError)
def test_bi_attr_action_set_unknown_str():
    record = nfc.ndef.SmartPosterRecord('')
    record.action = 'unknown'

@raises(ValueError)
def test_bi_attr_action_set_non_str():
    record = nfc.ndef.SmartPosterRecord('')
    record.action = int(1)

def test_bv_attr_resource_size():
    record = nfc.ndef.SmartPosterRecord('')
    record.resource_size = 0
    assert record.resource_size == 0
    record.resource_size = 1000
    assert record.resource_size == 1000
    record.resource_size = 0xffffffff
    assert record.resource_size == 0xffffffff

@raises(ValueError)
def test_bi_attr_resource_size_negative():
    record = nfc.ndef.SmartPosterRecord('')
    record.resource_size = -1

@raises(ValueError)
def test_bi_attr_resource_size_too_large():
    record = nfc.ndef.SmartPosterRecord('')
    record.resource_size = 0x100000000

def test_bv_attr_resource_type():
    record = nfc.ndef.SmartPosterRecord('')
    record.resource_type = "text/html"
    assert record.resource_type == "text/html"

