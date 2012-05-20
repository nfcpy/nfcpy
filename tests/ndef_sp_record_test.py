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
    record = nfc.ndef.SmartPosterRecord()
    assert record.uri == ''
    assert record.title == {}
    assert record.image == {}
    assert record.action == ''
    assert record.resource_size == 0
    assert record.resource_type == ''
    
def test_init_args_uri():
    record = nfc.ndef.SmartPosterRecord("http://nfcpy.org")
    assert record.uri == 'http://nfcpy.org'

def test_encode_uri():
    record = nfc.ndef.SmartPosterRecord("http://nfcpy.org")
    assert str(record) == '\x11\x02\x0eSp\xd1\x01\x0aU\x03nfcpy.org'

