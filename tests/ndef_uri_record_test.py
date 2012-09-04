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
    record = nfc.ndef.UriRecord()
    assert record.uri == ''
    
def test_init_args_uri():
    record = nfc.ndef.UriRecord("http://nfcpy.org")
    assert record.uri == "http://nfcpy.org"
    
def test_init_kwargs_uri():
    record = nfc.ndef.UriRecord(uri="http://nfcpy.org")
    assert record.uri == "http://nfcpy.org"
    
