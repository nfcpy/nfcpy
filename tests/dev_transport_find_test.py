#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import nfc.dev.transport

from nose.tools import raises
import subprocess
import re

lsusb = subprocess.check_output(['lsusb']).splitlines()
regex = re.compile(r'^Bus (.{3}) Device (.{3}): ID (.{4}):(.{4})')

def test_usb_find_path_is_empty():
    found = nfc.dev.transport.USB.find(path='')
    assert found is None
    
def test_usb_find_path_is_usb():
    found = nfc.dev.transport.USB.find(path='usb')
    assert type(found) is list
    assert len(found) == len(lsusb)
    assert len(found) > 1
    assert [(type(vid), type(pid), type(bus), type(dev))
            is (int, int, str, str)
            for vid, pid, bus, dev in found]

def test_usb_find_path_with_bus():
    devices = [regex.match(line).groups() for line in lsusb]
    bus, dev, vid, pid = devices[0]
    found = nfc.dev.transport.USB.find(path='usb:{0}'.format(bus))
    assert len(found) == len([1 for b,d,v,p in devices if b == bus])

def test_usb_find_path_with_dev():
    devices = [regex.match(line).groups() for line in lsusb]
    bus, dev, vid, pid = devices[0]
    found = nfc.dev.transport.USB.find(path='usb:{0}:{1}'.format(bus, dev))
    assert len(found) == len([1 for b,d,v,p in devices if (b,d) == (bus,dev)])

def test_usb_find_path_with_vid():
    devices = [regex.match(line).groups() for line in lsusb]
    bus, dev, vid, pid = devices[0]
    found = nfc.dev.transport.USB.find(path='usb:{0}'.format(vid))
    assert len(found) == len([1 for b,d,v,p in devices if v == vid])

def test_usb_find_path_with_pid():
    devices = [regex.match(line).groups() for line in lsusb]
    bus, dev, vid, pid = devices[0]
    found = nfc.dev.transport.USB.find(path='usb:{0}:{1}'.format(vid, pid))
    assert len(found) == len([1 for b,d,v,p in devices if (v,p) == (vid,pid)])

def test_usb_find_path_no_match():
    for path in ('usb:', 'usb:0o0', 'usb::001'):
        yield check_usb_find_path_no_match, path

def check_usb_find_path_no_match(path):
    assert nfc.dev.transport.USB.find(path) is None
