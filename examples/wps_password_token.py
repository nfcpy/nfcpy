#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import logging
logging.basicConfig(level=logging.ERROR)

import os
import sys
import time
import string

sys.path.insert(1, os.path.split(sys.path[0])[0])

from nfc import ContactlessFrontend
from nfc.ndef import Message, Record
from nfc.ndef.WiFiSimpleConfig import WiFiPasswordData

def make_printable(data):
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += make_printable(data[i:i+16])
    return '\n'.join(s)

def write_password_token(tag):
    print
    print "Writing Wi-Fi Password Token"

    pwd = WiFiPasswordData()
    pwd.public_key_hash = 20 * '\x01'
    pwd.device_password_id = 100
    pwd.device_password = "my oob device password"
    pwd.other_attributes.append((0x1023, "VAIO X11")) # model name

    message = Message(Record(("application/vnd.wfa.wsc", "", pwd.tostring())))

    print format_data(message.tostring())
    if tag: tag.ndef.message = message.tostring()
    return

def main():
    # find and initialize NFC reader
    clf = ContactlessFrontend()

    while True:
        tag = clf.poll()

        if tag is None:
            time.sleep(0.5)
            continue

        print "found", str(tag)

        if tag.ndef is None:
            print "This tag is not NDEF compatible - try another one"
            time.sleep(0.5)
            continue

        print "NDEF container present"
        print "  version   = %s" % tag.ndef.version
        print "  writeable = %s" % ("no", "yes")[tag.ndef.writeable]
        print "  capacity  = %d byte" % tag.ndef.capacity
        print "  data size = %d byte" % len(tag.ndef.message)
        print format_data(tag.ndef.message)

        if not tag.ndef.writeable:
            print "This tag is not writable - try another one"
            time.sleep(0.5)
            continue

        write_password_token(tag)
        break

try:
    main()
except KeyboardInterrupt:
    pass

