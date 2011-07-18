#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import os
import sys
import time

sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc
import nfc.ndef
import nfc.ndef.Text

def main():
    clf = nfc.ContactlessFrontend()

    print "Please touch a tag to send a hello to the world"
    while True:
        tag = clf.poll()
        if tag and tag.ndef:
            break

    text_en = nfc.ndef.Text.TextRecord( ("en", "Hello World") )
    text_de = nfc.ndef.Text.TextRecord( ("de", "Hallo Welt") )
    text_fr = nfc.ndef.Text.TextRecord( ("fr", "Bonjour tout le monde") )
    
    message = nfc.ndef.Message( [text_en, text_de, text_fr] )

    tag.ndef.message = message.tostring()
    
    print "Remove this tag"
    while tag.is_present:
        time.sleep(1)
    
    print "Now touch it again to receive a hello from the world"
    while True:
        tag = clf.poll()
        if tag and tag.ndef:
            break

    message = nfc.ndef.Message( tag.ndef.message )
    for record in message:
        if record.type == "urn:nfc:wkt:T":
            text = nfc.ndef.Text.TextRecord( record )
            print text.language + ": " + text.text

if __name__ == '__main__':
    main()

