#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011,2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

text_en = nfc.ndef.TextRecord(language="en", text="Hello World")
text_de = nfc.ndef.TextRecord(language="de", text="Hallo Welt")
text_fr = nfc.ndef.TextRecord(language="fr", text="Bonjour tout le monde")
    
def main():
    def send_hello(tag):
        if tag.ndef:
            tag.ndef.message = nfc.ndef.Message([text_en, text_de, text_fr])
            print "Remove this tag"
        else:
            print "Not an NDEF tag"
        return True
    
    def read_hello(tag):
        if tag.ndef:
            for record in tag.ndef.message:
                if record.type == "urn:nfc:wkt:T":
                    text = nfc.ndef.TextRecord( record )
                    print text.language + ": " + text.text
        return True
    
    clf = nfc.ContactlessFrontend()

    print "Please touch a tag to send a hello to the world"
    clf.connect(rdwr={'on-connect': send_hello})
    
    print "Now touch it again to receive a hello from the world"
    clf.connect(rdwr={'on-connect': read_hello})

if __name__ == '__main__':
    main()

