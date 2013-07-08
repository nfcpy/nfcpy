#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
logging.basicConfig()

import os
import sys
import time

sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc
import nfc.ndef

text_en = nfc.ndef.TextRecord(language="en", text="Hello World")
text_de = nfc.ndef.TextRecord(language="de", text="Hallo Welt")
text_fr = nfc.ndef.TextRecord(language="fr", text="Bonjour tout le monde")

class HelloWorld(object):
    def send_hello(self, tag):
        if tag.ndef:
            tag.ndef.message = nfc.ndef.Message([text_en, text_de, text_fr])
            self.sent_hello = True
        else:
            print "Not an NDEF tag"
        print "Remove the tag"
        return True
    
    def read_hello(self, tag):
        if tag.ndef:
            for record in tag.ndef.message:
                if record.type == "urn:nfc:wkt:T":
                    text = nfc.ndef.TextRecord( record )
                    print text.language + ": " + text.text
        return True
    
    def main(self):
        with nfc.ContactlessFrontend('usb') as clf:

            self.sent_hello = False

            while not self.sent_hello:
                print "Please touch a tag to send a hello to the world"
                clf.connect(rdwr={'on-connect': self.send_hello})

            print "Now touch it again to receive a hello from the world"
            clf.connect(rdwr={'on-connect': self.read_hello})

if __name__ == '__main__':
    HelloWorld().main()

