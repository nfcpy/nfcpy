#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
log = logging.getLogger()

import os
import sys
import time
import argparse

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.snep
import nfc.ndef

class DefaultServer(nfc.snep.SnepServer):
    def __init__(self, llc):
        service_name = 'urn:nfc:sn:snep'
        super(DefaultServer, self).__init__(llc, service_name)

    def put(self, ndef_message):
        log.info("default snep server got put request")
        log.info("ndef message length is {0} octets".format(len(ndef_message)))
        log.info(nfc.ndef.Message(ndef_message).pretty())
        return nfc.snep.Success

class ValidationServer(nfc.snep.SnepServer):
    def __init__(self, llc):
        service_name = "urn:nfc:xsn:nfc-forum.org:snep-validation"
        super(ValidationServer, self).__init__(llc, service_name, 10000)
        self.ndef_message_store = dict()

    def put(self, ndef_message):
        log.info("validation snep server got put request")
        ndef_message = nfc.ndef.Message(ndef_message)
        key = (ndef_message.type, ndef_message.name)
        log.info("store ndef message under key " + str(key))
        self.ndef_message_store[key] = ndef_message
        return nfc.snep.Success

    def get(self, acceptable_length, ndef_message):
        log.info("validation snep server got get request")
        ndef_message = nfc.ndef.Message(ndef_message)
        key = (ndef_message.type, ndef_message.name)
        log.info("client requests ndef message with key " + str(key))
        if key in self.ndef_message_store:
            ndef_message = str(self.ndef_message_store[key])
            info = "found matching ndef message, total length is {0} octets"
            log.info(info.format(len(ndef_message)))
            if len(ndef_message) <= acceptable_length:
                return ndef_message
            else: return nfc.snep.ExcessData
        return nfc.snep.NotFound

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        super(TestProgram, self).__init__(parser, groups="dbg p2p clf")

    def on_startup(self, llc):
        self.default_snep_server = DefaultServer(llc)
        self.validation_snep_server = ValidationServer(llc)
        return True
        
    def on_connect(self, llc):
        self.default_snep_server.start()
        self.validation_snep_server.start()
        return True

if __name__ == '__main__':
    TestProgram().run()
