#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import argparse
import logging
import nfc
import cli


log = logging.getLogger('main')


class DefaultServer(nfc.snep.SnepServer):
    def __init__(self, llc):
        service_name = 'urn:nfc:sn:snep'
        super(DefaultServer, self).__init__(llc, service_name)

    def process_put_request(self, ndef_message):
        log.info("default snep server got put request")
        for record in ndef_message:
            log.info("  {} ".format(record))
        return nfc.snep.Success


class ValidationServer(nfc.snep.SnepServer):
    def __init__(self, llc):
        service_name = "urn:nfc:xsn:nfc-forum.org:snep-validation"
        super(ValidationServer, self).__init__(llc, service_name, 10000)
        self.ndef_message_store = dict()

    def process_put_request(self, ndef_message):
        log.info("validation snep server got put request")
        for record in ndef_message:
            log.info("  {} ".format(record))
        key = (ndef_message[0].type, ndef_message[0].name)
        log.info("store ndef message under key {}".format(key))
        self.ndef_message_store[key] = ndef_message
        return nfc.snep.Success

    def process_get_request(self, ndef_message):
        log.info("validation snep server got get request")
        for record in ndef_message:
            log.info("  {} ".format(record))

        key = (ndef_message[0].type, ndef_message[0].name)
        log.info("client requests ndef message with key {}".format(key))

        if key not in self.ndef_message_store:
            return nfc.snep.NotFound

        ndef_message = self.ndef_message_store[key]
        log.info("found matching ndef message")
        for record in ndef_message:
            log.info("  {} ".format(record))

        return ndef_message


class TestProgram(cli.CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        super(TestProgram, self).__init__(parser, groups="llcp dbg clf")
        self.default_snep_server = None
        self.validation_snep_server = None

    def on_llcp_startup(self, llc):
        self.default_snep_server = DefaultServer(llc)
        self.validation_snep_server = ValidationServer(llc)
        return llc

    def on_llcp_connect(self, llc):
        self.default_snep_server.start()
        self.validation_snep_server.start()
        return True


if __name__ == '__main__':
    TestProgram().run()
