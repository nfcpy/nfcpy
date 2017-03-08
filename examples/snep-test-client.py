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

import logging
log = logging.getLogger('main')

import time
import argparse
from threading import Thread

from cli import CommandLineInterface, TestFail

import nfc
import nfc.snep
import nfc.ndef

validation_server = "urn:nfc:xsn:nfc-forum.org:snep-validation"

def info(message, prefix="  "):
    log.info(prefix + message)

description = """
Execute some Simple NDEF Exchange Protocol (SNEP) tests. The peer
device must have the SNEP validation test servers running.
"""
class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=description)
        super(TestProgram, self).__init__(
            parser, groups="test llcp dbg clf")

    def test_00(self, llc):
        """Read NDEF data to send from file 'beam.ndef'"""
        
        try:
            data = open("beam.ndef", "rb").read()
        except IOError:
            return
        ndef = nfc.ndef.Message(data)

        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=1024)
        snep.put(ndef)
        snep.close()

    def test_01(self, llc):
        """Connect and terminate"""
        
        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=1024)
        try:
            info("1st connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")
        else:
            info("disconnect from {0}".format(validation_server))
            snep.close()
        try:
            info("2nd connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")
        else:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_02(self, llc):
        """Unfragmented message exchange"""
        
        ndef_message_sent = list()
        ndef_message_rcvd = list()

        payload = ''.join([chr(x) for x in range(122-29)])
        record = nfc.ndef.Record("application/octet-stream", "1", payload)
        ndef_message_sent.append(nfc.ndef.Message(record))

        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=1024)
        try:
            info("connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")

        try:
            info("put short ndef message")
            snep.put(ndef_message_sent[0])

            info("get short ndef message")
            identifier = nfc.ndef.Record("application/octet-stream", "1", "")
            ndef_message = snep.get(nfc.ndef.Message(identifier))
            ndef_message_rcvd.append(ndef_message)

            for i in range(len(ndef_message_sent)):
                if not ndef_message_rcvd == ndef_message_sent:
                    raise TestFail("rcvd ndef message {0} differs".format(i))
                else:
                    info("rcvd ndef message {0} is correct".format(i))
        except Exception as e:
            raise TestFail("exception: " + str(e))
        finally:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_03(self, llc):
        """Fragmented message exchange"""
        
        ndef_message_sent = list()
        ndef_message_rcvd = list()

        payload = ''.join([chr(x%256) for x in range(2171-29)])
        record = nfc.ndef.Record("application/octet-stream", "1", payload)
        ndef_message_sent.append(nfc.ndef.Message(record))

        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=10000)
        try:
            info("connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")

        try:
            info("put large ndef message")
            snep.put(ndef_message_sent[0])

            info("get large ndef message")
            identifier = nfc.ndef.Record("application/octet-stream", "1", "")
            ndef_message = snep.get(nfc.ndef.Message(identifier))
            ndef_message_rcvd.append(ndef_message)

            for i in range(len(ndef_message_sent)):
                if not ndef_message_rcvd == ndef_message_sent:
                    info("rcvd ndef message {0} differs".format(i))
                    raise TestFail("rcvd ndef message {0} differs".format(i))
                else:
                    info("rcvd ndef message {0} is correct".format(i))
        except Exception as e:
            raise TestFail("exception " + str(e))
        finally:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_04(self, llc):
        """Multiple ndef messages"""
        
        ndef_message_sent = list()
        ndef_message_rcvd = list()

        payload = ''.join([chr(x%256) for x in range(50)])
        record = nfc.ndef.Record("application/octet-stream", "1", payload)
        ndef_message_sent.append(nfc.ndef.Message(record))
        record = nfc.ndef.Record("application/octet-stream", "2", payload)
        ndef_message_sent.append(nfc.ndef.Message(record))

        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=10000)    
        try:
            info("connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")

        try:
            info("put 1st ndef message")
            snep.put(ndef_message_sent[0])

            info("put 2nd ndef message")
            snep.put(ndef_message_sent[1])

            info("get 1st ndef message")
            identifier = nfc.ndef.Record("application/octet-stream", "1", "")
            ndef_message = snep.get(nfc.ndef.Message(identifier))
            ndef_message_rcvd.append(ndef_message)

            info("get 2nd ndef message")
            identifier = nfc.ndef.Record("application/octet-stream", "2", "")
            ndef_message = snep.get(nfc.ndef.Message(identifier))
            ndef_message_rcvd.append(ndef_message)

            for i in range(len(ndef_message_sent)):
                if not ndef_message_rcvd == ndef_message_sent:
                    info("rcvd ndef message {0} differs".format(i))
                    raise TestFail("rcvd ndef message {0} differs".format(i))
                else:
                    info("rcvd ndef message {0} is correct".format(i))
        except Exception as e:
            raise TestFail("exception " + str(e))
        finally:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_05(self, llc):
        """Undeliverable resource"""

        payload = ''.join([chr(x) for x in range(122-29)])
        record = nfc.ndef.Record("application/octet-stream", "1", payload)
        ndef_message_sent = nfc.ndef.Message(record)

        max_ndef_msg_recv_size = len(str(ndef_message_sent)) - 1
        snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size)
        try:
            info("connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")

        try:
            info("put {0} octets ndef message".format(
                    len(str(ndef_message_sent))))
            snep.put(ndef_message_sent)

            info("request ndef message back with max acceptable lenght " +
                 str(max_ndef_msg_recv_size))
            identifier = nfc.ndef.Record("application/octet-stream", "1", "")
            try:
                ndef_message = snep.get(nfc.ndef.Message(identifier))
            except nfc.snep.SnepError as e:
                if e.errno != nfc.snep.ExcessData:
                    raise TestFail("received unexpected response code")
                info("received 'excess data' response as expected")
            else:
                raise TestFail("received unexpected message from server")
        finally:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_06(self, llc):
        """Unavailable resource"""

        snep = nfc.snep.SnepClient(llc)
        try:
            info("connect to {0}".format(validation_server))
            snep.connect(validation_server)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to validation server")

        try:
            identifier = nfc.ndef.Record("application/octet-stream", "0", "")
            info("request ndef message " + repr(identifier))
            try:
                ndef_message = snep.get(nfc.ndef.Message(identifier))
            except nfc.snep.SnepError as e:
                if e.errno != nfc.snep.NotFound:
                    raise TestFail("received unexpected response code")
                info("received 'not found' response as expected")
            else:
                raise TestFail("received unexpected message from server")
        finally:
            info("disconnect from {0}".format(validation_server))
            snep.close()

    def test_07(self, llc):
        """Default server limits"""

        payload = ''.join([chr(x%256) for x in range(1024-32)])
        record = nfc.ndef.Record("application/octet-stream", "1", payload)
        ndef_message = nfc.ndef.Message(record)

        snep = nfc.snep.SnepClient(llc)
        try:
            info("connect to {0}".format("urn:nfc:sn:snep"))
            snep.connect("urn:nfc:sn:snep")
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to default server")

        try:
            info("put {0} octets ndef message".format(len(str(ndef_message))))
            snep.put(ndef_message)

            identifier = nfc.ndef.Record("application/octet-stream", "1", "")
            info("request ndef message " + repr(identifier))
            try:
                ndef_message = snep.get(nfc.ndef.Message(identifier))
            except nfc.snep.SnepError as e:
                if e.errno != nfc.snep.NotImplemented:
                    raise TestFail("received unexpected response code")
                info("received 'not implemented' response as expected")
            else:
                raise TestFail("received unexpected message from server")
        finally:
            info("disconnect from server")
            snep.close()

if __name__ == '__main__':
    TestProgram().run()
