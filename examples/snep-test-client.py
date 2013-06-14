#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import threading

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.snep
import nfc.ndef

validation_server = "urn:nfc:xsn:nfc-forum.org:snep-validation"

class TestError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return str(self.value)

def info(message, prefix="   "):
    log.info(prefix + message)
    
def test_01(llc):
    info("Test 1: connect and terminate", prefix="")
    snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=1024)
    try:
        info("1st connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")
    else:
        info("disconnect from {0}".format(validation_server))
        snep.close()
    try:
        info("2nd connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")
    else:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_02(llc):
    info("Test 2: unfragmented message exchange", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    payload = ''.join([chr(x) for x in range(122-29)])
    record = nfc.ndef.Record("application/octet-stream", "1", payload)
    ndef_message_sent.append(str(nfc.ndef.Message(record)))

    snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=1024)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put short ndef message")
        snep.put(ndef_message_sent[0])

        info("get short ndef message")
        identifier = nfc.ndef.Record("application/octet-stream", "1", "")
        ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        ndef_message_rcvd.append(ndef_message)

        for i in range(len(ndef_message_sent)):
            if not ndef_message_rcvd == ndef_message_sent:
                raise TestError("rcvd ndef message {0} differs".format(i))
            else:
                info("rcvd ndef message {0} is correct".format(i))
    except Exception as e:
        TestError("exception: " + str(e))
    finally:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_03(llc):
    info("Test 3: fragmented message exchange", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    #payload = ''.join([chr(x%256) for x in range(2171-29)])
    payload = ''.join([chr(x%256) for x in range(512)])
    record = nfc.ndef.Record("application/octet-stream", "1", payload)
    ndef_message_sent.append(str(nfc.ndef.Message(record)))

    snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=10000)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put large ndef message")
        snep.put(ndef_message_sent[0])
    
        info("get large ndef message")
        identifier = nfc.ndef.Record("application/octet-stream", "1", "")
        ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        ndef_message_rcvd.append(ndef_message)

        for i in range(len(ndef_message_sent)):
            if not ndef_message_rcvd == ndef_message_sent:
                info("rcvd ndef message {0} differs".format(i))
                raise TestError("rcvd ndef message {0} differs".format(i))
            else:
                info("rcvd ndef message {0} is correct".format(i))
    except Exception as e:
        raise TestError("exception " + str(e))
    finally:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_04(llc):
    info("Test 4: multiple ndef messages", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    payload = ''.join([chr(x%256) for x in range(50)])
    record = nfc.ndef.Record("application/octet-stream", "1", payload)
    ndef_message_sent.append(str(nfc.ndef.Message(record)))
    record = nfc.ndef.Record("application/octet-stream", "2", payload)
    ndef_message_sent.append(str(nfc.ndef.Message(record)))

    snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size=10000)    
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put 1st ndef message")
        snep.put(ndef_message_sent[0])

        info("put 2nd ndef message")
        snep.put(ndef_message_sent[1])
    
        info("get 1st ndef message")
        identifier = nfc.ndef.Record("application/octet-stream", "1", "")
        ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        ndef_message_rcvd.append(ndef_message)

        info("get 2nd ndef message")
        identifier = nfc.ndef.Record("application/octet-stream", "2", "")
        ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        ndef_message_rcvd.append(ndef_message)

        for i in range(len(ndef_message_sent)):
            if not ndef_message_rcvd == ndef_message_sent:
                info("rcvd ndef message {0} differs".format(i))
                raise TestError("rcvd ndef message {0} differs".format(i))
            else:
                info("rcvd ndef message {0} is correct".format(i))
    except Exception as e:
        raise TestError("exception " + str(e))
    finally:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_05(llc):
    info("Test 5: undeliverable resource", prefix="")

    payload = ''.join([chr(x) for x in range(122-29)])
    record = nfc.ndef.Record("application/octet-stream", "1", payload)
    ndef_message_sent = str(nfc.ndef.Message(record))

    max_ndef_msg_recv_size = len(ndef_message_sent) - 1
    snep = nfc.snep.SnepClient(llc, max_ndef_msg_recv_size)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put {0} octets ndef message".format(len(ndef_message_sent)))
        snep.put(ndef_message_sent)

        info("request ndef message back with max acceptable lenght of " +
             str(max_ndef_msg_recv_size))
        identifier = nfc.ndef.Record("application/octet-stream", "1", "")
        try:
            ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        except nfc.snep.SnepError as e:
            if e.errno == nfc.snep.ExcessData: return # PASS
            raise TestError("received unexpected response code")
        else:
            raise TestError("received unexpected message from server")
    except Exception:
        raise
    finally:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_06(llc):
    info("Test 6: unavailable resource", prefix="")

    snep = nfc.snep.SnepClient(llc)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        identifier = nfc.ndef.Record("application/octet-stream", "0", "")
        info("request ndef message " + str(identifier))
        try:
            ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        except nfc.snep.SnepError as e:
            if e.errno == nfc.snep.NotFound: return # PASS
            raise TestError("received unexpected response code")
        else:
            raise TestError("received unexpected message from server")
    except Exception:
        raise
    finally:
        info("disconnect from {0}".format(validation_server))
        snep.close()

def test_07(llc):
    info("Test 7: default server limits", prefix="")

    payload = ''.join([chr(x%256) for x in range(1024-32)])
    record = nfc.ndef.Record("application/octet-stream", "1", payload)
    ndef_message = str(nfc.ndef.Message(record))
    
    snep = nfc.snep.SnepClient(llc)
    try:
        info("connect to {0}".format("urn:nfc:sn:snep"))
        snep.connect("urn:nfc:sn:snep")
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put {0} octets ndef message".format(len(ndef_message)))
        snep.put(ndef_message)

        identifier = nfc.ndef.Record("application/octet-stream", "1", "")
        info("request ndef message " + str(identifier))
        try:
            ndef_message = snep.get(str(nfc.ndef.Message(identifier)))
        except nfc.snep.SnepError as e:
            if e.errno == nfc.snep.NotImplemented: return # PASS
            raise TestError("received unexpected response code")
        else:
            raise TestError("received unexpected message from server")
    except Exception:
        raise
    finally:
        snep.close()

class TestRunner(threading.Thread):
    def __init__(self, llc, options):
        super(TestRunner, self).__init__(name="TestRunner")
        self.options = options
        self.llc = llc
    
    def run():
        for test in self.options.test:
            try:
                eval("test_{N:02d}".format(N=test))(self.llc)
                info("Test {N:02d}: PASS".format(N=test))
            except NameError:
                info("invalid test number '{0}'".format(test))
            except TestError as error:
                info("Test {N:02d}: FAIL ({E})".format(N=test, E=error))

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-t", "--test", type=int, default=[], action="append",
            metavar="N", help="run test number <N>")
        super(TestProgram, self).__init__(parser, groups="dbg p2p clf")

    def on_startup(self, llc):
        if len(options.test) == 0:
            info("no test specified")
            return False
        else:
            self.test_runner = TestRunner()
            return True
        
    def on_connect(self, llc):
        self.test_runner.start()
        return True

if __name__ == '__main__':
    TestProgram().run()
