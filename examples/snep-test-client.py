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

sys.path.insert(1, os.path.split(sys.path[0])[0])
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
    
def test_01():
    #info("Test 1: connect and terminate", prefix="")
    snep = nfc.snep.SnepClient(max_ndef_msg_recv_size=1024)
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

def test_02():
    info("Test 2: unfragmented message exchange", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    payload = ''.join([chr(x) for x in range(122-29)])
    record = nfc.ndef.Record(("application/octet-stream", "1", payload))
    ndef_message_sent.append(nfc.ndef.Message(record).tostring())

    snep = nfc.snep.SnepClient(max_ndef_msg_recv_size=1024)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put short ndef message")
        snep.put(ndef_message_sent[0])

        info("get short ndef message")
        identifier = nfc.ndef.Record(("application/octet-stream", "1", ""))
        ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
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

def test_03():
    info("Test 3: fragmented message exchange", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    #payload = ''.join([chr(x%256) for x in range(2171-29)])
    payload = ''.join([chr(x%256) for x in range(512)])
    record = nfc.ndef.Record(("application/octet-stream", "1", payload))
    ndef_message_sent.append(nfc.ndef.Message(record).tostring())

    snep = nfc.snep.SnepClient(max_ndef_msg_recv_size=10000)
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put large ndef message")
        snep.put(ndef_message_sent[0])
    
        info("get large ndef message")
        identifier = nfc.ndef.Record(("application/octet-stream", "1", ""))
        ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
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

def test_04():
    info("Test 4: multiple ndef messages", prefix="")
    ndef_message_sent = list()
    ndef_message_rcvd = list()

    payload = ''.join([chr(x%256) for x in range(50)])
    record = nfc.ndef.Record(("application/octet-stream", "1", payload))
    ndef_message_sent.append(nfc.ndef.Message(record).tostring())
    record = nfc.ndef.Record(("application/octet-stream", "2", payload))
    ndef_message_sent.append(nfc.ndef.Message(record).tostring())

    snep = nfc.snep.SnepClient(max_ndef_msg_recv_size=10000)    
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
        identifier = nfc.ndef.Record(("application/octet-stream", "1", ""))
        ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
        ndef_message_rcvd.append(ndef_message)

        info("get 2nd ndef message")
        identifier = nfc.ndef.Record(("application/octet-stream", "2", ""))
        ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
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

def test_05():
    info("Test 5: undeliverable resource", prefix="")

    payload = ''.join([chr(x) for x in range(122-29)])
    record = nfc.ndef.Record(("application/octet-stream", "1", payload))
    ndef_message_sent = nfc.ndef.Message(record).tostring()

    max_ndef_msg_recv_size = len(ndef_message_sent) - 1
    snep = nfc.snep.SnepClient(max_ndef_msg_recv_size)
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
        identifier = nfc.ndef.Record(("application/octet-stream", "1", ""))
        try:
            ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
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

def test_06():
    info("Test 6: unavailable resource", prefix="")

    snep = nfc.snep.SnepClient()
    try:
        info("connect to {0}".format(validation_server))
        snep.connect(validation_server)
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        identifier = nfc.ndef.Record(("application/octet-stream", "0", ""))
        info("request ndef message " + str(identifier))
        try:
            ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
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

def test_07():
    info("Test 7: default server limits", prefix="")

    payload = ''.join([chr(x%256) for x in range(1024-32)])
    record = nfc.ndef.Record(("application/octet-stream", "1", payload))
    ndef_message = nfc.ndef.Message(record).tostring()
    
    snep = nfc.snep.SnepClient()
    try:
        info("connect to {0}".format("urn:nfc:sn:snep"))
        snep.connect("urn:nfc:sn:snep")
    except nfc.llcp.ConnectRefused:
        raise TestError("could not connect to validation server")

    try:
        info("put {0} octets ndef message".format(len(ndef_message)))
        snep.put(ndef_message)

        identifier = nfc.ndef.Record(("application/octet-stream", "1", ""))
        info("request ndef message " + str(identifier))
        try:
            ndef_message = snep.get(nfc.ndef.Message(identifier).tostring())
        except nfc.snep.SnepError as e:
            if e.errno == nfc.snep.NotImplemented: return # PASS
            raise TestError("received unexpected response code")
        else:
            raise TestError("received unexpected message from server")
    except Exception:
        raise
    finally:
        snep.close()

def main():
    general_bytes = nfc.llcp.startup({'send-lto': 1000, 'recv-miu': 1024})
    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return

    peer = llcp_connect(clf, general_bytes)
    if peer is None: return

    nfc.llcp.activate(peer)
    time.sleep(0.5)

    if not options.run_test:
        log.info("no test specified")

    test_suite = [test_01, test_02, test_03, test_04,
                  test_05, test_06, test_07]
    
    try:
        for test in options.run_test:
            if test > 0 and test <= len(test_suite):
                try:
                    test_suite[test-1]()
                    log.info("PASS")
                except TestError as error:
                    log.error("FAIL: {0}".format(error))
            else:
                log.info("invalid test number '{0}'".format(test))
    except KeyboardInterrupt:
        log.info("aborted by user")
        for thread in threading.enumerate():
            log.info(thread.name)
    finally:
        nfc.llcp.shutdown()
        log.info("I was the " + peer.role)

def llcp_connect(clf, general_bytes):
    try:
        while True:
            if options.mode == "target" or options.mode is None:
                listen_time = 250 + ord(os.urandom(1))
                peer = clf.listen(listen_time, general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        return peer
            if options.mode == "initiator" or options.mode is None:
                peer = clf.poll(general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        return peer
    except KeyboardInterrupt:
        log.info("aborted by user")

if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup
    parser = OptionParser()
    parser.add_option("-t", "--test", type="int", default=[],
                      action="append", dest="run_test", metavar="N",
                      help="run test number <N>")
    parser.add_option("-q", default=True,
                      action="store_false", dest="verbose",
                      help="be quiet, only print errors")
    parser.add_option("-d", type="string", default=[],
                      action="append", dest="debug", metavar="MODULE",
                      help="print debug messages for MODULE")
    parser.add_option("-f", type="string",
                      action="store", dest="logfile",
                      help="write log messages to LOGFILE")
    parser.add_option("--device", type="string", default=[],
                      action="append", dest="device", metavar="SPEC",
                      help="use only device(s) according to SPEC: "\
                          "usb[:vendor[:product]] (vendor and product in hex) "\
                          "usb[:bus[:dev]] (bus and device number in decimal) "\
                          "tty[:(usb|com)[:port]] (usb virtual or com port)")
    parser.add_option("--mode", type="choice", default=None,
                      choices=["target", "initiator"],
                      action="store", dest="mode",
                      help="restrict mode to 'target' or 'initiator'")

    global options
    options, args = parser.parse_args()

    verbosity = logging.INFO if options.verbose else logging.ERROR
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    import inspect, os, os.path
    nfcpy_path = os.path.dirname(inspect.getfile(nfc))
    for name in os.listdir(nfcpy_path):
        if os.path.isdir(os.path.join(nfcpy_path, name)):
            logging.getLogger("nfc."+name).setLevel(verbosity)
        elif name.endswith(".py") and name != "__init__.py":
            logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)
            
    if options.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.getLogger('nfc').setLevel(logging.DEBUG)
        for module in options.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)

    if len(options.device) == 0:
        # search and use first
        options.device = ["",]
        
    main()
