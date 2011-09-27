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

import logging
log = logging.getLogger()

import os
import sys
import time
import string
import threading

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.npp
import nfc.ndef

terminate = threading.Event()

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

class NdefPushServer(nfc.npp.NPPServer):
    def __init__(self):
        super(NdefPushServer, self).__init__()

    def process(self, ndef_message_data):
        log.info("ndef push server got message")
        if options.binary:
            sys.stdout.write(ndef_message_data)
            sys.stdout.flush()
        else:
            print ndef_message_data.encode("hex")
        log.info(format_data(ndef_message_data))
        ndef_message = nfc.ndef.Message(ndef_message_data)
        log.info("NDEF records:")
        for index, record in enumerate(ndef_message):
            record_type = record.type
            record_name = record.name
            record_data = make_printable(record.data)
            log.info("  [%d] type = %s" %(index, record_type))
            log.info("  [%d] name = %s" %(index, record_name))
            log.info("  [%d] data = %s" %(index, record_data))

        # echo part - send back the ndef message
        log.info("sending back this same message")
        try:
            nfc.npp.NPPClient().put(ndef_message)
        except Exception as e:
            log.error("Exception: {0}".format(e))
            
        if options.onemessage is True:
            terminate.set()

def main():
    llcp_config = {'recv-miu': options.link_miu, 'send-lto': 1000}
    if options.quirks == "android":
        llcp_config['send-agf'] = False

    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return

    try:
        while True:
            general_bytes = nfc.llcp.startup(llcp_config)
            peer = llcp_connect(clf, general_bytes)
            if peer is None: break

            nfc.llcp.activate(peer)
            try:
                ndef_push_server = NdefPushServer()
                ndef_push_server.start()
                while nfc.llcp.connected() and not terminate.is_set():
                    terminate.wait(1)
            except KeyboardInterrupt:
                log.info("aborted by user")
                break
            finally:
                nfc.llcp.shutdown()
                log.info("I was the " + peer.role)
                if options.loopmode is False:
                    break
    finally:
        clf.close()

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
                        if options.quirks == "android":
                            # Google Nexus S does not receive the first
                            # packet if we send immediately.
                            time.sleep(0.1)
                        return peer
    except KeyboardInterrupt:
        log.info("aborted by user")

if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup
    usage = "Usage: %prog [options] > message.ndef"
    parser = OptionParser(usage)
    parser.add_option("-b", default=False,
                      action="store_true", dest="binary",
                      help="write binary ndef to stdout")
    parser.add_option("-1", default=False,
                      action="store_true", dest="onemessage",
                      help="terminate when an ndef message arrived")
    parser.add_option("-l", default=False,
                      action="store_true", dest="loopmode",
                      help="run in endless loop (Ctrl-C to abort)")
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
    parser.add_option("--link-miu", type="int", default=1024,
                      action="store", dest="link_miu", metavar="MIU",
                      help="set maximum information unit size to MIU")
    parser.add_option("--quirks", type="string",
                      action="store", dest="quirks", metavar="choice",
                      help="quirks mode, choices are 'android'")

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
