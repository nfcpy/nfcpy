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
import threading

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.npp
import nfc.ndef

def main():
    llcp_config = {'recv-miu': options.link_miu, 'send-lto': 1000}
    if options.quirks == "android":
        llcp_config['send-agf'] = False

    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return

    if not options.binary:
        data = sys.stdin.readlines()
        data = ''.join([l.strip() for l in data])
        data = data.decode("hex")
    else:
        data = sys.stdin.read()

    ndef_message = nfc.ndef.Message(data)

    try:
        while True:
            peer = llcp_connect(clf, nfc.llcp.startup(llcp_config))
            if peer is None: break

            nfc.llcp.activate(peer)
            try:
                nfc.npp.NPPClient().put(ndef_message)
                while nfc.llcp.connected():
                    time.sleep(1)
            except Exception as e:
                log.error("Exception: {0}".format(e))
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
                            time.sleep(0.15)
                        return peer
    except KeyboardInterrupt:
        log.debug("aborted by user")

if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup

    usage = "Usage: %prog [options] < message.ndef"
    parser = OptionParser(usage)
    parser.add_option("-b", default=False,
                      action="store_true", dest="binary",
                      help="read binary ndef from stdin")
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
