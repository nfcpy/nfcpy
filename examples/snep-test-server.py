# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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

class DefaultServer(nfc.snep.SnepServer):
    def __init__(self):
        super(DefaultServer, self).__init__('urn:nfc:sn:snep')

    def put(self, ndef_message):
        log.info("default snep server got put request")
        print ndef_message.encode("hex")
        return nfc.snep.Success

class ValidationServer(nfc.snep.SnepServer):
    def __init__(self):
        service_name = "urn:nfc:xsn:nfc-forum.org:snep-validation"
        super(ValidationServer, self).__init__(service_name, 10000)
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
            ndef_message = self.ndef_message_store[key].tostring()
            info = "found matching ndef message, total length is {0} octets"
            log.info(info.format(len(ndef_message)))
            if len(ndef_message) <= acceptable_length:
                return ndef_message
            else: return nfc.snep.ExcessData
        return nfc.snep.NotFound

def main():
    general_bytes = nfc.llcp.startup({'send-lto': 1000, 'recv-miu': 1024})
    clf = nfc.ContactlessFrontend(options.device)

    peer = llcp_connect(clf, general_bytes)
    if peer is None: return

    nfc.llcp.activate(peer)
    try:
        default_snep_server = DefaultServer()
        default_snep_server.start()
        validation_snep_server = ValidationServer()
        validation_snep_server.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("aborted by user")
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
                      action="append", dest="device", metavar="NAME",
                      help="use this device ('ipsim' for TCP/IP simulation)")
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

    main()
