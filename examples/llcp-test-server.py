#!/usr/bin/python
# -*- coding: latin-1 -*-
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

import os
import sys
import time
import Queue as queue
from threading import Thread

import logging
log = logging.getLogger()

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.llcp

class ConnectionLessEchoServer(Thread):
    def __init__(self):
        super(ConnectionLessEchoServer, self).__init__()
        self.name = "ConnectionLessEchoServerThread"
        self.daemon = True

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.LOGICAL_DATA_LINK)
        try:
            nfc.llcp.bind(socket, 'urn:nfc:sn:cl-echo')
            log.info("connectionless server bound to port 63")
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
                log.info("connectionless server recv queue size is 2")
            else: log.error("could not set socket receive buffer size")
            while nfc.llcp.poll(socket, "recv"):
                log.info("data available, start delay time")
                time.sleep(2.0)
                while nfc.llcp.poll(socket, "recv", timeout=0):
                    data, addr = nfc.llcp.recvfrom(socket)
                    #if data and addr:
                    nfc.llcp.sendto(socket, data, addr)
                else: log.info("no more data, start waiting")
            else: log.info("remote side closed logical data link")
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            log.info("close connless echo server socket")
            nfc.llcp.close(socket)

class ConnectionModeEchoServer(Thread):
    def __init__(self):
        super(ConnectionModeEchoServer, self).__init__()
        self.name = "ConnectionModeEchoServerThread"
        self.daemon = True

    def echo(self, socket, echo_queue):
        peer = nfc.llcp.getpeername(socket)
        while True:
            data = echo_queue.get()
            if data == 0:
                log.info("echo thread got quit event")
                return
            if data != None:
                log.info("data available, wait 2 seconds")
                time.sleep(2.0)
            while data != None:
                try:
                    if nfc.llcp.send(socket, data):
                        log.info("sent {0} byte to sap {1}"
                                 .format(len(data), peer))
                except nfc.llcp.Error:
                    log.info("failed to send data")
                    try: echo_queue.get_nowait()
                    except queue.Empty: pass
                    return
                try: data = echo_queue.get_nowait()
                except queue.Empty: data = None
                if data == 0:
                    log.info("echo thread got quit event")
                    return
                if data != None:
                    log.info("more data available")

    def serve(self, socket):
        echo_queue = queue.Queue(2)
        echo_thread = Thread(target=self.echo, args=[socket, echo_queue])
        echo_thread.start()
        peer = nfc.llcp.getpeername(socket)
        log.info("serving connection from sap {0}".format(peer))
        while nfc.llcp.poll(socket, "recv"):
            data = nfc.llcp.recv(socket)
            if data == None: break
            log.info("rcvd {0} byte from sap {1}".format(len(data), peer))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBSY, echo_queue.full())
            echo_queue.put(data)
        try: echo_queue.put_nowait(int(0))
        except queue.Full: pass
        echo_thread.join()
        nfc.llcp.close(socket)
        log.info("serve thread terminated")

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, 'urn:nfc:sn:co-echo')
            addr = nfc.llcp.getsockname(socket)
            log.info("connectionmode server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
                log.info("connectionmode server recv window is 2")
            else: log.error("could not set socket recv window size")
            nfc.llcp.listen(socket, backlog=0)
            while True:
                client = nfc.llcp.accept(socket)
                peer = nfc.llcp.getpeername(client)
                log.info("client sap {0} connected".format(peer))
                self.serve(client)
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            nfc.llcp.close(socket)

class ConnectionModeDumpServer(Thread):
    def __init__(self):
        super(ConnectionModeEchoServer, self).__init__()
        self.name = "ConnectionModeEchoDumpThread"
        self.daemon = True

    def serve(self, socket):
        peer = nfc.llcp.getpeername(socket)
        log.info("serving connection from sap {0}".format(peer))
        while nfc.llcp.poll(socket, "recv"):
            data = nfc.llcp.recv(socket)
            if data == None: break
            log.info("dump: rcvd {0} byte from sap {1}"
                     .format(len(data), peer))
        nfc.llcp.close(socket)
        log.info("server thread terminated")

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, 'urn:nfc:sn:cm-dump')
            addr = nfc.llcp.getsockname(socket)
            log.info("connectionmode server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            if nfc.llcp.getsockopt(socket, nfc.llcp.SO_RCVBUF) == 2:
                log.info("connectionmode server recv window is 2")
            else: log.error("could not set socket recv window size")
            nfc.llcp.listen(socket, backlog=4)
            while True:
                client = nfc.llcp.accept(socket)
                peer = nfc.llcp.getpeername(client)
                log.info("client sap {0} connected".format(peer))
                Thread(target=self.serve, args=[client]).start()
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            nfc.llcp.close(socket)

def main():
    general_bytes = nfc.llcp.startup(lto=1000, miu=options.link_miu)
    clf = nfc.ContactlessFrontend(options.device)

    peer = None
    try:
        while True:
            if options.mode == "target" or options.mode is None:
                listen_time = 250 + ord(os.urandom(1))
                peer = clf.listen(listen_time, general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        break
            if options.mode == "initiator" or options.mode is None:
                peer = clf.poll(general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        break
                time.sleep(1)
    except KeyboardInterrupt:
        log.info("aborted by user")
        return

    nfc.llcp.activate(peer)
    try:
        cl_echo_server = ConnectionLessEchoServer()
        cm_echo_server = ConnectionModeEchoServer()
        cl_echo_server.start()
        cm_echo_server.start()
        cl_echo_server.join()
        cm_echo_server.join()
        nfc.llcp.deactivate()
    except KeyboardInterrupt:
        log.info("aborted by user")
    finally:
        nfc.llcp.shutdown()
        log.info("I was the " + peer.role)


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
    parser.add_option("--link-miu", type="int", default=128,
                      action="store", dest="link_miu", metavar="MIU",
                      help="set maximum information unit size to MIU")
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
