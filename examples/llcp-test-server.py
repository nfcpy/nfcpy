#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
#
# Server side implementation of an LLCP validation suite to verify
# inter-operability of independent implementations. This suite was
# primarily developed for the purpose of validating the LLCP
# specification before final release by the NFC Forum.
#
import os
import sys
import time
import argparse
import Queue as queue
from threading import Thread

import logging
log = logging.getLogger('main')

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.llcp

class ConnectionLessEchoServer(Thread):
    """The connection-less mode echo server accepts connection-less
    transport mode PDUs. Service data units may have any size between
    zero and the maximum information unit size announced with the LLCP
    Link MIU parameter. Inbound service data units enter a linear
    buffer of service data units. The buffer has a capacity of two
    service data units. The first service data unit entering the
    buffer starts a delay timer of 2 seconds (echo delay). Expiration
    of the delay timer causes service data units in the buffer to be
    sent back to the original sender, which may be different for each
    service data unit, until the buffer is completely emptied. The
    buffer empty condition then re-enables the delay timer start event
    for the next service data unit.
    """
    def __init__(self, llc):
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket.bind('urn:nfc:sn:cl-echo')
        log.info("bound connection-less echo server to port {0}"
                 .format(socket.getsockname()))
        super(ConnectionLessEchoServer, self).__init__(
            target=self.listen, args=(socket,))
        self.name = "ConnectionLessEchoServerThread"

    def listen(self, socket):
        try:
            socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
            while socket.poll("recv"):
                log.info("data available, start delay time")
                time.sleep(2.0)
                while socket.poll("recv", timeout=0):
                    data, addr = socket.recvfrom()
                    log.info("received {0} byte from sap {1}"
                             .format(len(data), addr))
                    socket.sendto(data, addr)
                log.info("no more data, start waiting")
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            log.info("close connection-less echo server socket")
            socket.close()

class ConnectionModeEchoServer(Thread):
    """The connection-oriented mode echo server waits for a connect
    request and then accepts and processes connection-oriented
    transport mode PDUs. Further connect requests will be rejected
    until termination of the data link connection. When accepting the
    connect request, the receive window parameter is transmitted with
    a value of 2.
    
    The connection-oriented mode echo service stores inbound service
    data units in a linear buffer of service data units. The buffer
    has a capacity of three service data units. The first service data
    unit entering the buffer starts a delay timer of 2 seconds (echo
    delay). Expiration of the delay timer causes service data units in
    the buffer to be sent back to the orignal sender until the buffer
    is completely emptied. The buffer empty condition then re-enables
    the delay timer start event for the next service data unit.
    
    The echo service determines itself as busy if it is unable to
    accept further incoming service data units.
    """
    def __init__(self, llc):
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.bind('urn:nfc:sn:co-echo')
        log.info("bound connection-mode echo server to port {0}"
                 .format(socket.getsockname()))
        super(ConnectionModeEchoServer, self).__init__(
            target=self.listen, args=(socket,))
        self.name = "ConnectionModeEchoServerThread"

    def echo(self, socket, echo_queue):
        peer = socket.getpeername()
        while True:
            data = echo_queue.get()
            if data == 0:
                log.info("echo thread got quit event")
                return
            if data != None:
                log.info("data available, wait 2 seconds")
                time.sleep(2.0)
            while data != None:
                if not echo_queue.full():
                    socket.setsockopt(nfc.llcp.SO_RCVBSY, False)
                try:
                    if socket.send(data):
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
        echo_thread = Thread(target=self.echo, args=(socket, echo_queue))
        echo_thread.start()
        peer = socket.getpeername()
        log.info("serving connection from sap {0}".format(peer))
        while socket.poll("recv"):
            data = socket.recv()
            if data == None: break
            log.info("rcvd {0} byte from sap {1}".format(len(data), peer))
            if echo_queue.full():
                socket.setsockopt(nfc.llcp.SO_RCVBSY, True)
            echo_queue.put(data)
        log.info("remote peer {0} closed closed connection".format(peer))
        try: echo_queue.put_nowait(int(0))
        except queue.Full: pass
        echo_thread.join()
        socket.close()
        log.info("serve thread terminated")

    def listen(self, socket):
        try:
            socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
            socket.listen(backlog=0)
            while True:
                client_socket = socket.accept()
                peer = client_socket.getpeername()
                log.info("client sap {0} connected".format(peer))
                self.serve(client_socket)
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            log.info("close connection-mode echo server socket")
            socket.close()

class ConnectionModeDumpServer(Thread):
    def __init__(self, llc):
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.bind('urn:nfc:sn:cm-dump')
        log.info("bound connection-mode dump server to port {0}"
                 .format(socket.getsockname()))
        super(ConnectionModeDumpServer, self).__init__(
            target=self.listen, args=(socket,))
        self.name = "ConnectionModeEchoDumpThread"

    def serve(self, socket):
        peer = socket.getpeername()
        log.info("serving connection from sap {0}".format(peer))
        while socket.poll("recv"):
            data = socket.recv()
            if data == None: break
            log.info("dump: {0} byte from sap {1}".format(len(data), peer))
        socket.close()
        log.info("server thread terminated")

    def listen(self, socket):
        try:
            socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
            socket.listen(backlog=4)
            while True:
                client_socket = socket.accept()
                peer = client_socket.getpeername()
                log.info("client sap {0} connected".format(peer))
                Thread(target=self.serve, args=(client_socket,)).start()
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            log.info("close connection-mode dump server socket")
            socket.close()

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        super(TestProgram, self).__init__(parser, "llcp dbg clf")

    def on_llcp_startup(self, clf, llc):
        self.cl_echo_server = ConnectionLessEchoServer(llc)
        self.cm_echo_server = ConnectionModeEchoServer(llc)
        self.cm_dump_server = ConnectionModeDumpServer(llc)
        return llc
        
    def on_llcp_connect(self, llc):
        self.cl_echo_server.start()
        self.cm_echo_server.start()
        self.cm_dump_server.start()
        return True

if __name__ == '__main__':
    TestProgram().run()
