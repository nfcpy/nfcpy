#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
#
# Server side implementation of an LLCP validation suite to verify
# inter-operability of independent implementations. This suite was
# primarily developed for the purpose of validating the LLCP
# specification before final release by the NFC Forum.
#
import time
import struct
import argparse
import Queue as queue
from threading import Thread

import logging
log = logging.getLogger('main')

from cli import CommandLineInterface

import nfc
import nfc.llcp

class PatternNumberReceiver(Thread):
    service_name = 'urn:nfc:sn:dta-pattern-number'
    def __init__(self, llc, options):
        super(PatternNumberReceiver, self).__init__(name=self.service_name)
        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket.bind(self.service_name)
        log.info("%s bound to sap %d", self.service_name, socket.getsockname())
        options.pattern_number = 0x1280
        self.options = options
        self.socket = socket

    def run(self):
        try:
            while self.socket.poll('recv'):
                data, addr = self.socket.recvfrom()
                log.debug("received %d byte from sap %d", len(data), addr)
                if len(data) == 6 and data.startswith(b'\xFF\x00\x00\x00'):
                    pattern_number = struct.unpack_from('!H', data, 4)[0]
                    log.info("received pattern number %02Xh", pattern_number)
                    self.options.pattern_number = pattern_number
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            self.socket.close()

class ConnectionLessEchoServer(Thread):
    service_name = 'urn:nfc:sn:dta-cl-echo-in'
    def __init__(self, llc, options):
        super(ConnectionLessEchoServer, self).__init__(name=self.service_name)

        socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
        socket.bind(self.service_name)
        log.info("%s bound to sap %d", self.service_name, socket.getsockname())
        
        socket.setsockopt(nfc.llcp.SO_RCVBUF, options.cl_echo_buffer)
        #assert socket.getsockopt(nfc.llcp.SO_RCVBUF) == options.cl_echo_buffer
        
        self.recv_socket = socket
        self.options = options
        self.llc = llc

    def run(self):
        recv_socket = self.recv_socket
        send_socket = nfc.llcp.Socket(self.llc, nfc.llcp.LOGICAL_DATA_LINK)
        try:
            while True:
                log.info("waiting for start-of-test command")
                data, addr = recv_socket.recvfrom()
                if data == b'SOT': break
            echo_out_addr = recv_socket.resolve('urn:nfc:sn:dta-cl-echo-out')
            while recv_socket.poll("recv"):
                log.info("received data, start delay time")
                time.sleep(self.options.cl_echo_delay)
                while recv_socket.poll("recv", timeout=0):
                    data, addr = recv_socket.recvfrom()
                    log.info("received %d byte from sap %d", len(data), addr)
                    send_socket.sendto(data, echo_out_addr)
                log.info("no more data, start waiting")
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            log.info("close connection-less echo server socket")
            send_socket.close()
            recv_socket.close()

class ConnectionModeEchoServer(Thread):
    service_name = 'urn:nfc:sn:dta-co-echo-in'
    def __init__(self, llc, options):
        super(ConnectionModeEchoServer, self).__init__(name=self.service_name)
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.bind(self.service_name)
        log.info("%s bound to sap %d", self.service_name, socket.getsockname())
        
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        assert socket.getsockopt(nfc.llcp.SO_RCVBUF) == 2
        
        self.listen_socket = socket
        self.options = options
        self.llc = llc

    def run(self):
        try:
            self.listen_socket.listen(backlog=0)
            while True:
                socket = self.listen_socket.accept()
                srcsap = socket.getpeername()
                log.info("accepted data link connection from sap %d", srcsap)
                self.recv(socket, socket.llc)
        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            log.info("close connection-mode echo server socket")
            self.listen_socket.close()

    @staticmethod
    def recv_on_inbound_connection(recv_socket, echo_buffer):
        log.info("receiving from sap %d", recv_socket.getpeername())
        while recv_socket.poll("recv"):
            data = recv_socket.recv()
            if data is None: break
            log.info("rcvd %d byte", len(data))
            recv_socket.setsockopt(nfc.llcp.SO_RCVBSY, echo_buffer.full())
            echo_buffer.put(data)
        log.info("remote side closed connection")
        try: echo_buffer.put_nowait(int(0))
        except queue.Full: pass
        pass

    @staticmethod
    def send_on_outbound_connection(send_socket, echo_buffer):
        pass
        
    def recv(self, recv_socket, llc):
        time.sleep(0.1) # delay to accept inbound connection before resolve
        echo_buffer = queue.Queue(self.options.co_echo_buffer)
        send_socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        if self.options.pattern_number == 0x1200:
            send_socket.connect(self.options.sap_lt_co_out_dest)
        elif self.options.pattern_number == 0x1240:
            send_socket.connect("urn:nfc:sn:dta-co-echo-out")
        elif self.options.pattern_number == 0x1280:
            send_socket.connect(llc.resolve("urn:nfc:sn:dta-co-echo-out"))
        send_thread = Thread(target=self.send, args=(send_socket, echo_buffer))
        send_thread.start()
        log.info("receiving from sap %d", recv_socket.getpeername())
        while recv_socket.poll("recv"):
            data = recv_socket.recv()
            if data == None: break
            log.info("rcvd %d byte", len(data))
            recv_socket.setsockopt(nfc.llcp.SO_RCVBSY, echo_buffer.full())
            echo_buffer.put(data)
        log.info("remote side closed connection")
        try: echo_buffer.put_nowait(int(0))
        except queue.Full: pass
        send_thread.join()
        recv_socket.close()
        log.info("recv thread terminated")

    def send(self, send_socket, echo_buffer):
        co_echo_delay = self.options.co_echo_delay
        log.info("sending back to sap %d", send_socket.getpeername())
        while True:
            data = echo_buffer.get()
            if data == 0:
                log.info("send thread got quit event")
                send_socket.close()
                return
            if data != None:
                log.info("data available, wait %.1f seconds", co_echo_delay)
                time.sleep(co_echo_delay)
            while data != None:
                try:
                    log.info("send %d byte", len(data))
                    send_socket.send(data)
                except nfc.llcp.Error:
                    log.info("failed to send data")
                    try: echo_buffer.get_nowait()
                    except queue.Empty: pass
                    return
                try: data = echo_buffer.get_nowait()
                except queue.Empty: data = None
                if data == 0:
                    log.info("send thread got quit event")
                    send_socket.close()
                    return
                if data != None:
                    log.info("more data available")

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        group = parser.add_argument_group(title="DTA Options")
        group.add_argument(
            "--cl-echo-delay", type=float, default=3.0, metavar='',
            help=("connection-less echo server delay time "
                  "(default: %(default).1f s)"))
        group.add_argument(
            "--cl-echo-buffer", type=int, default=1, metavar='',
            help=("connection-less echo server capacity "
                  "(default: %(default)d SDU)"))
        group.add_argument(
            "--co-echo-delay", type=float, default=3.0, metavar='',
            help=("connection-oriented server delay time "
                  "(default: %(default).1f s)"))
        group.add_argument(
            "--co-echo-buffer", type=int, default=2, metavar='',
            help=("connection-oriented server capacity "
                  "(default: %(default)d SDU)"))
        group.add_argument(
            "--co-echo-cwait", type=float, default=3.0, metavar='',
            help=("maximum wait time for outbound connection "
                  "(default: %(default).1f s)"))
        
        group.add_argument(
            "--sap-lt-cl-out-dest", type=int, default=0x11, metavar='',
            help=("outbound logical data link dest addr "
                  "(default: %(default)d)"))
        group.add_argument(
            "--sap-lt-co-out-dest", type=int, default=0x12, metavar='',
            help=("outbound data link connection dest addr "
                  "(default: %(default)d)"))
        
        super(TestProgram, self).__init__(parser, "llcp dbg clf")

    def on_llcp_startup(self, llc):
        self.pattern_number = PatternNumberReceiver(llc, self.options)
        self.cl_echo_server = ConnectionLessEchoServer(llc, self.options)
        self.cm_echo_server = ConnectionModeEchoServer(llc, self.options)
        return llc
        
    def on_llcp_connect(self, llc):
        self.pattern_number.start()
        self.cl_echo_server.start()
        self.cm_echo_server.start()
        return True

if __name__ == '__main__':
    TestProgram().run()
