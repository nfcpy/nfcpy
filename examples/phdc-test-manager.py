#!/usr/bin/env python
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
log = logging.getLogger('main')

import os
import sys
import time
import string
import struct
import os.path
import inspect
import argparse
from threading import Thread
import Queue as queue

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.ndef
import nfc.llcp

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.debug("{func}({args})".format(func=func.__name__, args=_args))
        return func(*args, **kwargs)
    return traced_func

def printable(data):
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += printable(data[i:i+16])
    return '\n'.join(s)

class PhdcManager(Thread):
    def __init__(self):
        super(PhdcManager, self).__init__()
        self.oqueue = queue.Queue()
        self.iqueue = queue.Queue()

    def enqueue(self, apdu):
        if apdu is None or len(apdu) > 0:
            self.iqueue.put(apdu)

    def dequeue(self):
        try:
            apdu = self.oqueue.get(block=True, timeout=0.1)
        except queue.Empty:
            apdu = ""
        return apdu
                
    def send(self, apdu):
        self.oqueue.put(apdu)

    def recv(self, timeout):
        try:
            return self.iqueue.get(block=True, timeout=timeout)
        except queue.Empty:
            return None

class PhdcTagManager(PhdcManager):
    def __init__(self, tag, apdu):
        super(PhdcTagManager, self).__init__()
        self.enqueue(apdu)
        self.tag = tag
        self.mc = 1

    @trace
    def read_phd_message(self, timeout):
        t0 = time.time()
        while True:
            time.sleep(0.01)
            if self.tag.ndef.changed:
                if self.tag.ndef.message.type == "urn:nfc:wkt:PHD":
                    data = bytearray(self.tag.ndef.message[0].data)
                    if data[0] & 0x8F == (self.mc % 16) | 0x80:
                        log.info("[phdc] <<< " + str(data).encode("hex"))
                        empty_ndef_msg = nfc.ndef.Message(nfc.ndef.Record())
                        self.tag.ndef.message = empty_ndef_msg
                        self.mc += 1
                        return data[1:]
                    else:
                        log.debug("wrong flags {0:02x}".format(data[0]))
            if int((time.time() - t0) * 1000) > timeout:
                return None

    @trace
    def write_phd_message(self, apdu):
        data = bytearray([(self.mc % 16) | 0x80]) + apdu
        record = nfc.ndef.Record("urn:nfc:wkt:PHD", data=str(data))
        log.info("[phdc] >>> {0}".format(record.data.encode("hex")))
        self.tag.ndef.message = nfc.ndef.Message(record)
        self.mc += 1
        
    def run(self):
        log.info("entering phdc manager run loop")
        while True:
            try:
                apdu = self.dequeue()
                self.write_phd_message(apdu)
                apdu = self.read_phd_message(timeout=100)
                self.enqueue(apdu)
            except IOError:
                self.enqueue(None)
                break
        log.info("leaving phdc manager run loop")
        
thermometer_assoc_req = \
    "E200 0032 8000 0000" \
    "0001 002A 5079 0026" \
    "8000 0000 A000 8000" \
    "0000 0000 0000 0080" \
    "0000 0008 3132 3334" \
    "3536 3738 0320 0001" \
    "0100 0000 0000"

thermometer_assoc_res = \
    "E300 002C 0003 5079" \
    "0026 8000 0000 8000" \
    "8000 0000 0000 0000" \
    "8000 0000 0008 3837" \
    "3635 3433 3231 0000" \
    "0000 0000 0000 0000" \

assoc_release_req = "E40000020000"
assoc_release_res = "E50000020000"

def phdc_tag_manager(tag):
    if tag.ndef.message.type == "urn:nfc:wkt:PHD":
        phd_data = bytearray(tag.ndef.message[0].data)
        if phd_data[0] == 0:
            manager = PhdcTagManager(tag, apdu=phd_data[1:])
            manager.start()
            log.info("entering ieee manager")
            while True:
                apdu = manager.recv(timeout=None)
                if apdu is None: break
                log.info("[ieee] <<< {0}".format(str(apdu).encode("hex")))
                if apdu.startswith("\xE2\x00"):
                    apdu = bytearray.fromhex(thermometer_assoc_res)
                elif apdu.startswith("\xE4\x00"):
                    apdu = bytearray.fromhex(assoc_release_res)
                else:
                    apdu = apdu[::-1]
                time.sleep(0.2)
                log.info("[ieee] >>> {0}".format(str(apdu).encode("hex")))
                manager.send(apdu)
            log.info("leaving ieee manager")
    
class PhdcPeerManager(Thread):
    def __init__(self, llc, service_name):
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.bind(service_name)
        addr = socket.getsockname()
        log.info("service {0!r} bound to port {1}".format(service_name, addr))
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        socket.listen(backlog=1)
        super(PhdcPeerManager, self).__init__(
            target=self.listen, args=(socket,))

    def listen(self, socket):
        try:
            while True:
                client = socket.accept()
                peer = client.getpeername()
                miu = client.getsockopt(nfc.llcp.SO_SNDMIU)
                log.info("serving phdc agent from sap {0}".format(peer))
                log.info("entering ieee manager")
                while True:
                    data = client.recv()
                    if data == None: break
                    log.info("rcvd {0} byte data".format(len(data)))
                    size = struct.unpack(">H", data[0:2])[0]
                    apdu = data[2:]
                    while len(apdu) < size:
                        data = client.recv()
                        if data == None: break
                        log.info("rcvd {0} byte data".format(len(data)))
                        apdu += data
                    log.info("[ieee] <<< {0}".format(str(apdu).encode("hex")))
                    if apdu.startswith("\xE2\x00"):
                        apdu = bytearray.fromhex(thermometer_assoc_res)
                    elif apdu.startswith("\xE4\x00"):
                        apdu = bytearray.fromhex(assoc_release_res)
                    else:
                        apdu = apdu[::-1]
                    time.sleep(0.2)
                    log.info("[ieee] >>> {0}".format(str(apdu).encode("hex")))
                    data = struct.pack(">H", len(apdu)) + apdu
                    for i in range(0, len(data), miu):
                        client.send(str(data[i:i+miu]))
                log.info("remote peer {0} closed connection".format(peer))
                log.info("leaving ieee manager")
                client.close()

        except nfc.llcp.Error as e:
            (log.debug if e.errno == nfc.llcp.errno.EPIPE else log.error)(e)
        finally:
            socket.close()

class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        super(TestProgram, self).__init__(
            parser, groups="llcp rdwr dbg clf")

    def on_llcp_startup(self, clf, llc):
        validation_service_name = "urn:nfc:xsn:nfc-forum.org:phdc-validation"
        self.phdc_manager_1 = PhdcPeerManager(llc, "urn:nfc:sn:phdc")
        self.phdc_manager_2 = PhdcPeerManager(llc, validation_service_name)
        return llc
        
    def on_llcp_connect(self, llc):
        self.phdc_manager_1.start()
        self.phdc_manager_2.start()
        return True

    def on_rdwr_connect(self, tag):
        log.info(tag)
        if tag.ndef:
            log.info("NDEF attribute data:")
            log.info("  version   = %s" % tag.ndef.version)
            log.info("  writeable = %s" % ("no", "yes")[tag.ndef.writeable])
            log.info("  capacity  = %d byte" % tag.ndef.capacity)
            log.info("  data size = %d byte" % len(tag.ndef.message))
            if len(tag.ndef.message):
                log.info("NDEF message dump:")
                log.info(format_data(str(tag.ndef.message)))
                log.info(tag.ndef.message.pretty())
                phdc_tag_manager(tag)
                return False
        return True

if __name__ == '__main__':
    TestProgram().run()
