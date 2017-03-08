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

import os
import sys
import time
import string
import struct
import inspect
import argparse
import Queue as queue
from threading import Thread, Lock

from cli import CommandLineInterface, TestFail

import nfc
import nfc.ndef
import nfc.llcp

def info(message, prefix="  "):
    log.info(prefix + message)

class PhdcAgent(Thread):
    def __init__(self):
        super(PhdcAgent, self).__init__()
        self.oqueue = queue.Queue()
        self.iqueue = queue.Queue()

    def enqueue(self, apdu):
        if apdu is None or len(apdu) > 0:
            self.iqueue.put(apdu)

    def dequeue(self, timeout):
        try:
            apdu = self.oqueue.get(block=True, timeout=timeout)
        except queue.Empty:
            apdu = ""
        return apdu
                
    def send(self, apdu):
        log.info("[ieee] >>> {0}".format(str(apdu).encode("hex")))
        self.oqueue.put(apdu)

    def recv(self, timeout):
        try:
            apdu = self.iqueue.get(block=True, timeout=timeout)
        except queue.Empty:
            pass
        else:
            log.info("[ieee] <<< {0}".format(str(apdu).encode("hex")))
            return apdu

class PhdcTagAgent(PhdcAgent):
    def __init__(self, tag, cmd, apdu=bytearray(), flags='\x00'):
        super(PhdcTagAgent, self).__init__()
        self.terminate = False
        self.mc = 1
        attr = nfc.tag.tt3.NdefAttributeData()
        attr.version = "1.0"
        attr.nbr, attr.nbw = 12, 8
        attr.capacity = 1024
        attr.writeable = True
        attr.length = 7 + len(apdu)
    
        phd_rec = nfc.ndef.Record("urn:nfc:wkt:PHD", data=flags + apdu)
        phd_msg = nfc.ndef.Message(phd_rec)
        
        self.ndef_data_area = str(attr) + bytearray(attr.capacity)
        self.ndef_data_area[16:16+7+len(apdu)] = bytearray(str(phd_msg))

        tag.add_service(0x0009, self.ndef_read, self.ndef_write)
        tag.add_service(0x000B, self.ndef_read, lambda: False)
        self.tag = tag
        self.cmd = cmd
        
        self.ndef_read_lock = Lock()
        self.ndef_write_lock = Lock()

    def ndef_read(self, block, read_begin, read_end):
        if read_begin is True:
            self.ndef_read_lock.acquire()
        try:
            if block < len(self.ndef_data_area) / 16:
                data = self.ndef_data_area[block*16:(block+1)*16]
                log.debug("[tt3] got read block #{0} {1}".format(
                        block, str(data).encode("hex")))
                return data
            else:
                log.debug("[tt3] got read block #{0}".format(block))
        finally:
            if read_end is True:
                self.ndef_read_lock.release()
    
    def ndef_write(self, block, data, write_begin, write_end):
        if write_begin is True:
            self.ndef_write_lock.acquire()
        try:
            log.debug("[tt3] got write block #{0} {1}".format(
                    block, str(data).encode("hex")))
            if block < len(self.ndef_data_area) / 16:
                self.ndef_data_area[block*16:(block+1)*16] = data
                return True
        finally:
            if write_end is True:
                self.ndef_write_lock.release()
                apdu = self.recv_phd_message()
                if apdu is not None:
                    self.enqueue(apdu)
                    Thread(target=self.send_phd_message).start()
            
    def recv_phd_message(self):
        attr = nfc.tag.tt3.NdefAttributeData(self.ndef_data_area[0:16])
        if attr.valid and not attr.writing and attr.length > 0:
            #print str(self.ndef_data_area[16:16+attr.length]).encode("hex")
            try:
                message = nfc.ndef.Message(
                    self.ndef_data_area[16:16+attr.length])
            except nfc.ndef.LengthError:
                return None

            if message.type == "urn:nfc:wkt:PHD":
                data = bytearray(message[0].data)
                if data[0] & 0x8F == 0x80 | (self.mc % 16):
                    log.info("[phdc] <<< " + str(data).encode("hex"))
                    self.mc += 1
                    attr.length = 0
                    self.ndef_data_area[0:16] = bytearray(str(attr))
                    return data[1:]
                   
    def send_phd_message(self):
        apdu = self.dequeue(timeout=0.1)
        data = bytearray([0x80 | (self.mc % 16)]) + apdu
        record = nfc.ndef.Record("urn:nfc:wkt:PHD", data=str(data))
        with self.ndef_read_lock:
            if not self.terminate:
                log.info("[phdc] >>> " + str(data).encode("hex"))
                data = bytearray(str(nfc.ndef.Message(record)))
                attr = nfc.tag.tt3.NdefAttributeData(self.ndef_data_area[0:16])
                attr.length = len(data)
                self.ndef_data_area[0:16+attr.length] = str(attr) + data
                self.mc += 1
        
    def run(self):
        log.info("entering phdc agent run loop")
        command, self.cmd = self.cmd, None
        while not (command is None or self.terminate is True):
            response = self.tag.process_command(command)
            try:
                command = self.tag.send_response(response, timeout=1)
            except nfc.clf.TimeoutError:
                log.info("no command received within 1 second")
                break
            except nfc.clf.TransmissionError:
                break
        log.info("leaving phdc agent run loop")

    def stop(self):
        self.terminate = True
        self.join(timeout=10.0)
        
thermometer_assoc_req = \
    "E200 0032 8000 0000" \
    "0001 002A 5079 0026" \
    "8000 0000 8000 8000" \
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

phdc_tag_agent_description = """
Execute some Personal Health Device Communication (PHDC) tests running
as a Tag Agent. The reader device must have the PHDC validation R/W
Mode Test Manager running.
"""
class PhdcTagAgentTest(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=phdc_tag_agent_description)
        super(PhdcTagAgentTest, self).__init__(
            parser, groups="test card dbg clf")

    def on_card_startup(self, target):
        idm = bytearray.fromhex("02FE") + os.urandom(6)
        pmm = bytearray.fromhex("01E0000000FFFF00")
        sys = bytearray.fromhex("12FC")
        
        target.brty = str(self.options.bitrate) + "F"
        target.sensf_res = "\x01" + idm + pmm + sys
        return target
    
    def test_00(self, tag, command):
        """Send data read from scenario file"""

        agent = PhdcTagAgent(tag, command)
        agent.start()
        info("entering ieee agent")

        try:
            with open("scenario.txt") as f:
                for line in f:
                    if line.startswith('#'):
                        continue
                    apdu = bytearray.fromhex(line.strip())
                    agent.send(apdu)
                    apdu = agent.recv(timeout=5.0)
                    if apdu is None:
                        raise TestFail("no data received")
        except IOError as e:
            log.error(e)
            time.sleep(0.1)

        info("leaving ieee agent")

        if agent.is_alive():
            agent.stop()

    def test_01(self, tag, command):
        """Discovery, association and release"""
        
        agent = PhdcTagAgent(tag, command)
        agent.start()
        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        info("send thermometer association request")
        agent.send(apdu)

        apdu = agent.recv(timeout=5.0)
        if apdu is None:
            raise TestFail("no data received")

        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        time.sleep(3.0)

        apdu = bytearray.fromhex(assoc_release_req)
        info("send association release request")
        agent.send(apdu)

        apdu = agent.recv(timeout=5.0)
        if apdu is None:
            raise TestFail("no data received")

        if apdu.startswith("\xE5\x00"):
            info("rcvd association release response")

        info("leaving ieee agent")

        if agent.is_alive():
            agent.stop()
        
    def test_02(self, tag, command):
        """Association after release"""
        
        agent = PhdcTagAgent(tag, command)
        agent.start()
        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        info("send thermometer association request")
        agent.send(apdu)

        apdu = agent.recv(timeout=5.0)
        if apdu is None:
            raise TestFail("no data received")
        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        apdu = bytearray.fromhex(assoc_release_req)
        info("send association release request")
        agent.send(apdu)

        apdu = agent.recv(timeout=5.0)
        if apdu is None:
            raise TestFail("no data received")
        if apdu.startswith("\xE5\x00"):
            info("rcvd association release response")

        info("leaving ieee agent")

        time.sleep(3.0)

        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        info("send thermometer association request")
        agent.send(apdu)

        apdu = agent.recv(timeout=5.0)
        if apdu is None:
            raise TestFail("no data received")
        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        time.sleep(1.0)
        info("now move devices out of communication range")

        info("leaving ieee agent")
        
        if agent.is_alive():
            agent.stop()
        
    def test_03(self, tag, command):
        """Activation with invalid settings"""
        
        agent = PhdcTagAgent(tag, command, flags='\x02')
        info("sending with non-zero message counter")
        agent.start()
        if agent.is_alive():
            agent.stop()
        
    def test_04(self, tag, command):
        """Activation with invalid RFU value"""
        
        agent = PhdcTagAgent(tag, command, flags='\x40')
        info("sending with non-zero reserved field")
        agent.start()
            
        info("entering ieee agent")
        time.sleep(3.0)
        info("leaving ieee agent")
        if agent.is_alive():
            agent.stop()
        
phdc_p2p_agent_description = """
Execute some Personal Health Device Communication (PHDC) tests. The
peer device must have the PHDC validation test manager running.
"""
class PhdcP2pAgentTest(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=phdc_p2p_agent_description)
        super(PhdcP2pAgentTest, self).__init__(
            parser, groups="test llcp dbg clf")

    def test_00(self, llc):
        """Send data read from scenario file"""

        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        socket.connect("urn:nfc:sn:phdc")
        peer_sap = socket.getpeername()
        log.info("connected with phdc manager at sap {0}".format(peer_sap))
        log.info("entering ieee agent")

        try:
            with open("scenario.txt") as f:
                for line in f:
                    if line.startswith('#'):
                        continue

                    apdu = bytearray.fromhex(line)
                    apdu = struct.pack(">H", len(apdu)) + apdu
                    log.info("send {0}".format(str(apdu).encode("hex")))
                    socket.send(str(apdu))

                    apdu = socket.recv()
                    log.info("rcvd {0}".format(str(apdu).encode("hex")))
        except IOError as e:
            log.error(e)

        log.info("leaving ieee agent")
        socket.close()

    def test_01(self, llc):
        """Connect, associate and release"""
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        service_name = "urn:nfc:sn:phdc"
        try:
            socket.connect(service_name)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to {0!r}".format(service_name))
        
        peer_sap = socket.getpeername()
        info("connected with phdc manager at sap {0}".format(peer_sap))
        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        apdu = struct.pack(">H", len(apdu)) + apdu
        info("send thermometer association request")
        info("send {0}".format(str(apdu).encode("hex")))
        socket.send(str(apdu))

        apdu = socket.recv()
        info("rcvd {0}".format(str(apdu).encode("hex")))
        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        time.sleep(3.0)

        apdu = bytearray.fromhex(assoc_release_req)
        apdu = struct.pack(">H", len(apdu)) + apdu
        info("send association release request")
        info("send {0}".format(str(apdu).encode("hex")))
        socket.send(str(apdu))

        apdu = socket.recv()
        info("rcvd {0}".format(str(apdu).encode("hex")))
        if apdu.startswith("\xE5\x00"):
            info("rcvd association release response")

        info("leaving ieee agent")
        socket.close()

    def test_02(self, llc):
        """Association after release"""

        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        service_name = "urn:nfc:sn:phdc"
        try:
            socket.connect(service_name)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to {0!r}".format(service_name))
        
        peer_sap = socket.getpeername()
        info("connected with phdc manager at sap {0}".format(peer_sap))
        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        apdu = struct.pack(">H", len(apdu)) + apdu
        info("send thermometer association request")
        info("send {0}".format(str(apdu).encode("hex")))
        socket.send(str(apdu))

        apdu = socket.recv()
        info("rcvd {0}".format(str(apdu).encode("hex")))
        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        socket.close()

        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        socket.connect("urn:nfc:sn:phdc")
        peer_sap = socket.getpeername()
        info("connected with phdc manager at sap {0}".format(peer_sap))
        info("entering ieee agent")

        apdu = bytearray.fromhex(thermometer_assoc_req)
        apdu = struct.pack(">H", len(apdu)) + apdu
        info("send thermometer association request")
        info("send {0}".format(str(apdu).encode("hex")))
        socket.send(str(apdu))

        apdu = socket.recv()
        info("rcvd {0}".format(str(apdu).encode("hex")))
        if apdu.startswith("\xE3\x00"):
            info("rcvd association response")

        time.sleep(3.0)

        apdu = bytearray.fromhex(assoc_release_req)
        apdu = struct.pack(">H", len(apdu)) + apdu
        info("send association release request")
        info("send {0}".format(str(apdu).encode("hex")))
        socket.send(str(apdu))

        apdu = socket.recv()
        info("rcvd {0}".format(str(apdu).encode("hex")))
        if apdu.startswith("\xE5\x00"):
            info("rcvd association release response")

        info("leaving ieee agent")

    def test_03(self, llc):
        """Fragmentation and reassembly"""
        
        socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
        socket.setsockopt(nfc.llcp.SO_RCVBUF, 2)
        service_name = "urn:nfc:xsn:nfc-forum.org:phdc-validation"
        try:
            socket.connect(service_name)
        except nfc.llcp.ConnectRefused:
            raise TestFail("could not connect to {0!r}".format(service_name))
        
        peer_sap = socket.getpeername()
        info("connected with phdc manager at sap {0}".format(peer_sap))

        miu = socket.getsockopt(nfc.llcp.SO_SNDMIU)
        
        apdu = os.urandom(2176)
        log.info("send ieee apdu of size {0} byte".format(len(apdu)))
        apdu = struct.pack(">H", len(apdu)) + apdu
        for i in range(0, len(apdu), miu):
            socket.send(str(apdu[i:i+miu]))

        sent_apdu = apdu[2:]

        data = socket.recv()
        size = struct.unpack(">H", data[0:2])[0]
        apdu = data[2:]
        while len(apdu) < size:
            data = socket.recv()
            if data == None: break
            log.info("rcvd {0} byte data".format(len(data)))
            apdu += data
        info("rcvd {0} byte apdu".format(len(apdu)))

        rcvd_apdu = apdu[::-1]
        if rcvd_apdu != sent_apdu:
            raise TestFail("received data does not equal sent data")

        socket.close()
    
if __name__ == '__main__':
    try: mode, sys.argv = sys.argv[1], sys.argv[0:1] + sys.argv[2:]
    except IndexError: mode = None

    if mode is None or mode not in ("p2p", "tag"):
        print("{0} requires 'p2p' or 'tag' as first argument."
              .format(sys.argv[0]))
    elif mode == "p2p":
        PhdcP2pAgentTest().run()
    elif mode == "tag":
        PhdcTagAgentTest().run()
