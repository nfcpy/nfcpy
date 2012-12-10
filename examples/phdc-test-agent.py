#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
import struct
import os.path
import inspect
import threading
import Queue as queue

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef
import nfc.llcp

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.info("{func}({args})".format(func=func.__name__, args=_args))
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

class PhdcAgent(threading.Thread):
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
    def __init__(self, tag, apdu=bytearray(), flags='\x00'):
        super(PhdcTagAgent, self).__init__()
        self.mc = 1
        attr = nfc.tt3.NdefAttributeData()
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
        
        self.ndef_read_lock = threading.Lock()
        self.ndef_write_lock = threading.Lock()

    def ndef_read(self, block, read_begin, read_end):
        if read_begin is True:
            self.ndef_read_lock.acquire()
        try:
            log.debug("tt3 read block #{0}".format(block))
            if block < len(self.ndef_data_area) / 16:
                return self.ndef_data_area[block*16:(block+1)*16]
        finally:
            if read_end is True:
                self.ndef_read_lock.release()
    
    def ndef_write(self, block, data, write_begin, write_end):
        if write_begin is True:
            self.ndef_write_lock.acquire()
        try:
            log.debug("tt3 write block #{0}".format(block))
            if block < len(self.ndef_data_area) / 16:
                self.ndef_data_area[block*16:(block+1)*16] = data
                return True
        finally:
            if write_end is True:
                self.ndef_write_lock.release()
                apdu = self.recv_phd_message()
                if apdu is not None:
                    self.enqueue(apdu)
                    threading.Thread(target=self.send_phd_message).start()
            
    def recv_phd_message(self):
        attr = nfc.tt3.NdefAttributeData(self.ndef_data_area[0:16])
        if attr.valid and not attr.writing and attr.length > 0:
            try:
                message = nfc.ndef.Message(
                    self.ndef_data_area[16:16+attr.length])
            except nfc.ndef.LengthError:
                return None

            if message.type == "urn:nfc:wkt:PHD":
                data = bytearray(message[0].data)
                if data[0] & 0x0F == (self.mc % 4) << 2 | 3:
                    log.info("[phdc] <<< " + str(data).encode("hex"))
                    self.mc += 1
                    attr.length = 0
                    self.ndef_data_area[0:16] = bytearray(str(attr))
                    return data[1:]
                   
    def send_phd_message(self):
        apdu = self.dequeue(timeout=0.1)
        data = bytearray([(self.mc % 4) << 2 | 2]) + apdu
        record = nfc.ndef.Record("urn:nfc:wkt:PHD", data=str(data))
        with self.ndef_read_lock:
            log.info("[phdc] >>> " + str(data).encode("hex"))
            data = bytearray(str(nfc.ndef.Message(record)))
            attr = nfc.tt3.NdefAttributeData(self.ndef_data_area[0:16])
            attr.length = len(data)
            self.ndef_data_area[0:16+attr.length] = str(attr) + data
            self.mc += 1
        
    def run(self):
        log.info("entering phdc agent run loop")
        while self.tag.wait_command(timeout=1.0):
            self.tag.send_response()
        log.info("leaving phdc agent run loop")
        
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

def phdc_tag_agent(args):
    log.info("performing as tag agent")
    if args.test == 1:
        phdc_tag_agent_test1(args)
    if args.test == 2:
        phdc_tag_agent_test2(args)
    if args.test == 3:
        phdc_tag_agent_test3(args)
    if args.test == 4:
        phdc_tag_agent_test4(args)

def phdc_tag_agent_test1(args):
    idm = bytearray.fromhex("02FE") + os.urandom(6)
    pmm = bytearray.fromhex("01E0000000FFFF00")
    sc = bytearray.fromhex("12FC")
    tag = nfc.tt3.Type3TagEmulation(idm, pmm, sc, "212")
                       
    agent = PhdcTagAgent(tag)
    log.info("touch a manager")

    while True:
        activated = args.clf.listen(1.0, agent.tag)
        if activated and activated == agent.tag:
            log.info("agent activated")
            agent.start()
            log.info("entering ieee agent")
            
            apdu = bytearray.fromhex(thermometer_assoc_req)
            log.info("send thermometer association request")
            agent.send(apdu)
            
            apdu = agent.recv(timeout=5.0)
            if apdu is None: break
            if apdu.startswith("\xE3\x00"):
                log.info("rcvd association response")
            
            time.sleep(3.0)
            
            apdu = bytearray.fromhex(assoc_release_req)
            log.info("send association release request")
            agent.send(apdu)
                
            apdu = agent.recv(timeout=5.0)
            if apdu is None: break
            if apdu.startswith("\xE5\x00"):
                log.info("rcvd association release response")
            
            log.info("leaving ieee agent")
            agent.join(timeout=10.0)
            break
        
def phdc_tag_agent_test2(args):
    idm = bytearray.fromhex("02FE") + os.urandom(6)
    pmm = bytearray.fromhex("01E0000000FFFF00")
    sc = bytearray.fromhex("12FC")
    tag = nfc.tt3.Type3TagEmulation(idm, pmm, sc, "212")
                       
    agent = PhdcTagAgent(tag)
    log.info("touch a manager")

    while True:
        activated = args.clf.listen([agent.tag], timeout=1000)
        if activated and activated == agent.tag:
            log.info("agent activated")
            agent.start()
            log.info("entering ieee agent")
            
            apdu = bytearray.fromhex(thermometer_assoc_req)
            log.info("send thermometer association request")
            agent.send(apdu)
            
            apdu = agent.recv(timeout=5.0)
            if apdu is None: break
            if apdu.startswith("\xE3\x00"):
                log.info("rcvd association response")
            
            apdu = bytearray.fromhex(assoc_release_req)
            log.info("send association release request")
            agent.send(apdu)
                
            apdu = agent.recv(timeout=5.0)
            if apdu is None: break
            if apdu.startswith("\xE5\x00"):
                log.info("rcvd association release response")
            
            log.info("leaving ieee agent")

            time.sleep(3.0)

            log.info("entering ieee agent")
            
            apdu = bytearray.fromhex(thermometer_assoc_req)
            log.info("send thermometer association request")
            agent.send(apdu)
            
            apdu = agent.recv(timeout=5.0)
            if apdu is None: break
            if apdu.startswith("\xE3\x00"):
                log.info("rcvd association response")
            
            time.sleep(1.0)
            log.info("now move devices out of communication range")
            
            log.info("leaving ieee agent")
            agent.join(timeout=10.0)
            
            break
        
def phdc_tag_agent_test3(args):
    idm = bytearray.fromhex("02FE") + os.urandom(6)
    pmm = bytearray.fromhex("01E0000000FFFF00")
    sc = bytearray.fromhex("12FC")
    tag = nfc.tt3.Type3TagEmulation(idm, pmm, sc, "212")
                       
    agent = PhdcTagAgent(tag, flags="\x02")
    log.info("touch a manager")

    while True:
        activated = args.clf.listen([agent.tag], timeout=1000)
        if activated and activated == agent.tag:
            log.info("tag activated, wait 10 sec")
            agent.start()
            agent.join(timeout=10.0)
        
def phdc_tag_agent_test4(args):
    idm = bytearray.fromhex("02FE") + os.urandom(6)
    pmm = bytearray.fromhex("01E0000000FFFF00")
    sc = bytearray.fromhex("12FC")
    tag = nfc.tt3.Type3TagEmulation(idm, pmm, sc, "212")

    agent = PhdcTagAgent(tag, flags="\x40")
    log.info("touch a manager")

    while True:
        activated = args.clf.listen([agent.tag], timeout=1000)
        if activated and activated == agent.tag:
            log.info("agent activated")
            agent.start()
            log.info("entering ieee agent")
            time.sleep(3.0)
            log.info("leaving ieee agent")
            agent.join(timeout=10.0)
            break
        
def phdc_p2p_agent(args):
    log.info("performing as p2p agent")
    if args.test == 1:
        phdc_p2p_agent_test1(args)
    if args.test == 2:
        phdc_p2p_agent_test2(args)
    if args.test == 3:
        phdc_p2p_agent_test3(args)

def phdc_p2p_agent_test1(args):
    log.info("running p2p agent test #1")
    llcp_config = {'recv-miu': 240, 'send-lto': 500}
    llcp_option_string = nfc.llcp.startup(llcp_config)
    try:
        while True:
            peer = args.clf.poll(llcp_option_string)
            if isinstance(peer, nfc.dep.DEP):
                log.info("dep target activated")
                log.info("general bytes: {0}".
                         format(peer.general_bytes.encode("hex")))
                if peer.general_bytes.startswith("Ffm"):
                    break
    except KeyboardInterrupt:
        pass
    
    if not peer:
        return

    log.info("got a peer")
    nfc.llcp.activate(peer)
    
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    nfc.llcp.connect(socket, "urn:nfc:sn:phdc")
    peer_sap = nfc.llcp.getpeername(socket)
    log.info("connected with phdc manager at sap {0}".format(peer_sap))
    log.info("entering ieee agent")
    
    apdu = bytearray.fromhex(thermometer_assoc_req)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send thermometer association request")
    log.info("send {0}".format(str(apdu).encode("hex")))
    nfc.llcp.send(socket, str(apdu))
    
    apdu = nfc.llcp.recv(socket)
    log.info("rcvd {0}".format(str(apdu).encode("hex")))
    if apdu.startswith("\xE3\x00"):
        log.info("rcvd association response")

    time.sleep(3.0)
            
    apdu = bytearray.fromhex(assoc_release_req)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send association release request")
    log.info("send {0}".format(str(apdu).encode("hex")))
    nfc.llcp.send(socket, str(apdu))

    apdu = nfc.llcp.recv(socket)
    log.info("rcvd {0}".format(str(apdu).encode("hex")))
    if apdu.startswith("\xE5\x00"):
        log.info("rcvd association release response")

    log.info("leaving ieee agent")
    socket.close()
    
def phdc_p2p_agent_test2(args):
    log.info("running p2p agent test #2")
    llcp_config = {'recv-miu': 240, 'send-lto': 500}
    llcp_option_string = nfc.llcp.startup(llcp_config)
    try:
        while True:
            peer = args.clf.poll(llcp_option_string)
            if isinstance(peer, nfc.dep.DEP):
                if peer.general_bytes.startswith("Ffm"):
                    break
    except KeyboardInterrupt:
        pass
    
    if not peer:
        return

    log.info("got a peer")
    nfc.llcp.activate(peer)
    
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    nfc.llcp.connect(socket, "urn:nfc:sn:phdc")
    peer_sap = nfc.llcp.getpeername(socket)
    log.info("connected with phdc manager at sap {0}".format(peer_sap))
    log.info("entering ieee agent")
    
    apdu = bytearray.fromhex(thermometer_assoc_req)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send thermometer association request")
    log.info("send {0}".format(str(apdu).encode("hex")))
    nfc.llcp.send(socket, str(apdu))
    
    apdu = nfc.llcp.recv(socket)
    log.info("rcvd {0}".format(str(apdu).encode("hex")))
    if apdu.startswith("\xE3\x00"):
        log.info("rcvd association response")

    socket.close()
    
    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    nfc.llcp.connect(socket, "urn:nfc:sn:phdc")
    peer_sap = nfc.llcp.getpeername(socket)
    log.info("connected with phdc manager at sap {0}".format(peer_sap))
    log.info("entering ieee agent")
    
    apdu = bytearray.fromhex(thermometer_assoc_req)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send thermometer association request")
    log.info("send {0}".format(str(apdu).encode("hex")))
    nfc.llcp.send(socket, str(apdu))
    
    apdu = nfc.llcp.recv(socket)
    log.info("rcvd {0}".format(str(apdu).encode("hex")))
    if apdu.startswith("\xE3\x00"):
        log.info("rcvd association response")

    time.sleep(3.0)
            
    apdu = bytearray.fromhex(assoc_release_req)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send association release request")
    log.info("send {0}".format(str(apdu).encode("hex")))
    nfc.llcp.send(socket, str(apdu))

    apdu = nfc.llcp.recv(socket)
    log.info("rcvd {0}".format(str(apdu).encode("hex")))
    if apdu.startswith("\xE5\x00"):
        log.info("rcvd association release response")

    log.info("leaving ieee agent")
    
def phdc_p2p_agent_test3(args):
    log.info("running p2p agent test #3")
    llcp_config = {'recv-miu': 240, 'send-lto': 500}
    llcp_option_string = nfc.llcp.startup(llcp_config)
    try:
        while True:
            peer = args.clf.poll(llcp_option_string)
            if isinstance(peer, nfc.dep.DEP):
                if peer.general_bytes.startswith("Ffm"):
                    break
    except KeyboardInterrupt:
        pass
    
    if not peer:
        return

    log.info("got a peer")
    nfc.llcp.activate(peer)

    socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
    nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
    nfc.llcp.connect(socket, "urn:nfc:xsn:nfc-forum.org:phdc-validation")
    peer_sap = nfc.llcp.getpeername(socket)
    log.info("connected with phdc manager at sap {0}".format(peer_sap))

    miu = nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDMIU)
    miu = 240

    apdu = os.urandom(2176)
    apdu = struct.pack(">H", len(apdu)) + apdu
    log.info("send long message")
    for i in range(0, len(apdu), miu):
        nfc.llcp.send(socket, str(apdu[i:i+miu]))

    sent_apdu = apdu
    
    data = nfc.llcp.recv(socket)
    size = struct.unpack(">H", data[0:2])[0]
    apdu = data[2:]
    while len(apdu) < size:
        data = nfc.llcp.recv(socket)
        if data == None: break
        log.info("rcvd {0} byte data".format(len(data)))
        apdu += data
    log.info("rcvd {0} byte apdu".format(len(apdu)))

    rcvd_apdu = apdu
    if rcvd_apdu != sent_apdu[::-1]:
        log.error("received data does not equal sent data")
        
    socket.close()
    
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", dest="quiet", action="store_true",
        help="do not print any log messages'")
    parser.add_argument(
        "-d", metavar="MODULE", dest="debug", action="append",
        help="print debug messages for MODULE, use '' for all")
    parser.add_argument(
        "-f", dest="logfile", metavar="FILE",
        help="write log messages to file")
    parser.add_argument(
        "-l", "--loop", action='store_true',
        help="repeat command until Control-C")
    parser.add_argument(
        "--no-wait", action='store_true',
        help="do not wait for tag removal")
    parser.add_argument(
        "--device", metavar="NAME", action="append",
        help="use specified contactless reader(s): "\
            "usb[:vendor[:product]] (vendor and product in hex), "\
            "usb[:bus[:dev]] (bus and device number in decimal), "\
            "tty[:(usb|com)[:port]] (usb virtual or com port)")

    parser.add_argument(
        "-t", "--test", type=int, metavar="N", default=1,
        help="run test number N")

    subparsers = parser.add_subparsers(title="commands", dest="subparser")
    sp = subparsers.add_parser('tag', help='run phdc tag agent')
    sp.set_defaults(func=phdc_tag_agent)
    sp = subparsers.add_parser('p2p', help='run phdc p2p agent')
    sp.set_defaults(func=phdc_p2p_agent)

    options = parser.parse_args()

    logformat = '%(message)s'
    verbosity = logging.ERROR if options.quiet else logging.INFO
        
    if options.debug:
        logformat = '%(levelname)-5s [%(name)s] %(message)s'
        if '' in options.debug:
            verbosity = logging.DEBUG
        
    logging.basicConfig(level=verbosity, format=logformat)

    if options.debug and 'nfc' in options.debug:
        verbosity = logging.DEBUG
            
    if options.logfile:
        logfile_format = \
            '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    nfcpy_path = os.path.dirname(inspect.getfile(nfc))
    for name in os.listdir(nfcpy_path):
        if os.path.isdir(os.path.join(nfcpy_path, name)):
            logging.getLogger("nfc."+name).setLevel(verbosity)
        elif name.endswith(".py") and name != "__init__.py":
            logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)

    if options.debug:
        for module in options.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)

    if options.device is None:
        options.device = ['']
            
    for device in options.device:
        try:
            options.clf = nfc.ContactlessFrontend(device);
            break
        except LookupError:
            pass
    else:
        log.warning("no contactless reader")
        raise SystemExit(1)

    try:
        while True:
            log.info("waiting for agent")
            options.func(options)
            if not options.loop:
                break
    except KeyboardInterrupt:
        raise SystemExit
    finally:
        options.clf.close()
    
