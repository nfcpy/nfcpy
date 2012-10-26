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

class PhdcAgent(threading.Thread):
    def __init__(self):
        super(PhdcAgent, self).__init__()
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

class PhdcTagAgent(PhdcAgent):
    def __init__(self, tag, apdu=bytearray()):
        super(PhdcTagAgent, self).__init__()
        self.mc = 1
        attr = nfc.tt3.NdefAttributeData()
        attr.version = "1.0"
        attr.nbr, attr.nbw = 12, 8
        attr.capacity = 1024
        attr.writeable = True
        attr.length = 7 + len(apdu)
    
        phd_rec = nfc.ndef.Record("urn:nfc:wkt:PHD", data="\x00" + apdu)
        phd_msg = nfc.ndef.Message(phd_rec)
        
        self.ndef_data_area = str(attr) + bytearray(attr.capacity)
        self.ndef_data_area[16:16+7+len(apdu)] = bytearray(str(phd_msg))

        tag.add_service(0x0009, self.ndef_read, self.ndef_write)
        tag.add_service(0x000B, self.ndef_read, lambda: False)
        self.tag = tag
        
        self.ndef_read_lock = threading.Lock()
        self.ndef_write_lock = threading.Lock()

    def ndef_read(self, block, read_begin, read_end):
        print "read_begin = {0} read_end = {1}".format(read_begin, read_end)
        if read_begin is True:
            self.ndef_read_lock.acquire()
        try:
            log.info("tt3 read block #{0}".format(block))
            if block < len(self.ndef_data_area) / 16:
                return self.ndef_data_area[block*16:(block+1)*16]
        finally:
            if read_end is True:
                self.ndef_read_lock.release()
        
    def ndef_write(self, block, data, write_begin, write_end):
        if write_begin is True:
            self.ndef_write_lock.acquire()
        try:
            log.info("tt3 write block #{0}".format(block))
            if block < len(self.ndef_data_area) / 16:
                self.ndef_data_area[block*16:(block+1)*16] = data
                return True
        finally:
            if write_end is True:
                self.ndef_write_lock.release()
            
    @trace
    def read_phd_message(self, timeout):
        t0 = time.time()
        while True:
            message = None
            time.sleep(0.1)
            with self.ndef_write_lock:
                #print str(self.ndef_data_area[0:16]).encode("hex")
                #print str(self.ndef_data_area[16:32]).encode("hex")
                attr = nfc.tt3.NdefAttributeData(self.ndef_data_area[0:16])
                if attr.length > 0 and not attr.writing:
                    try:
                        message = nfc.ndef.Message(
                            self.ndef_data_area[16:16+attr.length])
                    except nfc.ndef.LengthError:
                        pass
                
            if message and message.type == "urn:nfc:wkt:PHD":
                data = bytearray(message[0].data)
                if data[0] & 0x0F == (self.mc % 4) << 2 | 2:
                    log.info("[phdc] <<< {0:2d} {1}"
                             .format(self.mc % 16, str(data).encode("hex")))
                    self.mc += 1
                    return data[1:]
                    
            if int((time.time() - t0) * 1000) > timeout:
                return None
                    
    @trace
    def write_phd_message(self, apdu):
        data = bytearray([(self.mc % 4) << 2 | 2]) + apdu
        record = nfc.ndef.Record("urn:nfc:wkt:PHD", data=str(data))
        with self.ndef_read_lock:
            log.info("[phdc] >>> {0:2d} {1}"
                     .format(self.mc % 16, str(data).encode("hex")))
            data = bytearray(str(nfc.ndef.Message(record)))
            attr = nfc.tt3.NdefAttributeData(self.ndef_data_area[0:16])
            attr.length = len(data)
            self.ndef_data_area[0:16+attr.length] = str(attr) + data
            self.mc += 1
        
    def run(self):
        log.info("entering phdc agent run loop")
        for i in range(10):
            try:
                self.enqueue(self.read_phd_message(timeout=1000))
            except IOError:
                self.enqueue(None)
                break
            try:
                self.write_phd_message(self.dequeue())
            except IOError:
                break
        log.info("leaving phdc agent run loop")
        

def phdc_tag_agent(args):
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
            threading.Thread(target=agent.tag.serve, args=(5000,)).start()
            agent.start()
            log.info("entering ieee agent")
            for i in range(1):
                apdu = agent.recv(timeout=5.0)
                if apdu is None: break
                log.info("[ieee] <<< {0}".format(str(apdu).encode("hex")))
                apdu = apdu[::-1]
                #time.sleep(0.2)
                log.info("[ieee] >>> {0}".format(str(apdu).encode("hex")))
                agent.send(apdu)
            log.info("leaving ieee agent")
            break
        
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
            phdc_tag_agent(options)
            if not options.loop:
                break
    except KeyboardInterrupt:
        raise SystemExit
    finally:
        options.clf.close()
    
