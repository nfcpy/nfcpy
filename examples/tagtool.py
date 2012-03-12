#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
import signal

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef

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

def show(tag):
    print tag
    if isinstance(tag, nfc.Type3Tag):
        tt3_card_map = {
            "\x00\xF0": "FeliCa Lite RC-S965",
            "\x01\xE0": "FeliCa Plug RC-S801/RC-S802",
            "\x01\x20": "FeliCa Card RC-S976F [212/424kbps]",
            "\x03\x01": "FeliCa Card RC-S860 [212kbps, 4KB FEPROM]",
            }
        print "  " + tt3_card_map.get(str(tag.pmm[0:2]), "unknown card type")
    if tag.ndef:
        print "NDEF content"
        print "  version   = %s" % tag.ndef.version
        print "  writeable = %s" % ("no", "yes")[tag.ndef.writeable]
        print "  capacity  = %d byte" % tag.ndef.capacity
        print "  data size = %d byte" % len(tag.ndef.message)
        if len(tag.ndef.message):
            print format_data(tag.ndef.message)
            message = nfc.ndef.Message(tag.ndef.message)
            print "NDEF records"
            for index, record in enumerate(message):
                record.data = make_printable(record.data)
                print "  [%d] type = %s" %(index, record.type)
                print "  [%d] name = %s" %(index, record.name)
                print "  [%d] data = %s" %(index, record.data)

def format_tag(clf):
    while True:
        tag = poll(clf)
        if tag:
            if isinstance(tag, nfc.Type1Tag):
                tt1_format(tag)
            if isinstance(tag, nfc.Type2Tag):
                print "unable to format {0}".format(str(tag))
            if isinstance(tag, nfc.Type3Tag):
                tt3_format(tag)
            if options.loopmode:
                while tag.is_present:
                    time.sleep(1)
            else: break
        else: break

def tt1_format(tag):
    # fixme: this is only correct for 120 byte tags
    # but there aren't any larger I know of
    with tag:
        tag[0x08] = 0xE1
        tag[0x09] = 0x10
        tag[0x0A] = 0x0E
        tag[0x0B] = 0x00
        tag[0x0C] = 0x03
        tag[0x0D] = 0x00
    
def tt3_format(tag):
    def determine_block_count(tag):
        block = 0
        try:
            while True:
                data = tag.read([block], 9)
                block += 1
        except Exception:
            if tag.pmm[0:2] == "\x00\xF0":
                block -= 1 # last block on FeliCa Lite is unusable
            return block

    def determine_block_read_count(tag, block_count):
        try:
            for i in range(block_count):
                tag.read(range(i+1))
        except Exception: return i

    def determine_block_write_count(tag, block_count):
        try:
            for i in range(block_count):
                data = ((i+1)*16) * "\x00"
                tag.write(data, range(i+1))
        except Exception: return i

    block_count = determine_block_count(tag)
    print "tag has %d user data blocks" % block_count

    nbr = determine_block_read_count(tag, block_count)
    print "%d block(s) can be read at once" % nbr

    nbw = determine_block_write_count(tag, block_count)
    print "%d block(s) can be written at once" % nbw

    nmaxb_msb = (block_count - 1) / 256
    nmaxb_lsb = (block_count - 1) % 256
    attr = [0x10, nbr, nbw, nmaxb_msb, nmaxb_lsb, 
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
    csum = sum(attr[0:14])
    attr[14] = csum / 256
    attr[15] = csum % 256

    print "writing attribute data block:"
    print " ".join(["%02x" % x for x in attr])

    attr = ''.join([chr(b) for b in attr])
    tag.write(attr, [0])

def copy_tag(clf):
    tag = poll(clf)
    if tag and tag.ndef:
        data = tag.ndef.message
        print "copied {0} byte <= {1}".format(len(data), tag)
        while True:
            while tag.is_present:
                time.sleep(1)
            tag = poll(clf)
            if tag is None:
                return
            if tag.ndef:
                tag.ndef.message = data
                print "copied {0} byte => {1}".format(len(data), tag)
            else:
                print "not an ndef tag: {0}".format(tag)
            if not options.loopmode:
                break

def dump_tag(clf):
    while True:
        tag = poll(clf)
        if tag:
            if tag.ndef:
                data = tag.ndef.message
                if options.binary:
                    sys.stdout.write(data)
                    sys.stdout.flush()
                else:
                    print data.encode("hex")
                if not options.loopmode:
                    break
            while tag.is_present:
                time.sleep(1)
        else: break

def load_tag(clf):
    if not options.binary:
        data = sys.stdin.readlines()
        data = ''.join([l.strip() for l in data])
        data = data.decode("hex")
    else:
        data = sys.stdin.read()
    while True:
        tag = poll(clf)
        if tag:
            if tag.ndef:
                tag.ndef.message = data
                print data.encode("hex")
                if not options.loopmode:
                    break
            while tag.is_present:
                time.sleep(1)
        else: break

def poll(clf):
    try:
        while True:
            tag = clf.poll()
            if tag: return tag
            else: time.sleep(0.5)
    except KeyboardInterrupt:
        return None

def sigint_handler(signum, frame):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise KeyboardInterrupt

def main():
    signal.signal(signal.SIGINT, sigint_handler)
    
    # find and initialize an NFC reader
    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return
    
    try:
        if options.command == "show":
            while True:
                tag = poll(clf)
                if tag:
                    show(tag)
                    if options.loopmode:
                        while tag.is_present:
                            time.sleep(1)
                    else: break
                else: break
        elif options.command == "format":
            format_tag(clf)
        elif options.command == "copy":
            copy_tag(clf)
        elif options.command == "dump":
            dump_tag(clf)
        elif options.command == "load":
            load_tag(clf)
        else:
            log.error("unknown command '{0}'".format(options.command))
    except KeyboardInterrupt:
        print
    finally:
        clf.close()

if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup

    usage = ["Usage: %prog [options] command\n",
             "Commands:",
             "  show   - pretty print NDEF data",
             "  dump   - print NDEF data to stdout",
             "  load   - write NDEF data from stdin",
             "  copy   - copy NDEF data between tags",
             "  format - format NDEF partition on tag"]

    parser = OptionParser('\n'.join(usage), version="%prog 0.1")
    parser.add_option("-l", default=False,
                      action="store_true", dest="loopmode",
                      help="run command in loop mode")
    parser.add_option("-b", default=False,
                      action="store_true", dest="binary",
                      help="use binary format for dump/load")
    parser.add_option("-q", default=True,
                      action="store_false", dest="verbose",
                      help="be quiet, only print errors")
    parser.add_option("-d", default=False,
                      action="store_true", dest="debug",
                      help="print debug messages")
    parser.add_option("-f", type="string",
                      action="store", dest="logfile",
                      help="write log messages to LOGFILE")
    parser.add_option("--device", type="string", default=[],
                      action="append", dest="device", metavar="SPEC",
                      help="use only device(s) according to SPEC: "\
                          "usb[:vendor[:product]] (vendor and product in hex) "\
                          "usb[:bus[:dev]] (bus and device number in decimal) "\
                          "tty[:(usb|com)[:port]] (usb virtual or com port)")

    global options
    options, args = parser.parse_args()
    if len(args) > 0: options.command = args[0]
    else: options.command = "show"

    verbosity = logging.INFO if options.verbose else logging.ERROR
    verbosity = logging.DEBUG if options.debug else verbosity
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    if len(options.device) == 0:
        # search and use first
        options.device = ["",]
        
    main()

