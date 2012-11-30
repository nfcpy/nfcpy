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
import struct

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef

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

def add_show_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=show_tag)
        
def show_tag(args):
    tag = poll(args.clf)
    if tag is None:
        raise SystemExit(1)

    print(tag)
    if isinstance(tag, nfc.Type3Tag):
        tt3_card_map = {
            "\x00\xF0": "FeliCa Lite RC-S965",
            "\x00\xF1": "FeliCa Lite-S RC-S966",
            "\x01\xE0": "FeliCa Plug RC-S801/RC-S802",
            "\x01\x20": "FeliCa Card RC-S976F [424 kbps]",
            "\x03\x01": "FeliCa Card RC-S860 [212 kbps, 4KB FEPROM]",
            "\x0f\x0d": "FeliCa Card RC-S889 [424 kbps, 9KB FRAM]",
            }
        print("  " + tt3_card_map.get(str(tag.pmm[0:2]), "unknown card"))
    if tag.ndef:
        print("NDEF attribute data:")
        if isinstance(tag, nfc.Type3Tag):
            attr = ["{0:02x}".format(b) for b in tag.ndef.attr]
            print("  " + " ".join(attr))
        print("  version   = %s" % tag.ndef.version)
        print("  writeable = %s" % ("no", "yes")[tag.ndef.writeable])
        print("  capacity  = %d byte" % tag.ndef.capacity)
        print("  data size = %d byte" % len(tag.ndef.message))
        if len(tag.ndef.message):
            print("NDEF message dump:")
            print(format_data(tag.ndef.message))
            message = nfc.ndef.Message(tag.ndef.message)
            print("NDEF record list:")
            print(message.pretty())
    return tag
        
def add_dump_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=dump_tag)
    parser.add_argument(
        "-o", dest="output", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save ndef to FILE (writes binary data)")
        
def dump_tag(args):
    tag = poll(args.clf)
    if tag is None:
        raise SystemExit(1)

    if tag.ndef:
        data = tag.ndef.message
        if args.output.name == "<stdout>":
            args.output.write(str(data).encode("hex"))
            if args.loop:
                args.output.write('\n')
            else:
                args.output.flush()
        else:
            args.output.write(str(data))                    

    return tag

def add_load_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=load_tag)
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        help="ndef data file ('-' reads from stdin)")
        
def load_tag(args):
    try: args.data
    except AttributeError:
        args.data = args.input.read()
        try: args.data = args.data.decode("hex")
        except TypeError: pass
    
    tag = poll(args.clf)
    if tag is None:
        raise SystemExit(1)

    if tag.ndef:
        log.info("old: " + tag.ndef.message.encode("hex"))
        tag.ndef.message = args.data
        log.info("new: " + args.data.encode("hex"))
    else:
        log.info("not an ndef tag")

    return tag

def add_format_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=format_tag)
    parser.add_argument(
        "--tt3-ver", metavar="STR", default="1.0",
        help="ndef mapping version number (default: %(default)s)")
    parser.add_argument(
        "--tt3-nbr", metavar="INT", type=int,
        help="number of blocks that can be written at once")
    parser.add_argument(
        "--tt3-nbw", metavar="INT", type=int,
        help="number of blocks that can be read at once")
    parser.add_argument(
        "--tt3-max", metavar="INT", type=int,
        help="maximum number of blocks (nmaxb x 16 == capacity)")
    parser.add_argument(
        "--tt3-rfu", metavar="INT", type=int, default=0,
        help="value to set for reserved bytes (default: %(default)s)")
    parser.add_argument(
        "--tt3-wf", metavar="INT", type=int, default=0,
        help="write-flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--tt3-rw", metavar="INT", type=int, default=1,
        help="read-write flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--tt3-len", metavar="INT", type=int, default=0,
        help="ndef length attribute value (default: %(default)s)")
    parser.add_argument(
        "--tt3-crc", metavar="INT", type=int,
        help="checksum attribute value (default: computed)")
        
def format_tag(clf):
    tag = poll(args.clf)
    if tag is None:
        raise SystemExit(1)

    if isinstance(tag, nfc.Type1Tag):
        tt1_format(tag)
    elif isinstance(tag, nfc.Type2Tag):
        print("unable to format {0}".format(str(tag)))
    elif isinstance(tag, nfc.Type3Tag):
        tt3_format(tag, args)
    elif isinstance(tag, nfc.Type4Tag):
        print("unable to format {0}".format(str(tag)))

    return tag

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
    
def tt3_format(tag, args):
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
            else:
                return block_count
        except Exception:
            return i

    def determine_block_write_count(tag, block_count):
        try:
            for i in range(block_count):
                data = tag.read(range(i+1))
                tag.write(data, range(i+1))
            else:
                return block_count
        except Exception:
            return i

    block_count = determine_block_count(tag)
    print("tag has %d user data blocks" % block_count)

    nbr = determine_block_read_count(tag, block_count)
    print("%d block(s) can be read at once" % nbr)

    nbw = determine_block_write_count(tag, block_count)
    print("%d block(s) can be written at once" % nbw)

    if not args.tt3_max is None:
        block_count = args.tt3_max + 1
    if not args.tt3_nbw is None:
        nbw = args.tt3_nbw
    if not args.tt3_nbr is None:
        nbr = args.tt3_nbr
    rfu = args.tt3_rfu
    wf = args.tt3_wf
    rw = args.tt3_rw
    ver = map(int, args.tt3_ver.split('.'))
    ver = ver[0] << 4 | ver[1]
        
    nmaxb_msb = (block_count - 1) / 256
    nmaxb_lsb = (block_count - 1) % 256
    attr = bytearray([ver, nbr, nbw, nmaxb_msb, nmaxb_lsb, 
                      rfu, rfu, rfu, rfu, wf, rw, 0, 0, 0, 0, 0])
    attr[11:14] = bytearray(struct.pack('!I', args.tt3_len)[1:])
    csum = sum(attr[0:14]) if args.tt3_crc is None else args.tt3_crc
    attr[14] = csum / 256
    attr[15] = csum % 256

    log.info("writing attribute data block:")
    log.info(" ".join(["%02x" % x for x in attr]))
    log.info("  Ver = {0}".format(args.tt3_ver))
    log.info("  Nbr = {0}".format(nbr))
    log.info("  Nbw = {0}".format(nbw))
    log.info("  WF  = {0}".format(wf))
    log.info("  RW  = {0}".format(rw))
    log.info("  Ln  = {0}".format(args.tt3_len))
    log.info("  CRC = {0}".format(csum))

    tag.write(str(attr), [0])

def poll(clf):
    try:
        while True:
            tag = clf.poll()
            if tag: return tag
            else: time.sleep(0.5)
    except KeyboardInterrupt:
        return None

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", dest="quiet", action="store_true",
        help="do not print any log messages'")
    parser.add_argument(
        "-d", dest="debug", action="store_true",
        help="print debug log messages")
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

    subparsers = parser.add_subparsers(title="commands")
    add_show_parser(subparsers.add_parser(
            'show', help='pretty print ndef data'))
    add_dump_parser(subparsers.add_parser(
            'dump', help='read ndef data from tag'))
    add_load_parser(subparsers.add_parser(
            'load', help='write ndef data to tag'))
    add_format_parser(subparsers.add_parser(
            'format', help='format ndef tag'))

    for argument in sys.argv[1:]:
        if not argument.startswith('-'):
            break
    else: sys.argv += ['show']
    args = parser.parse_args()

    if args.debug:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR
    else:
        log_level = logging.INFO
        
    logging.basicConfig(level=log_level, format='%(message)s')

    log.debug(args)

    if args.device is None:
        args.device = ['']
            
    for device in args.device:
        try:
            args.clf = nfc.ContactlessFrontend(device);
            break
        except LookupError:
            pass
    else:
        log.warning("no contactless reader")
        raise SystemExit(1)

    try:
        while True:
            log.info("touch a tag")
            tag = args.func(args)
            if not args.no_wait:
                log.info("\nremove tag")
                while tag.is_present:
                    time.sleep(1)
            if not args.loop:
                break
    except KeyboardInterrupt:
        raise SystemExit
    finally:
        args.clf.close()
    
    raise SystemExit
    
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

    global options
    options, args = parser.parse_args()
    if len(args) > 0: options.command = args[0]
    else: options.command = "show"

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

