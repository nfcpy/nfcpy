#!/usr/bin/python
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
from __future__ import print_function

import logging
log = logging.getLogger()

import os
import sys
import time
import string
import struct

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.tag
import nfc.ndef

def format_data(data, w=16):
    printable = string.digits + string.letters + string.punctuation + ' '
    if type(data) is not type(str()):
        data = str(data)
    s = []
    for i in range(0, len(data), w):
        s.append("  {offset:04x}: ".format(offset=i))
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+w]]) + ' '
        s[-1] += (8 + w*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+w]])
    return '\n'.join(s)

def add_show_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=show_tag)
        
def show_tag(args):
    def show(tag):
        print(tag)
        if args.verbose:
            if tag.type == "Type1Tag":
                memory_dump = tag[0:8+tag[10]*8]
                print("TAG memory dump:")
                print(format_data(memory_dump, w=8))
            elif tag.type == "Type2Tag":
                memory_dump = tag[0:16+tag[14]*8]
                print("TAG memory dump:")
                print(format_data(memory_dump))
            elif tag.type == "Type3Tag":
                tt3_card_map = {
                    "\x00\xF0": "FeliCa Lite RC-S965",
                    "\x00\xF1": "FeliCa Lite-S RC-S966",
                    "\x01\xE0": "FeliCa Plug RC-S801/RC-S802",
                    "\x01\x20": "FeliCa Card RC-S962 [424 kbps, 4KB FRAM]",
                    "\x03\x01": "FeliCa Card RC-S860 [212 kbps, 4KB FEPROM]",
                    "\x0f\x0d": "FeliCa Card RC-S889 [424 kbps, 9KB FRAM]",
                    }
                icc = str(tag.pmm[0:2]) # ic code
                print("  " + tt3_card_map.get(icc, "unknown card"))
        if tag.ndef:
            print("NDEF attribute data:")
            if args.verbose and tag.type == "Type3Tag":
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

        return args.wait or args.loop
        
    log.info("touch a tag")
    while args.clf.connect(tag={'on-connect': show}) and args.loop:
        log.info("touch a tag")

def add_dump_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=dump_tag)
    parser.add_argument(
        "-o", dest="output", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save ndef to FILE (writes binary data)")
        
def dump_tag(args):
    def dump(tag):
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
        return args.wait or args.loop
        
    log.info("touch a tag")
    while args.clf.connect(tag={'on-connect': dump}) and args.loop:
        log.info("touch a tag")

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
    
    def load(tag):
        if tag.ndef is not None:
            log.info("old: " + tag.ndef.message.encode("hex"))
            tag.ndef.message = args.data
            log.info("new: " + tag.ndef.message.encode("hex"))
        else:
            log.info("not an ndef tag")
        return args.wait or args.loop
        
    log.info("touch a tag")
    while args.clf.connect(tag={'on-connect': load}) and args.loop:
        log.info("touch a tag")

def add_format_parser(parser):
    subparsers = parser.add_subparsers(title="tags")
    add_format_tt3_parser(subparsers.add_parser(
            'tt3', help='format type 3 tag'))

def add_format_tt3_parser(parser):
    #parser.description = ""
    parser.set_defaults(func=tt3_format)
    parser.add_argument(
        "--ver", metavar="STR", default="1.0",
        help="ndef mapping version number (default: %(default)s)")
    parser.add_argument(
        "--nbr", metavar="INT", type=int,
        help="number of blocks that can be written at once")
    parser.add_argument(
        "--nbw", metavar="INT", type=int,
        help="number of blocks that can be read at once")
    parser.add_argument(
        "--max", metavar="INT", type=int,
        help="maximum number of blocks (nmaxb x 16 == capacity)")
    parser.add_argument(
        "--rfu", metavar="INT", type=int, default=0,
        help="value to set for reserved bytes (default: %(default)s)")
    parser.add_argument(
        "--wf", metavar="INT", type=int, default=0,
        help="write-flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--rw", metavar="INT", type=int, default=1,
        help="read-write flag attribute value (default: %(default)s)")
    parser.add_argument(
        "--len", metavar="INT", type=int, default=0,
        help="ndef length attribute value (default: %(default)s)")
    parser.add_argument(
        "--crc", metavar="INT", type=int,
        help="checksum attribute value (default: computed)")
        
def tt3_format(args):
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

    def format(tag):
        block_count = determine_block_count(tag)
        print("tag has %d user data blocks" % block_count)

        nbr = determine_block_read_count(tag, block_count)
        print("%d block(s) can be read at once" % nbr)

        nbw = determine_block_write_count(tag, block_count)
        print("%d block(s) can be written at once" % nbw)

        if not args.max is None:
            block_count = args.max + 1
        if not args.nbw is None:
            nbw = args.nbw
        if not args.nbr is None:
            nbr = args.nbr
        rfu = args.rfu
        wf = args.wf
        rw = args.rw
        ver = map(int, args.ver.split('.'))
        ver = ver[0] << 4 | ver[1]

        nmaxb_msb = (block_count - 1) / 256
        nmaxb_lsb = (block_count - 1) % 256
        attr = bytearray([ver, nbr, nbw, nmaxb_msb, nmaxb_lsb, 
                          rfu, rfu, rfu, rfu, wf, rw, 0, 0, 0, 0, 0])
        attr[11:14] = bytearray(struct.pack('!I', args.len)[1:])
        csum = sum(attr[0:14]) if args.crc is None else args.crc
        attr[14] = csum / 256
        attr[15] = csum % 256

        log.info("writing attribute data block:")
        log.info(" ".join(["%02x" % x for x in attr]))
        log.info("  Ver = {0}".format(args.ver))
        log.info("  Nbr = {0}".format(nbr))
        log.info("  Nbw = {0}".format(nbw))
        log.info("  WF  = {0}".format(wf))
        log.info("  RW  = {0}".format(rw))
        log.info("  Ln  = {0}".format(args.len))
        log.info("  CRC = {0}".format(csum))

        tag.write(str(attr), [0])
        return args.wait or args.loop
        
    log.info("touch a type 3 tag to format")
    while args.clf.connect(tag={'on-connect': format}) and args.loop:
        log.info("touch a type 3 tag to format")

def add_emulate_parser(parser):
    parser.description = """Emulate an ndef tag."""    
    subparsers = parser.add_subparsers()
    emulate_tt3_parser(subparsers.add_parser(
            'tt3', help='emulate a type 3 tag'))
    
def emulate_tt3_parser(parser):
    parser.set_defaults(func=emulate_tt3)
    parser.add_argument(
        "--idm", metavar="HEX", default="03FEFFE011223344",
        help="manufacture identifier (default: %(default)s)")
    parser.add_argument(
        "--pmm", metavar="HEX", default="01E0000000FFFF00",
        help="manufacture parameter (default: %(default)s)")
    parser.add_argument(
        "--sys", "--sc", metavar="HEX", default="12FC",
        help="system code (default: %(default)s)")
    parser.add_argument(
        "--br", choices=["212", "424"], default="212",
        help="baud rate (default: %(default)s)")
    parser.add_argument(
        "-s", dest="size", type=int, default="1024",
        help="ndef data area size (default: %(default)s)")
#    parser.add_argument(
#        "-c", dest="continue", action="store_true",
#        help="continue to listen after tag release")
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        nargs="?", default=None,
        help="ndef message to serve ('-' reads from stdin)")
    
def emulate_tt3(args):
    if args.size % 16 != 0:
        args.size = ((args.size + 15) // 16) * 16
        log.warning("ndef data area size rounded to {0}".format(args.size))
    
    try: args.data
    except AttributeError:
        if args.input:
            args.data = args.input.read()
            try: args.data = args.data.decode("hex")
            except TypeError: pass
        else:
            args.data = ""
    
    if args.input:
        ndef_data_area = bytearray(16) + bytearray(args.data) + \
            bytearray(max(0, args.size - len(args.data)))
    else:
        ndef_data_area = bytearray(16 + args.size)

    # set attribute data
    attr = nfc.tt3.NdefAttributeData()
    attr.version = "1.0"
    attr.nbr, attr.nbw = 12, 8
    attr.capacity = len(ndef_data_area) - 16
    attr.writeable = True
    attr.length = len(args.data)
    ndef_data_area[0:16] = str(attr)
    
    def ndef_read(block_number, rb, re):
        log.debug("tt3 read block #{0}".format(block_number))
        if block_number < len(ndef_data_area) / 16:
            block_data = ndef_data_area[block_number*16:(block_number+1)*16]
            return block_data
    def ndef_write(block_number, block_data, wb, we):
        log.debug("tt3 write block #{0}".format(block_number))
        if block_number < len(ndef_data_area) / 16:
            ndef_data_area[block_number*16:(block_number+1)*16] = block_data
            return True

    idm = bytearray.fromhex(args.idm)
    pmm = bytearray.fromhex(args.pmm)
    sys = bytearray.fromhex(args.sys)
    target = nfc.clf.TTF(br=args.br, idm=idm, pmm=pmm, sys=sys)
    try:
        log.info("touch a reader")
        while True:
            activated = args.clf.listen([target], timeout=1)
            if activated:
                log.info("tag activated")
                target, command = activated
                tag = nfc.tt3.Type3TagEmulation(args.clf, target)
                tag.add_service(0x0009, ndef_read, ndef_write)
                tag.add_service(0x000B, ndef_read, lambda: False)
                while command is not None:
                    response = tag.process_command(command)
                    try:
                        command = tag.send_response(response, timeout=10)
                    except nfc.clf.TimeoutError:
                        log.info("no command received within 10 seconds")
                    except nfc.clf.TransmissionError:
                        break
                log.info("tag released")
                if not args.loop: break
                log.info("touch a reader")
    except KeyboardInterrupt:
        return

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q", dest="quiet", action="store_true",
        help="print minimum information'")
    parser.add_argument(
        "-v", dest="verbose", action="store_true",
        help="print verbose information'")
    parser.add_argument(
        "-d", dest="debug", action="store_true",
        help="print debug log messages")
    parser.add_argument(
        "-l", "--loop", action='store_true',
        help="repeat command until Control-C")
    parser.add_argument(
        "--wait", action='store_true',
        help="wait until tag is removed")
    parser.add_argument(
        "--device", metavar="NAME", action="append",
        help="use specified contactless reader(s): "\
            "usb[:vendor[:product]] (vendor and product in hex), "\
            "usb[:bus[:dev]] (bus and device number in decimal), "\
            "tty[:(usb|com)[:port]] (usb virtual or com port)")

    subparsers = parser.add_subparsers(title="commands", dest="subparser")
    add_show_parser(subparsers.add_parser(
            'show', help='pretty print ndef data'))
    add_dump_parser(subparsers.add_parser(
            'dump', help='read ndef data from tag'))
    add_load_parser(subparsers.add_parser(
            'load', help='write ndef data to tag'))
    add_format_parser(subparsers.add_parser(
            'format', help='format ndef tag'))
    add_emulate_parser(subparsers.add_parser(
            'emulate', help='emulate ndef tag'))

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
        
    logging.basicConfig(level=log_level,
                        format='%(asctime)s %(message)s')

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
        args.func(args)
    finally:
        args.clf.close()
    
