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
import argparse

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.ndef

tt3_card_map = {
    "\x00\xF0": "FeliCa Lite RC-S965",
    "\x00\xF1": "FeliCa Lite-S RC-S966",
    "\x01\xE0": "FeliCa Plug RC-S801/RC-S802",
    "\x01\x20": "FeliCa Card RC-S962 [424 kbps, 4KB FRAM]",
    "\x03\x01": "FeliCa Card RC-S860 [212 kbps, 4KB FEPROM]",
    "\x0f\x0d": "FeliCa Card RC-S889 [424 kbps, 9KB FRAM]",
    }

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

def tt3_determine_block_count(tag):
    block = 0
    try:
        while True:
            data = tag.read([block], 9)
            block += 1
    except Exception:
        if tag.pmm[0:2] == "\x00\xF0":
            block -= 1 # last block on FeliCa Lite is unusable
        return block

def tt3_determine_block_read_once_count(tag, block_count):
    try:
        for i in range(block_count):
            tag.read(range(i+1))
        else:
            return block_count
    except Exception:
        return i

def tt3_determine_block_write_once_count(tag, block_count):
    try:
        for i in range(block_count):
            data = tag.read(range(i+1))
            tag.write(data, range(i+1))
        else:
            return block_count
    except Exception:
        return i

#
# command parsers
#
def add_show_parser(parser):
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="show more tag information")

def add_dump_parser(parser):
    parser.add_argument(
        "-o", dest="output", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save ndef to FILE (writes binary data)")
        
def add_load_parser(parser):
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        help="ndef data file ('-' reads from stdin)")
        
def add_format_parser(parser):
    subparsers = parser.add_subparsers(title="tags")
    add_format_tt3_parser(subparsers.add_parser(
            'tt3', help='format type 3 tag'))

def add_format_tt3_parser(parser):
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
        
def add_emulate_parser(parser):
    parser.description = "Emulate an ndef tag."    
    parser.add_argument(
        "-s", dest="size", type=int, default="1024",
        help="ndef data area size (default: %(default)s)")
    subparsers = parser.add_subparsers(dest="tagtype")
    add_emulate_tt3_parser(subparsers.add_parser(
            'tt3', help='emulate a type 3 tag'))
    
def add_emulate_tt3_parser(parser):
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
        "--bitrate", choices=["212", "424"], default="212",
        help="bitrate to listen (default: %(default)s)")
    parser.add_argument(
        "-s", dest="size", type=int, default="1024",
        help="ndef data area size (default: %(default)s)")
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        nargs="?", default=None,
        help="ndef message to serve ('-' reads from stdin)")
    
def emulate_tt3_prepare(options):
    if options.size % 16 != 0:
        options.size = ((options.size + 15) // 16) * 16
        log.warning("ndef data area size rounded to {0}".format(options.size))
    
    try: options.data
    except AttributeError:
        if options.input:
            options.data = options.input.read()
            try: options.data = options.data.decode("hex")
            except TypeError: pass
        else:
            options.data = ""
    
    if options.input:
        options.ndef_data_area = bytearray(16) + bytearray(options.data) + \
            bytearray(max(0, options.size - len(options.data)))
    else:
        options.ndef_data_area = bytearray(16 + options.size)

    # set attribute data
    attr = nfc.tag.tt3.NdefAttributeData()
    attr.version = "1.0"
    attr.nbr, attr.nbw = (12, 8)
    attr.capacity = len(options.ndef_data_area) - 16
    attr.writeable = True
    attr.length = len(options.data)
    options.ndef_data_area[0:16] = str(attr)
    
    idm = bytearray.fromhex(options.idm)
    pmm = bytearray.fromhex(options.pmm)
    sys = bytearray.fromhex(options.sys)
    return nfc.clf.TTF(options.bitrate, idm, pmm, sys)

def emulate_tt3(tag, command, options):
    def ndef_read(block_number, rb, re):
        log.debug("tt3 read block #{0}".format(block_number))
        if block_number < len(options.ndef_data_area) / 16:
            first, last = block_number*16, (block_number+1)*16
            block_data = options.ndef_data_area[first:last]
            return block_data
    def ndef_write(block_number, block_data, wb, we):
        log.debug("tt3 write block #{0}".format(block_number))
        if block_number < len(ndef_data_area) / 16:
            first, last = block_number*16, (block_number+1)*16
            options.ndef_data_area[firs:last] = block_data
            return True

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

class TagTool(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="")
        subparsers = parser.add_subparsers(
            title="commands", dest="command")
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

        super(TagTool, self).__init__(
            parser, groups="rdwr card dbg clf")

    def on_rdwr_startup(self, clf, targets):
        if self.options.command in ("show", "dump", "load", "format"):
            log.info("touch a tag")
            return targets

    def on_rdwr_connect(self, tag):
        commands = {"show": self.show_tag, "dump": self.dump_tag,
                    "load": self.load_tag, "format": self.format_tag}
        commands[self.options.command](tag)
        return self.options.wait
    
    def on_card_startup(self, clf, targets):
        if self.options.command == "emulate":
            log.info("touch a reader")
            if self.options.tagtype == "tt3":
                target = emulate_tt3_prepare(self.options)
                return [target]

    def on_card_connect(self, tag, command):
        log.info("tag activated")
        self.options.func(tag, command, self.options)
        log.info("tag released")
        return self.options.wait

    def show_tag(self, tag):
        print(tag)
        if self.options.verbose:
            if tag.type == "Type1Tag":
                memory_dump = tag[0:8+tag[10]*8]
                print("TAG memory dump:")
                print(format_data(memory_dump, w=8))
            elif tag.type == "Type2Tag":
                memory_dump = tag[0:16+tag[14]*8]
                print("TAG memory dump:")
                print(format_data(memory_dump))
            elif tag.type == "Type3Tag":
                icc = str(tag.pmm[0:2]) # ic code
                print("  " + tt3_card_map.get(icc, "unknown card"))
        if tag.ndef:
            print("NDEF attribute data:")
            if self.options.verbose and tag.type == "Type3Tag":
                attr = ["{0:02x}".format(b) for b in tag.ndef.attr]
                print("  " + " ".join(attr))
            print("  version   = %s" % tag.ndef.version)
            print("  writeable = %s" % ("no", "yes")[tag.ndef.writeable])
            print("  capacity  = %d byte" % tag.ndef.capacity)
            print("  data size = %d byte" % len(tag.ndef.message))
            if len(tag.ndef.message):
                if self.options.verbose:
                    print("NDEF message dump:")
                    print(format_data(tag.ndef.message))
                message = nfc.ndef.Message(tag.ndef.message)
                print("NDEF record list:")
                print(message.pretty())

    def dump_tag(self, tag):
        if tag.ndef:
            data = tag.ndef.message
            if self.options.output.name == "<stdout>":
                self.options.output.write(str(data).encode("hex"))
                if self.options.loop:
                    self.options.output.write('\n')
                else:
                    self.options.output.flush()
            else:
                self.options.output.write(str(data))

    def load_tag(self, tag):
        try: selfoptions.data
        except AttributeError:
            self.self.options.data = self.options.input.read()
            try: self.options.data = self.options.data.decode("hex")
            except TypeError: pass

        if tag.ndef is not None:
            log.info("old: " + tag.ndef.message.encode("hex"))
            tag.ndef.message = args.data
            log.info("new: " + tag.ndef.message.encode("hex"))
        else:
            log.info("not an ndef tag")

    def format_tag(self, tag):
        if self.options.tagtype == "tt3":
            self.format_tt3_tag(tag)

    def format_tt3_tag(self, tag):
        block_count = tt3_determine_block_count(tag)
        print("tag has %d user data blocks" % block_count)
        nbr = tt3_determine_block_read_once_count(tag, block_count)
        print("%d block(s) can be read at once" % nbr)
        nbw = tt3_determine_block_write_once_count(tag, block_count)
        print("%d block(s) can be written at once" % nbw)

        if self.options.max is not None:
            block_count = self.options.max + 1
        if self.options.nbw is not None:
            nbw = self.options.nbw
        if self.options.nbr is not None:
            nbr = self.options.nbr
        rfu = self.options.rfu
        wf = self.options.wf
        rw = self.options.rw
        ver = map(int, self.options.ver.split('.'))
        ver = ver[0] << 4 | ver[1]

        nmaxb_msb = (block_count - 1) / 256
        nmaxb_lsb = (block_count - 1) % 256
        attr = bytearray([ver, nbr, nbw, nmaxb_msb, nmaxb_lsb, 
                          rfu, rfu, rfu, rfu, wf, rw, 0, 0, 0, 0, 0])
        attr[11:14] = bytearray(struct.pack('!I', self.options.len)[1:])
        csum = sum(attr[0:14]) if self.options.crc is None else self.options.crc
        attr[14] = csum / 256
        attr[15] = csum % 256

        log.info("writing attribute data block:")
        log.info(" ".join(["%02x" % x for x in attr]))
        log.info("  Ver = {0}".format(self.options.ver))
        log.info("  Nbr = {0}".format(nbr))
        log.info("  Nbw = {0}".format(nbw))
        log.info("  WF  = {0}".format(wf))
        log.info("  RW  = {0}".format(rw))
        log.info("  Ln  = {0}".format(self.options.len))
        log.info("  CRC = {0}".format(csum))

        tag.write(str(attr), [0])

if __name__ == '__main__':
    TagTool().run()
