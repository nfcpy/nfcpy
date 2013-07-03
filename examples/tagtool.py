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
log = logging.getLogger('main')

import os
import sys
import time
import string
import struct
import argparse

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc

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
    subparsers = parser.add_subparsers(title="Tag Types", dest="tagtype")
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
        "-l", "--loop", action="store_true",
        help="continue (restart) after tag release")
    parser.add_argument(
        "-k", "--keep", action="store_true",
        help="keep tag memory (when --loop is set)")
    parser.add_argument(
        "-s", dest="size", type=int, default="1024",
        help="ndef data area size (default: %(default)s)")
    parser.add_argument(
        "-p", dest="preserve", metavar="FILE", type=argparse.FileType('wb'),
        help="preserve tag memory when released")
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        nargs="?", default=None,
        help="ndef message to serve ('-' reads from stdin)")
    subparsers = parser.add_subparsers(title="Tag Types", dest="tagtype")
    add_emulate_tt3_parser(subparsers.add_parser(
            'tt3', help='emulate a type 3 tag'))
    
def add_emulate_tt3_parser(parser):
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

class TagTool(CommandLineInterface):
    def __init__(self):
        parser = ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="")
        parser.add_argument(
            "-v", "--verbose", action="store_true",
            help="show more information")
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
        return self.options.wait or self.options.loop
    
    def on_card_startup(self, clf, targets):
        if self.options.command == "emulate":
            target = self.prepare_tag()
            log.info("touch a reader")
            return [target]

    def on_card_connect(self, tag, command):
        log.info("tag activated")
        self.emulate_tag(tag, command)
        log.info("tag released")

    def show_tag(self, tag):
        print(tag)
        if self.options.verbose:
            if tag.type == "Type1Tag":
                memory_dump = tag[0:8+tag[10]*8]
                print("TAG memory dump:")
                print(format_data(memory_dump, w=8))
            elif tag.type == "Type2Tag":
                print("TAG memory dump:")
                try:
                    memory_dump = tag[0:16+tag[14]*8]
                    print(format_data(memory_dump))
                except nfc.clf.ProtocolError as e:
                    log.error(e)
            elif tag.type == "Type3Tag":
                icc = str(tag.pmm[0:2]) # ic code
                print("  " + tt3_card_map.get(icc, "unknown card"))
        if tag.ndef:
            print("NDEF capabilities:")
            if self.options.verbose and tag.type == "Type3Tag":
                print("  [%s]" % tag.ndef.attr.pretty())
            print("  version   = %s" % tag.ndef.version)
            print("  readable  = %s" % ("no", "yes")[tag.ndef.readable])
            print("  writeable = %s" % ("no", "yes")[tag.ndef.writeable])
            print("  capacity  = %d byte" % tag.ndef.capacity)
            print("  message   = %d byte" % tag.ndef.length)
            if self.options.verbose:
                print("NDEF message dump:")
                print(format_data(tag.ndef.message))
            print("NDEF record list:")
            print(tag.ndef.message.pretty())

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
        try: self.options.data
        except AttributeError:
            self.options.data = self.options.input.read()
            try: self.options.data = self.options.data.decode("hex")
            except TypeError: pass

        if tag.ndef is None:
            log.info("not an ndef tag")
            return

        log.info("old message: \n" + tag.ndef.message.pretty())
        try:
            tag.ndef.message = nfc.ndef.Message(self.options.data)
            if tag.ndef.changed:
                log.info("new message: \n" + tag.ndef.message.pretty())
            else:
                log.info("new message is same as old message")
        except nfc.tag.AccessError:
            log.error("this tag is not writeable")
        except nfc.tag.CapacityError:
            log.error("message exceeds tag capacity")

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
        if self.options.max is not None: block_count = self.options.max + 1
        if self.options.nbw is not None: nbw = self.options.nbw
        if self.options.nbr is not None: nbr = self.options.nbr
        
        attr = nfc.tag.tt3.NdefAttributeData()
        attr.version = self.options.ver
        attr.nbr, attr.nbw = (nbr, nbw)
        attr.capacity = (block_count - 1) * 16
        attr.rfu = 4 * [self.options.rfu]
        attr.wf = self.options.wf
        attr.writing = bool(self.options.wf)
        attr.rw = self.options.rw
        attr.writeable = bool(self.options.rw)
        attr.length = self.options.len
        attr = bytearray(str(attr))
        if self.options.crc is not None:
            attr[14:16] = (self.options.crc / 256, self.options.crc % 256)
    
        tag.write(attr, [0])
        attr = nfc.tag.tt3.NdefAttributeData(tag.read([0]))
        log.info("new attribute data: " + attr.pretty())

    def prepare_tag(self):
        if self.options.tagtype == "tt3":
            return self.prepare_tt3_tag()

    def prepare_tt3_tag(self):
        if self.options.size % 16 != 0:
            self.options.size = ((self.options.size + 15) // 16) * 16
            log.warning("tt3 ndef data area size rounded to {0}"
                        .format(self.options.size))

        try: self.options.data
        except AttributeError:
            if self.options.input:
                self.options.data = self.options.input.read()
                try: self.options.data = self.options.data.decode("hex")
                except TypeError: pass
            else:
                self.options.data = ""

        if not (hasattr(self.options, "ndef_data_area") and self.options.keep):
            if self.options.input:
                self.options.ndef_data_area = \
                    bytearray(16) + bytearray(self.options.data) + \
                    bytearray(max(0, self.options.size-len(self.options.data)))
            #elif self.options.preserve:
            #    log.info("reading tag data from {0!r}"
            #             .format(self.options.preserve.name))
            #    data = self.options.preserve.read()
            #    if len(data) % 16 != 0:
            #        log.warning("memory data truncated to 16 byte boundary")
            #    self.options.ndef_data_area = bytearray(data)
            else:
                self.options.ndef_data_area = bytearray(16 + self.options.size)

            # set attribute data
            attr = nfc.tag.tt3.NdefAttributeData()
            attr.version = "1.0"
            attr.nbr, attr.nbw = (12, 8)
            attr.capacity = len(self.options.ndef_data_area) - 16
            attr.writeable = True
            attr.length = len(self.options.data)
            self.options.ndef_data_area[0:16] = str(attr)

        idm = bytearray.fromhex(self.options.idm)
        pmm = bytearray.fromhex(self.options.pmm)
        sys = bytearray.fromhex(self.options.sys)
        return nfc.clf.TTF(self.options.bitrate, idm, pmm, sys)

    def emulate_tag(self, tag, command):
        if self.options.tagtype == "tt3":
            self.emulate_tt3_tag(tag, command)
        if self.options.preserve:
            self.options.preserve.seek(0)
            self.options.preserve.write(self.options.ndef_data_area)
            log.info("wrote tag memory to file '{0}'"
                     .format(self.options.preserve.name))

    def emulate_tt3_tag(self, tag, command):
        def ndef_read(block_number, rb, re):
            log.debug("tt3 read block #{0}".format(block_number))
            if block_number < len(self.options.ndef_data_area) / 16:
                first, last = block_number*16, (block_number+1)*16
                block_data = self.options.ndef_data_area[first:last]
                return block_data
        def ndef_write(block_number, block_data, wb, we):
            log.debug("tt3 write block #{0}".format(block_number))
            if block_number < len(self.options.ndef_data_area) / 16:
                first, last = block_number*16, (block_number+1)*16
                self.options.ndef_data_area[first:last] = block_data
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

class ArgparseError(SystemExit):
    pass

class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgparseError(2, '{0}: error: {1}'.format(self.prog, message))

if __name__ == '__main__':
    try:
        TagTool().run()
    except ArgparseError as e:
        sys.argv = sys.argv + ['show']
        try:
            TagTool().run()
        except ArgparseError:
            print(e.args[1], file=sys.stderr)
