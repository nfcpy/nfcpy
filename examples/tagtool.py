#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import hmac, hashlib

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.clf
import nfc.ndef

def parse_version(string):
    try: major_version, minor_version = map(int, string.split('.'))
    except ValueError, AttributeError:
        msg = "%r is not a version string, expecting <int>.<int>"
        raise argparse.ArgumentTypeError(msg % string)
    if major_version < 0 or major_version > 15:
        msg = "major version %r is out of range, expecting 0...15"
        raise argparse.ArgumentTypeError(msg % major_version)
    if minor_version < 0 or minor_version > 15:
        msg = "minor version %r is out of range, expecting 0...15"
        raise argparse.ArgumentTypeError(msg % minor_version)
    return major_version << 4 | minor_version

def parse_uint8(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as an 8-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

def parse_uint16(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xffff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as a 16-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

def parse_uint24(string):
    for base in (10, 16):
        try:
            value = int(string, base)
            if value >= 0 and value <= 0xffffff:
                return value
        except ValueError:
            pass
    else:
        msg = "%r can not be read as a 24-bit unsigned integer"
        raise argparse.ArgumentTypeError(msg % string)

#
# command parsers
#
def add_show_parser(parser):
    pass

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
    parser.add_argument(
        "--wipe", metavar="BYTE", type=int, default=None,
        help="overwrite all data with BYTE")
    parser.add_argument(
        "--version", metavar="x.y", type=parse_version,
        help="ndef mapping version, default is latest")
    subparsers = parser.add_subparsers(
        title="tag type subcommands", dest="tagtype", metavar='{tt1,tt2,tt3}',
        help="tag type specific arguments")
    subparsers.add_parser('any')
    description = (
        "The tag type specific arguments are intended to give full "
        "control over the format creation. Arguments provided here "
        "are written to the tag regardless of whether they will "
        "create a valid configuration. It is thus possible to create "
        "formats that may confuse a reader, as useful for testing.")
    add_format_tt1_parser(subparsers.add_parser(
        'tt1', description=description))
    add_format_tt2_parser(subparsers.add_parser(
        'tt2', description=description))
    add_format_tt3_parser(subparsers.add_parser(
        'tt3', description=description))

def add_format_tt1_parser(parser):
    parser.add_argument(
        "--magic", metavar="BYTE", type=parse_uint8,
        help="value to use as ndef magic byte")
    parser.add_argument(
        "--ver", metavar="x.y", type=parse_version,
        help="ndef mapping major and minor version")
    parser.add_argument(
        "--tms", metavar="BYTE", type=parse_uint8,
        help="tag memory size, 8*(tms+1)")
    parser.add_argument(
        "--rwa", metavar="BYTE", type=parse_uint8,
        help="read write access byte")

def add_format_tt2_parser(parser):
    pass

def add_format_tt3_parser(parser):
    parser.add_argument(
        "--ver", metavar="x.y", type=parse_version,
        help="ndef mapping major and minor version")
    parser.add_argument(
        "--nbr", metavar="BYTE", type=parse_uint8,
        help="number of blocks that can be written at once")
    parser.add_argument(
        "--nbw", metavar="BYTE", type=parse_uint8,
        help="number of blocks that can be read at once")
    parser.add_argument(
        "--max", metavar="SHORT", type=parse_uint16,
        help="maximum number of blocks (nmaxb)")
    parser.add_argument(
        "--rfu", metavar="BYTE", type=parse_uint8,
        help="value to set for reserved bytes")
    parser.add_argument(
        "--wf", metavar="BYTE", type=parse_uint8,
        help="write-flag attribute value")
    parser.add_argument(
        "--rw", metavar="BYTE", type=parse_uint8,
        help="read-write flag attribute value")
    parser.add_argument(
        "--len", metavar="INT", type=parse_uint24,
        help="ndef length attribute value")
    parser.add_argument(
        "--crc", metavar="INT", type=parse_uint16,
        help="checksum attribute value")
        
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
        help="minimum ndef data area size (default: %(default)s)")
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
    parser.add_argument(
        "--ver", metavar="x.y", type=parse_version, default="1.0",
        help="ndef mapping version number (default: %(default)s)")
    parser.add_argument(
        "--nbr", metavar="INT", type=int, default=12,
        help="max write blocks at once (default: %(default)s)")
    parser.add_argument(
        "--nbw", metavar="INT", type=int, default=8,
        help="max read blocks at once (default: %(default)s)")
    parser.add_argument(
        "--max", metavar="INT", type=int,
        help="maximum number of blocks (default: computed)")
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
        "--crc", metavar="INT", type=int,
        help="checksum attribute value (default: computed)")

def add_protect_parser(parser):
    parser.add_argument(
        "-p", dest="password",
        help="protect with password if possible")
    parser.add_argument(
        "--from", metavar="BLOCK", dest="protect_from", type=int, default=0,
        help="first block to protect (default: %(default)s)")
    parser.add_argument(
        "--unreadable", action="store_true",
        help="make tag unreadable without password")

class TagTool(CommandLineInterface):
    def __init__(self):
        parser = ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="")
        parser.add_argument(
            "-p", dest="authenticate", metavar="PASSWORD",
            help="unlock with password if supported")
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
        add_protect_parser(subparsers.add_parser(
                'protect', help='write protect a tag'))
        add_emulate_parser(subparsers.add_parser(
                'emulate', help='emulate an ndef tag'))

        self.rdwr_commands = {"show": self.show_tag,
                              "dump": self.dump_tag,
                              "load": self.load_tag,
                              "format": self.format_tag,
                              "protect": self.protect_tag,}
    
        super(TagTool, self).__init__(
            parser, groups="rdwr card dbg clf")

    def on_rdwr_startup(self, targets):
        if self.options.command in self.rdwr_commands.keys():
            print("** waiting for a tag **", file=sys.stderr)
            return targets

    def on_rdwr_connect(self, tag):
        if self.options.authenticate is not None:
            if len(self.options.authenticate) > 0:
                key, msg = self.options.authenticate, tag.identifier
                password = hmac.new(key, msg, hashlib.sha256).digest()
            else:
                password = "" # use factory default password
            result = tag.authenticate(password)
            if result is False:
                print("I'm sorry, but authentication failed.")
                return False
            if result is None:
                print(tag)
                print("I don't know how to authenticate this tag.")
                return False
            
        self.rdwr_commands[self.options.command](tag)
        return self.options.wait or self.options.loop
    
    def on_card_startup(self, target):
        if self.options.command == "emulate":
            target = self.prepare_tag(target)
            print("** waiting for a reader **", file=sys.stderr)
            return target

    def on_card_connect(self, tag):
        log.info("tag activated")
        return self.emulate_tag_start(tag)

    def on_card_release(self, tag):
        log.info("tag released")
        self.emulate_tag_stop(tag)
        return True

    def show_tag(self, tag):
        print(tag)
        
        if tag.ndef:
            print("NDEF Capabilities:")
            print("  readable  = %s" % ("no","yes")[tag.ndef.is_readable])
            print("  writeable = %s" % ("no","yes")[tag.ndef.is_writeable])
            print("  capacity  = %d byte" % tag.ndef.capacity)
            print("  message   = %d byte" % tag.ndef.length)
            if tag.ndef.length > 0:
                print("NDEF Message:")
                print(tag.ndef.message.pretty())
        
        if self.options.verbose:
            print("Memory Dump:")
            print('  ' + '\n  '.join(tag.dump()))

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
            print("This is not an NDEF Tag.")
            return

        if not tag.ndef.is_writeable:
            print("This Tag is not writeable.")
            return

        new_ndef_message = nfc.ndef.Message(self.options.data)
        if new_ndef_message == tag.ndef.message:
            print("The Tag already contains the message to write.")
            return

        if len(str(new_ndef_message)) > tag.ndef.capacity:
            print("The new message exceeds the Tag's capacity.")
            return
        
        print("Old message:")
        print(tag.ndef.message.pretty())
        tag.ndef.message = new_ndef_message
        print("New message:")
        print(tag.ndef.message.pretty())

    def format_tag(self, tag):
        if (self.options.tagtype != "any" and
            self.options.tagtype[2] != tag.type[4]):
            print("This is not a Type {0} Tag but you said so."
                  .format(self.options.tagtype[2]))
            return

        if self.options.version is None:
            version = {'Type1Tag': 0x12, 'Type2Tag': 0x12,
                       'Type3Tag': 0x10, 'Type4Tag': 0x30}[tag.type]
        else: version = self.options.version
            
        formatted = tag.format(version=version, wipe=self.options.wipe)

        if formatted is True:
            {'tt1': self.format_tt1_tag, 'tt2': self.format_tt2_tag,
             'tt3': self.format_tt3_tag, 'tt4': self.format_tt4_tag,
             'any': lambda tag: None}[self.options.tagtype](tag)
            print("Formatted %s" % tag)
            if tag.ndef:
                print("  readable  = %s" % ("no","yes")[tag.ndef.is_readable])
                print("  writeable = %s" % ("no","yes")[tag.ndef.is_writeable])
                print("  capacity  = %d byte" % tag.ndef.capacity)
                print("  message   = %d byte" % tag.ndef.length)
        elif formatted is None:
            print("Sorry, this tag can not be formatted.")
        else:
            print("Sorry, I could not format this tag.")

    def format_tt1_tag(self, tag):
        if self.options.magic is not None:
            tag.write_byte(8, self.options.magic)
        if self.options.ver is not None:
            tag.write_byte(9, self.options.ver)
        if self.options.tms is not None:
            tag.write_byte(10, self.options.tms)
        if self.options.rwa is not None:
            tag.write_byte(11, self.options.rwa)

    def format_tt2_tag(self, tag):
        pass

    def format_tt3_tag(self, tag):
        attribute_data = tag.read_from_ndef_service(0)
        if self.options.ver is not None:
            attribute_data[0] = self.options.ver
        if self.options.nbr is not None:
            attribute_data[1] = self.options.nbr
        if self.options.nbw is not None:
            attribute_data[2] = self.options.nbw
        if self.options.max is not None:
            attribute_data[3:5] = struct.pack(">H", self.options.max)
        if self.options.rfu is not None:
            attribute_data[5:9] = 4 * [self.options.rfu]
        if self.options.wf is not None:
            attribute_data[9] = self.options.wf
        if self.options.rw is not None:
            attribute_data[10] = self.options.rw
        if self.options.len is not None:
            attribute_data[11:14] = struct.pack(">I", self.options.len)[1:]
        if self.options.crc is not None:
            attribute_data[14:16] = struct.pack(">H", self.options.crc)
        else:
            checksum = sum(attribute_data[:14])
            attribute_data[14:16] = struct.pack(">H", checksum)
        tag.write_to_ndef_service(attribute_data, 0)

    def format_tt4_tag(self, tag):
        pass

    def protect_tag(self, tag):
        print(tag)
        
        if self.options.password is not None:
            if len(self.options.password) >= 8:
                print("generating diversified key from password")
                key, msg = self.options.password, tag.identifier
                password = hmac.new(key, msg, hashlib.sha256).digest()
            elif len(self.options.password) == 0:
                print("using factory default key for password")
                password = ""
            else:
                print("A password should be at least 8 characters.")
                return
            
        result = tag.protect(password, self.options.unreadable,
                             self.options.protect_from)
        if result is True:
            print("This tag is now protected.")
        elif result is False:
            print("Failed to protect this tag.")
        elif result is None:
            print("Sorry, but this tag can not be protected.")

    def prepare_tag(self, target):
        if self.options.tagtype == "tt3":
            return self.prepare_tt3_tag(target)

    def prepare_tt3_tag(self, target):
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

        if not (hasattr(self.options, "tt3_data") and self.options.keep):
            if self.options.input:
                ndef_data_size = len(self.options.data)
                ndef_area_size = ((ndef_data_size + 15) // 16) * 16
                ndef_area_size = max(ndef_area_size, self.options.size)
                ndef_data_area = bytearray(self.options.data) + \
                                 bytearray(ndef_area_size - ndef_data_size)
            else:
                ndef_data_area = bytearray(self.options.size)

            # create attribute data
            attribute_data = bytearray(16)
            attribute_data[0] = self.options.ver
            attribute_data[1] = self.options.nbr
            attribute_data[2] = self.options.nbw
            if self.options.max is None:
                nmaxb = len(ndef_data_area) // 16
            else: nmaxb = self.options.max
            attribute_data[3:5] = struct.pack(">H", nmaxb)
            attribute_data[5:9] = 4 * [self.options.rfu]
            attribute_data[9] = self.options.wf
            attribute_data[10:14] = struct.pack(">I", len(self.options.data))
            attribute_data[10] = self.options.rw
            attribute_data[14:16] = struct.pack(">H", sum(attribute_data[:14]))
            self.options.tt3_data = attribute_data + ndef_data_area

        idm = bytearray.fromhex(self.options.idm)
        pmm = bytearray.fromhex(self.options.pmm)
        sys = bytearray.fromhex(self.options.sys)

        target.brty = str(self.options.bitrate) + "F"
        target.sensf_res = "\x01" + idm + pmm + sys
        return target

    def emulate_tag_start(self, tag):
        if self.options.tagtype == "tt3":
            return self.emulate_tt3_tag(tag)

    def emulate_tag_stop(self, tag):
        if self.options.preserve:
            self.options.preserve.seek(0)
            self.options.preserve.write(self.options.tt3_data)
            log.info("wrote tag memory to file '{0}'"
                     .format(self.options.preserve.name))

    def emulate_tt3_tag(self, tag):
        def ndef_read(block_number, rb, re):
            log.debug("tt3 read block #{0}".format(block_number))
            if block_number < len(self.options.tt3_data) / 16:
                first, last = block_number*16, (block_number+1)*16
                block_data = self.options.tt3_data[first:last]
                return block_data
        def ndef_write(block_number, block_data, wb, we):
            log.debug("tt3 write block #{0}".format(block_number))
            if block_number < len(self.options.tt3_data) / 16:
                first, last = block_number*16, (block_number+1)*16
                self.options.tt3_data[first:last] = block_data
                return True

        tag.add_service(0x0009, ndef_read, ndef_write)
        tag.add_service(0x000B, ndef_read, lambda: False)
        return True

class ArgparseError(SystemExit):
    def __init__(self, prog, message):
        super(ArgparseError, self).__init__(2, prog, message)
    
    def __str__(self):
        return '{0}: {1}'.format(self.args[1], self.args[2])

class ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ArgparseError(self.prog, message)

if __name__ == '__main__':
    try:
        TagTool().run()
    except ArgparseError as e:
        prog = e.args[1].split()
    else:
        sys.exit(0)

    if len(prog) == 1:
        sys.argv = sys.argv + ['show']
    elif prog[-1] == "format":
        sys.argv = sys.argv + ['any']

    try:
        TagTool().run()
    except ArgparseError as e:
        print(e, file=sys.stderr)
