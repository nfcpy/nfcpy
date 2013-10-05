#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

import sys, os
import mimetypes

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef

def add_print_parser(parser):
    parser.description = """Parse and print NDEF messages."""
    parser.set_defaults(func=print_command)
    parser.add_argument(
        "message", type=argparse.FileType('r'), default="-", nargs="?",
        help="message data file ('-' for stdin)")

def print_command(args):
    data = args.message.read()
    try: data = data.decode("hex")
    except TypeError: pass
    
    message = nfc.ndef.Message(data)
    for index, record in enumerate(message):
        rcount = " [record {0}]".format(index+1) if len(message) > 1 else ""
        try:
            if record.type == "urn:nfc:wkt:T":
                print("Text Record" + rcount)
                record = nfc.ndef.TextRecord(record)
            elif record.type == "urn:nfc:wkt:U":
                print("URI Record" + rcount)
                record = nfc.ndef.UriRecord(record)
            elif record.type == "urn:nfc:wkt:Sp":
                print("Smartposter Record" + rcount)
                record = nfc.ndef.SmartPosterRecord(record)
            elif record.type == "application/vnd.bluetooth.ep.oob":
                print("Bluetooth Configuration Record" + rcount)
                record = nfc.ndef.BluetoothConfigRecord(record)
            elif record.type == "application/vnd.wfa.wsc":
                try:
                    record = nfc.ndef.WifiPasswordRecord(record)
                    print("WiFi Password Record" + rcount)
                except nfc.ndef.DecodeError:
                    record = nfc.ndef.WifiConfigRecord(record)
                    print("WiFi Configuration Record" + rcount)
            elif record.type == "urn:nfc:wkt:Hr":
                print("Handover Request Record" + rcount)
                record = nfc.ndef.handover.HandoverRequestRecord(record)
            elif record.type == "urn:nfc:wkt:Hs":
                print("Handover Select Record" + rcount)
                record = nfc.ndef.handover.HandoverSelectRecord(record)
            elif record.type == "urn:nfc:wkt:Hc":
                print("Handover Carrier Record" + rcount)
                record = nfc.ndef.handover.HandoverCarrierRecord(record)
            else:
                print("Unknown Record Type" + rcount)
        except nfc.ndef.FormatError as e:
            log.error(e)
        print(record.pretty(indent=2))

    try:
        if message.type == "urn:nfc:wkt:Hr":
            message = nfc.ndef.HandoverRequestMessage(message)
            print("\nHandover Request Message")
            print(message.pretty(indent=2) + '\n')
        elif message.type == "urn:nfc:wkt:Hs":
            message = nfc.ndef.HandoverSelectMessage(message)
            print("\nHandover Select Message")
            print(message.pretty(indent=2) + '\n')
    except nfc.ndef.FormatError as e:
        log.error(e)
    
def add_make_parser(parser):
    parser.description = """The make command creates ndef
    messages."""
    
    subparsers = parser.add_subparsers()
    make_smartposter_parser(subparsers.add_parser(
            'smartposter',
            help='create a smartposter message'))
    make_wifipassword_parser(subparsers.add_parser(
            'wifipwd',
            help='create a wifi password token'))
    make_wificonfig_parser(subparsers.add_parser(
            'wificfg',
            help='create a wifi config record'))
    make_bluetoothcfg_parser(subparsers.add_parser(
            'btcfg',
            help='create bluetooth out-of-band record'))
    
def make_smartposter_parser(parser):
    parser.set_defaults(func=make_smartposter)
    parser.add_argument(
        "-o", dest="outfile", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="write message to file (writes binary data) ")
    parser.add_argument(
        "-t", metavar="TITLE", dest="titles", action="append", default=list(),
        help="smartposter title as '[language:]titlestring'")
    parser.add_argument(
        "-i", metavar="ICON", dest="icons", action="append", default=list(),
        type=argparse.FileType('r'),
        help="smartposter icon file")
    parser.add_argument(
        "-a", dest="action", default="default",
        help="smartposter action 'exec', 'save' or 'edit'")
    parser.add_argument(
        "resource",
        help="uniform resource identifier")
    
def make_smartposter(args):
    record = nfc.ndef.SmartPosterRecord(args.resource)
    for title in args.titles:
        lang, text = title.split(':', 1) if ':' in title else ('en', title)
        record.title[lang] = text
    for icon in args.icons:
        mimetype = mimetypes.guess_type(icon.name, strict=False)[0]
        if mimetype is None:
            log.error("file '%s' is not a recognized mime type" % icon.name)
            return
        mimetype, subtype = mimetype.split('/')
        if not mimetype == "image":
            log.error("file '%s' is not an image mime type" % icon.name)
            return
        record.icons[subtype] = icon.read()
        if not args.action in ('default', 'exec', 'save', 'edit'):
            log.error("action not one of 'default', 'exec', 'save', 'edit'")
            return
    record.action = args.action

    message = nfc.ndef.Message(record)
    if args.outfile.name == "<stdout>":
        args.outfile.write(str(message).encode("hex"))
    else:
        args.outfile.write(str(message))

def make_wifipassword_parser(parser):
    parser.set_defaults(func=make_wifipassword)
    parser.add_argument(
        "-o", dest="outfile", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="write message to file (writes binary data) ")
    parser.add_argument(
        "pubkey", type=argparse.FileType('r'),
        help="enrollee's public key file ('-' reads from stdin)")
    parser.add_argument(
        "-p", dest="password", metavar="STRING",
        help="device password (default: 32 octet random string)")
    parser.add_argument(
        "-i", dest="password_id", metavar="INT",
        help="password identifier (default: random number)")
    
def make_wifipassword(args):
    import random, string, hashlib
    if args.password is None:
        printable = string.digits + string.letters + string.punctuation
        args.password = ''.join([random.choice(printable) for i in xrange(32)])
    if args.password_id is None:
        args.password_id = random.randint(0x0010, 0xFFFF)
    pkhash = hashlib.sha256(args.pubkey.read()).digest()[0:20]
        
    record = nfc.ndef.WifiPasswordRecord()
    record.password['public-key-hash'] = pkhash
    record.password['password-id'] = args.password_id
    record.password['password'] = args.password
    
    message = nfc.ndef.Message(record)
    if args.outfile.name == "<stdout>":
        args.outfile.write(str(message).encode("hex"))
    else:
        args.outfile.write(str(message))
    
def make_wificonfig_parser(parser):    
    parser.set_defaults(func=make_wificonfig)
    parser.add_argument(
        "-o", dest="outfile", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="write message to file (writes binary data) ")
    parser.add_argument(
        "ssid", metavar="network-name", nargs="?",
        help="network name (SSID)")
    parser.add_argument(
        "--key", default="",
        help="network key (default: open network)")
    parser.add_argument(
        "--mac", default="ff:ff:ff:ff:ff:ff",
        help="mac address (default: 'ff:ff:ff:ff:ff:ff')")
    parser.add_argument(
        "--mixed-mode", action="store_true",
        help="access point supports WPA2 and WPA")
    parser.add_argument(
        "--shareable", action="store_true",
        help="network key may be shared with other devices")
    parser.add_argument(
        "--hs", action="store_true",
        help="generate a handover select message")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--active", action="store_true",
        help="set power state 'active' (implies --hs)")
    group.add_argument(
        "--inactive", action="store_true",
        help="set power state 'inactive' (implies --hs)")
    group.add_argument(
        "--activating", action="store_true",
        help="set power state 'activating' (implies --hs)")
    
def make_wificonfig(args):
    import uuid
    if args.ssid is None:
        args.ssid = str(uuid.uuid1())
    authentication, encryption = "Open", "None"
    if args.key:
        if not args.mixed_mode:
            authentication, encryption = "WPA2-Personal", "AES"
        else:
            authentication, encryption = "WPA/WPA2-Personal", "AES/TKIP"
        
    record = nfc.ndef.WifiConfigRecord()
    record.credential['network-name'] = args.ssid
    record.credential['network-key'] = args.key
    record.credential['authentication'] = authentication
    record.credential['encryption'] = encryption
    record.credential['mac-address'] = args.mac
    log.info(record.pretty())

    if args.active or args.inactive or args.activating:
        args.hs = True
        
    if args.hs:
        message = nfc.ndef.HandoverSelectMessage(version='1.2')
        power_state = ("active" if args.active else "inactive" if args.inactive
                       else "activating" if args.activating else "unknown")
        message.add_carrier(record, power_state)
    else:
        message = nfc.ndef.Message(record)
        
    if args.outfile.name == "<stdout>":
        args.outfile.write(str(message).encode("hex"))
    else:
        args.outfile.write(str(message))

def make_bluetoothcfg_parser(parser):    
    parser.set_defaults(func=make_bluetoothcfg)
    parser.add_argument(
        "-o", dest="outfile", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="write message to file (writes binary data) ")
    parser.add_argument(
        "bdaddr", metavar="device-address",
        help="Bluetooth device address")
    parser.add_argument(
        "-c", dest="cod", metavar="BITSTR",
        help="class of device/service")
    parser.add_argument(
        "-n", dest="name", metavar="STRING",
        help="user friendly device name")
    parser.add_argument(
        "-s", dest="service", metavar="STRING", action="append", default=[],
        help="a service class uuid")
    parser.add_argument(
        "--hs", action="store_true",
        help="generate a handover select message")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--active", action="store_true",
        help="set power state 'active' (implies --hs)")
    group.add_argument(
        "--inactive", action="store_true",
        help="set power state 'inactive' (implies --hs)")
    group.add_argument(
        "--activating", action="store_true",
        help="set power state 'activating' (implies --hs)")
    
def make_bluetoothcfg(args):
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = args.bdaddr
    if args.cod:
        record.class_of_device = int(args.cod.replace(' ', ''), 2)
    if args.name:
        record.local_device_name = args.name
    for index, service in enumerate(args.service):
        for key, value in nfc.ndef.bt_record.service_class_uuid_map.items():
            if service.lower() == value.lower():
                args.service[index] = key
                break
        else:
            try: record.service_class_uuid_list = [service,]
            except ValueError:
                log.error("unrecognized service class '{0}', expected a "
                          "128-bit UUID string or one of:".format(service))
                log.error(nfc.ndef.bt_record.service_class_uuid_map.values())
                sys.exit(1)
    record.service_class_uuid_list = args.service
    log.info(record.pretty())

    if args.active or args.inactive or args.activating:
        args.hs = True
        
    if args.hs:
        message = nfc.ndef.HandoverSelectMessage(version='1.2')
        power_state = ("active" if args.active else "inactive" if args.inactive
                       else "activating" if args.activating else "unknown")
        message.add_carrier(record, power_state)
    else:
        message = nfc.ndef.Message(record)
        
    if args.outfile.name == "<stdout>":
        args.outfile.write(str(message).encode("hex"))
    else:
        args.outfile.write(str(message))

def add_pack_parser(parser):
    parser.description = """The pack command creates an NDEF record
    encapsulating the contents of FILE. The record type is determined
    by the file type if possible, it may be explicitely set with the
    -t option. The record name (payload identifier) is set to the file
    name."""

    parser.set_defaults(func=pack)
    parser.add_argument(
        "-o", dest="outfile", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save to file (writes binary data)")
    parser.add_argument(
        "-t", metavar="STRING", dest="type", default="unknown",
        help="record type (default: mimetype)")
    parser.add_argument(
        "-n", metavar="STRING", dest="name", default=None,
        help="record name (default: pathname)")
    parser.add_argument(
        "input", metavar="FILE", type=argparse.FileType('r'),
        help="record data file ('-' to read from stdin)")
    
def pack(args):
    if args.type == 'unknown':
        print >> sys.stderr, "guess mime type from file"
        mimetype = mimetypes.guess_type(args.input.name, strict=False)[0]
        if mimetype is not None: args.type = mimetype
    if args.name is None:
        args.name = args.input.name if args.input.name != "<stdin>" else ""
        
    data = args.input.read()

    if args.type == "text/plain":
        print >> sys.stderr, "text/plain ==> urn:nfc:wkt:T"
        try:
            from guess_language import guessLanguage
            print >> sys.stderr, "guess language from text"
            language = guessLanguage(data)
            if language == "UNKNOWN": language = "en"
        except ImportError:
            language = "en"
        print >> sys.stderr, "text language is '%s'" % language
        record = nfc.ndef.TextRecord(data, language=language)
        record.name = args.name
    else:
        print >> sys.stderr, "mime type is %s" % args.type
        record = nfc.ndef.Record(args.type, args.name, data)

    message = nfc.ndef.Message(record)
    if args.outfile.name == "<stdout>":
        args.outfile.write(str(message).encode("hex"))
    else:
        args.outfile.write(str(message))

def add_split_parser(parser):
    parser.description = """The split command separates an an NDEF
    message into individual records. If data is read from a file,
    records are written as binary data into individual files with file
    names constructed from the input file base name, a hyphen followed
    by a three digit number and the input file name extension. If data
    is read from stdin, records are written to stdout as individual
    lines of hexadecimal strings."""
    
    parser.set_defaults(func=split)
    parser.add_argument(
        "input", metavar="message", type=argparse.FileType('r'),
        help="message file ('-' to read from stdin)")
    parser.add_argument(
        "--keep-message-flags", dest="keepmf", action="store_true",
        help="do not reset message begin and end flags")
    
def split(args):
    log.info("reading message data from '{0}'".format(args.input.name))
    
    data = args.input.read()
    try: data = data.decode("hex")
    except TypeError: pass
        
    message = nfc.ndef.Message(data)
    for index, record in enumerate(message):
        if not args.keepmf:
            record._message_begin = record._message_end = False
        if args.input.name == "<stdin>":
            print(str(record).encode("hex"))
        else:
            fn = os.path.splitext(os.path.split(args.input.name)[1])
            fn = fn[0] + "-{0:03d}".format(index+1) + fn[1]
            log.info("writing {fn}".format(fn=fn))
            file(fn, "w").write(str(record))

def add_cat_parser(parser):
    parser.description = "Concatenate records to a new message."
    parser.set_defaults(func=cat)
    parser.add_argument(
        "-o", dest="output", metavar="FILE",
        type=argparse.FileType('w'), default="-",
        help="save message to file (writes binary data)")
    parser.add_argument(
        "records", metavar="record", type=argparse.FileType('r'), nargs="+",
        help="record file")
    
def cat(args):
    message = nfc.ndef.Message()
    for f in args.records:
        data = f.read()
        try: data = data.decode("hex")
        except TypeError: pass
        record = nfc.ndef.Record(data=data)
        log.info("add '{0}' record from file '{1}'"
                 .format(record.type, f.name))
        message.append(record)
    if args.output.name == "<stdout>":
        args.output.write(str(message).encode("hex"))
    else:
        args.output.write(str(message))

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", dest="verbose", action="store_true",
        help="print info messages to stderr")
    parser.add_argument(
        "-d", dest="debug", action="store_true",
        help="print debug messages to stderr")

    subparsers = parser.add_subparsers(title="commands")
    add_print_parser(subparsers.add_parser(
            'print', help='parse and print messages'))
    add_make_parser(subparsers.add_parser(
            'make', help='create ndef messages'))
    add_pack_parser(subparsers.add_parser(
            'pack', help='pack data into an ndef record'))
    add_split_parser(subparsers.add_parser(
            'split', help='split messages into records'))
    add_cat_parser(subparsers.add_parser(
            'cat', help='concatenate records to message'))

    args = parser.parse_args()

    verbosity = logging.INFO if args.verbose else logging.ERROR
    verbosity = logging.DEBUG if args.debug else verbosity
    logging.basicConfig(level=verbosity, format='%(levelname)s: %(message)s')

    log.debug(args)
    args.func(args)

