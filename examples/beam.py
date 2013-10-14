#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import os
import io
import sys
import time
import argparse
import threading
import mimetypes

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.snep
import nfc.ndef

def add_send_parser(parser):
    subparsers = parser.add_subparsers(title="send item", dest="send",
        description="Construct beam data from the send item and transmit to "
        "the peer device when touched. Use 'beam.py send {item} -h' to learn "
        "additional and/or required arguments per send item.")
    add_send_link_parser(subparsers.add_parser(
        "link", help="send hyperlink",
        description="Construct a smartposter message with URI and the "
        "optional title argument and send it to the peer when connected."))
    add_send_file_parser(subparsers.add_parser(
        "file", help="send disk file",
        description="Embed the file content into an NDEF message and send "
        "it to the peer when connected. The message type is guessed from "
        "the file type using the mimetype module and the message name is "
        "set to the file name unless explicitly set with command line flags "
        "-t TYPE and -n NAME, respectively."))
    add_send_ndef_parser(subparsers.add_parser(
        "ndef", help="send ndef data",
        description="Send the NDEF message stored in FILE. If the file "
        "contains multiple messages only the first one is extracted."))

def add_send_link_parser(parser):
    parser.set_defaults(func=run_send_link_action)
    parser.add_argument(
        "uri", help="smartposter uri")
    parser.add_argument(
        "title", help="smartposter title", nargs="?")

def run_send_link_action(args, llc):
    sp = nfc.ndef.SmartPosterRecord(args.uri)
    if args.title: sp.title = args.title
    nfc.snep.SnepClient(llc).put(nfc.ndef.Message(sp))

def add_send_file_parser(parser):
    parser.set_defaults(func=run_send_file_action)
    parser.add_argument(
        "file", type=argparse.FileType('rb'), metavar="FILE",
        help="file to send")
    parser.add_argument(
        "-t", metavar="TYPE", dest="type", default="unknown",
        help="record type (default: mimetype)")
    parser.add_argument(
        "-n", metavar="NAME", dest="name", default=None,
        help="record name (default: pathname)")

def run_send_file_action(args, llc):
    if args.type == 'unknown':
        mimetype = mimetypes.guess_type(args.file.name, strict=False)[0]
        if mimetype is not None: args.type = mimetype
    if args.name is None:
        args.name = args.file.name if args.file.name != "<stdin>" else ""

    data = args.file.read()
    try: data = data.decode("hex")
    except TypeError: pass

    record = nfc.ndef.Record(args.type, args.name, data)
    nfc.snep.SnepClient(llc).put(nfc.ndef.Message(record))

def add_send_ndef_parser(parser):
    parser.set_defaults(func=run_send_ndef_action)
    parser.add_argument(
        "ndef", type=argparse.FileType('rb'), metavar="FILE",
        help="NDEF message file")

def run_send_ndef_action(args, llc):
    data = args.ndef.read()
    try: data = data.decode("hex")
    except TypeError: pass
    nfc.snep.SnepClient(llc).put(nfc.ndef.Message(data))

def add_recv_parser(parser):
    subparsers = parser.add_subparsers(title="receive action", dest="recv",
        description="On receipt of incoming beam data perform the specified "
        "action. Use 'beam.py recv {action} -h' to learn additional and/or "
        "required arguments per action.")
    add_recv_save_parser(subparsers.add_parser(
        "save", help="save ndef data to a disk file",
        description="Save incoming beam data to a file. New data is appended "
        "if the file does already exist, a parser can use the NDEF message "
        "begin and end flags to separate messages."))
    add_recv_echo_parser(subparsers.add_parser(
        "echo", help="send ndef data back to peer device",
        description="Receive an NDEF message and send it back to the peer "
        "device without any modification."))
    add_recv_send_parser(subparsers.add_parser(
        "send", help="receive data and send an answer",
        description="Receive an NDEF message and use the translations file "
        "to find a matching response to send to the peer device. Each "
        "translation is a pair of in and out NDEF message cat together."))

def add_recv_save_parser(parser):
    parser.set_defaults(func=run_recv_save_action)
    parser.add_argument(
        "file", type=argparse.FileType('a+b'),
        help="write ndef to file ('-' write to stdout)")

def run_recv_save_action(args, llc, rcvd_ndef_msg):
    log.info('save ndef message {0!r}'.format(rcvd_ndef_msg.type))
    args.file.write(str(rcvd_ndef_msg))

def add_recv_echo_parser(parser):
    parser.set_defaults(func=run_recv_echo_action)

def run_recv_echo_action(args, llc, rcvd_ndef_msg):
    log.info('echo ndef message {0!r}'.format(rcvd_ndef_msg.type))
    nfc.snep.SnepClient(llc).put(rcvd_ndef_msg)

def add_recv_send_parser(parser):
    parser.set_defaults(func=run_recv_send_action)
    parser.add_argument(
        "translations", type=argparse.FileType('r'),
        help="echo translations file")

def run_recv_send_action(args, llc, rcvd_ndef_msg):
    log.info('translate ndef message {0!r}'.format(rcvd_ndef_msg.type))
    if type(args.translations) == file:
        bytestream = io.BytesIO(args.translations.read())
        args.translations = list()
        while True:
            try:
                msg_recv = nfc.ndef.Message(bytestream)
                msg_send = nfc.ndef.Message(bytestream)
                args.translations.append((msg_recv, msg_send))
                log.info('added translation {0!r} => {1:!r}'.format(
                    msg_recv, msg_send))
            except nfc.ndef.LengthError:
                break
    for msg_recv, msg_send in args.translations:
        if msg_recv == rcvd_ndef_msg:
            log.info('rcvd beam {0!r}'.format(msg_rcvd))
            log.info('send beam {0!r}'.format(msg_send))
            nfc.snep.SnepClient(llc).put(msg_send)
            break

class DefaultServer(nfc.snep.SnepServer):
    def __init__(self, args, llc):
        self.args, self.llc = args, llc
        super(DefaultServer, self).__init__(llc, 'urn:nfc:sn:snep')

    def put(self, ndef_message):
        log.info("default snep server got put request")
        log.info(ndef_message.pretty())
        if self.args.action == "recv":
            self.args.func(self.args, self.llc, ndef_message)
        return nfc.snep.Success

class Main(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(
            title="actions", dest="action")
        add_send_parser(subparsers.add_parser(
            'send', help='send data to beam receiver'))
        add_recv_parser(subparsers.add_parser(
            'recv', help='receive data from beam sender'))
        super(Main, self).__init__(
            parser, groups="llcp dbg clf")

    def on_llcp_startup(self, clf, llc):
        self.default_snep_server = DefaultServer(self.options, llc)
        return llc
        
    def on_llcp_connect(self, llc):
        self.default_snep_server.start()
        if self.options.action == "send":
            func, args = self.options.func, ((self.options, llc))
            threading.Thread(target=func, args=args).start()
        return True

if __name__ == '__main__':
    Main().run()
