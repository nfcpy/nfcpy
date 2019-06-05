#!/usr/bin/env python
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
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import threading
import mimetypes
import argparse
import logging
import random
import time
import ndef
import nfc
import cli
import sys
import io


log = logging.getLogger('main')
filetype = file if sys.version_info.major < 3 else io.IOBase  # noqa: F821


def add_send_parser(parser):
    subparsers = parser.add_subparsers(
        title="send item", dest="send_action", description="""
        Construct beam data from the send item and transmit to the peer
        device when touched. Use 'beam.py send {item} -h' to learn
        additional and/or required arguments per send item.""")
    subparsers.required = True
    add_send_link_parser(subparsers.add_parser(
        "link", help="send hyperlink", description="""
        Construct an NDEF Smartposter message with URI and the optional
        title argument and send it to the peer when connected."""))
    add_send_text_parser(subparsers.add_parser(
        "text", help="send plain text", description="""
        Construct an NDEF Text message with the input string as
        text content. The language default is 'en' (English) but may be set
        differently with the --lang option."""))
    add_send_file_parser(subparsers.add_parser(
        "file", help="send disk file", description="""
        Embed the file content into an NDEF message and send
        it to the peer when connected. The message type is guessed from
        the file type using the mimetype module and the message name is
        set to the file name unless explicitly set with command line flags
        -t TYPE and -n NAME, respectively."""))
    add_send_ndef_parser(subparsers.add_parser(
        "ndef", help="send ndef data", description="""
        Send an NDEF message from FILE. If the file contains
        multiple messages the strategy that determines the message to be
        send can be set with the --select argument. For strategies that
        select a different message per touch beam.py must be called with
        the --loop flag. The strategies 'first', 'last' and 'random'
        select the first, last or a random message from the file. The
        strategies 'next' and 'cycle' start with the first message and
        then count up, the difference is that 'next' stops at the last
        message while 'cycle' continues with first."""))
    parser.add_argument(
        "--timeit", action="store_true", help="measure transfer time")


def send_message(args, llc, message):
    t0 = time.time() if args.timeit else None
    if not nfc.snep.SnepClient(llc).put_records(message):
        log.error("failed to send message")
    if t0 is not None:
        transfer_time = time.time() - t0
        message_size = len(b''.join(ndef.message_encoder(message)))
        print("message sent in {0:.3f} seconds ({1} byte @ {2:.0f} byte/sec)"
              .format(transfer_time, message_size,
                      message_size / transfer_time))


def add_send_link_parser(parser):
    parser.set_defaults(func=run_send_link_action)
    parser.add_argument(
            "uri", help="smartposter uri")
    parser.add_argument(
            "title", help="smartposter title", nargs="?")


def run_send_link_action(args, llc):
    record = ndef.SmartposterRecord(args.uri)
    if args.title:
        record.set_title(args.title)
    send_message(args, llc, [record])


def add_send_text_parser(parser):
    parser.set_defaults(func=run_send_text_action)
    parser.add_argument(
            "--lang", help="text language")
    parser.add_argument(
            "text", metavar="STRING", help="text string")


def run_send_text_action(args, llc):
    record = ndef.TextRecord(args.text)
    if args.lang:
        record.language = args.lang
    send_message(args, llc, [record])


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
        if mimetype is not None:
            args.type = mimetype
    if args.name is None:
        args.name = args.file.name if args.file.name != "<stdin>" else ""

    record = ndef.Record(args.type, args.name, args.file.read())
    log.info("send {}".format(record))
    send_message(args, llc, [record])


def add_send_ndef_parser(parser):
    parser.set_defaults(func=run_send_ndef_action)
    parser.add_argument(
            "ndef", metavar="FILE", type=argparse.FileType('rb'),
            help="NDEF message file")
    parser.add_argument(
            "--select", metavar="STRATEGY",
            choices=['first', 'last', 'next', 'cycle', 'random'],
            default="first",
            help="strategies are: %(choices)s")


def run_send_ndef_action(args, llc):
    if isinstance(args.ndef, filetype):
        octets = io.BytesIO(args.ndef.read())
        args.selected = -1
        args.ndef = list()
        records = list(ndef.message_decoder(octets, known_types={}))
        while records:
            args.ndef.append(records)
            records = list(ndef.message_decoder(octets, known_types={}))

    if args.select == "first":
        args.selected = 0
    elif args.select == "last":
        args.selected = len(args.ndef) - 1
    elif args.select == "next":
        args.selected = args.selected + 1
    elif args.select == "cycle":
        args.selected = (args.selected + 1) % len(args.ndef)
    elif args.select == "random":
        args.selected = random.choice(range(len(args.ndef)))

    if 0 <= args.selected < len(args.ndef):
        log.info("send {}".format(args.ndef[args.selected]))
        send_message(args, llc, args.ndef[args.selected])


def add_recv_parser(parser):
    subparsers = parser.add_subparsers(
        title="receive action", dest="recv_action", description="""
        On receipt of incoming beam data perform the specified
        action. Use 'beam.py recv {action} -h' to learn additional and/or
        required arguments per action.""")
    subparsers.required = True
    add_recv_print_parser(subparsers.add_parser(
        "print", help="print received message", description="""
        Print the received NDEF message and do nothing else."""))
    add_recv_save_parser(subparsers.add_parser(
        "save", help="save ndef data to a disk file", description="""
        Save incoming beam data to a file. New data is appended
        if the file does already exist, a parser can use the NDEF message
        begin and end flags to separate messages."""))
    add_recv_echo_parser(subparsers.add_parser(
        "echo", help="send ndef data back to peer device", description="""
        Receive an NDEF message and send it back to the peer device
        without any modification."""))
    add_recv_send_parser(subparsers.add_parser(
        "send", help="receive data and send an answer", description="""
        Receive an NDEF message and use the translations file
        to find a matching response to send to the peer device. Each
        translation is a pair of in and out NDEF message cat together."""))


def add_recv_print_parser(parser):
    parser.set_defaults(func=run_recv_print_action)


def run_recv_print_action(args, llc, message):
    for record in message:
        print(record)


def add_recv_save_parser(parser):
    parser.set_defaults(func=run_recv_save_action)
    parser.add_argument(
            "file", type=argparse.FileType('a+b'),
            help="write ndef data octets to file")


def run_recv_save_action(args, llc, message):
    log.info('save ndef message {}'.format(message[0].type))
    args.file.write(b''.join(ndef.message_encoder(message)))


def add_recv_echo_parser(parser):
    parser.set_defaults(func=run_recv_echo_action)


def run_recv_echo_action(args, llc, message):
    log.info('echo ndef message {}'.format(message[0].type))
    nfc.snep.SnepClient(llc).put_records(message)


def add_recv_send_parser(parser):
    parser.set_defaults(func=run_recv_send_action)
    parser.add_argument(
            "translations", type=argparse.FileType('r'),
            help="echo translations file")


def run_recv_send_action(args, llc, message):
    log.info('translate ndef message {}'.format(message[0].type))

    if isinstance(args.translations, filetype):
        stream = io.BytesIO(args.translations.read())
        args.translations = list()
        while True:
            try:
                msg_recv = list(ndef.message_decoder(stream, known_records={}))
                msg_send = list(ndef.message_decoder(stream, known_records={}))
                args.translations.append((msg_recv, msg_send))
                log.info('added translation {} => {}'.format(
                        msg_recv, msg_send))
            except ndef.DecodeError:
                break

    for msg_recv, msg_send in args.translations:
        if message == msg_recv:
            log.info('rcvd beam {}'.format(msg_recv))
            log.info('send beam {}'.format(msg_send))
            nfc.snep.SnepClient(llc).put_records(msg_send)
            break


class DefaultServer(nfc.snep.SnepServer):
    def __init__(self, args, llc):
        self.args, self.llc = args, llc
        super(DefaultServer, self).__init__(llc)

    def process_put_request(self, ndef_message):
        log.info("default snep server got put request")
        if self.args.action == "recv":
            self.args.func(self.args, self.llc, ndef_message)
        return nfc.snep.Success


class Main(cli.CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(
                title="actions", dest="action")
        subparsers.required = True
        add_send_parser(subparsers.add_parser(
                'send', help='send data to beam receiver'))
        add_recv_parser(subparsers.add_parser(
                'recv', help='receive data from beam sender'))
        super(Main, self).__init__(
                parser, groups="llcp dbg clf")
        self.default_snep_server = None

    def on_llcp_startup(self, llc):
        self.default_snep_server = DefaultServer(self.options, llc)
        return llc

    def on_llcp_connect(self, llc):
        self.default_snep_server.start()
        if self.options.action == "send":
            func, args = self.options.func, (self.options, llc)
            threading.Thread(target=func, args=args).start()
        return True


if __name__ == '__main__':
    Main().run()
