#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import argparse
import binascii
import logging
import time
import ndef
import nfc
import cli

log = logging.getLogger('main')

mime_btoob = "application/vnd.bluetooth.ep.oob"
mime_wfasc = "application/vnd.wfa.wsc"


class HandoverServer(nfc.handover.HandoverServer):
    def __init__(self, llc, select_carrier_func, options):
        super(HandoverServer, self).__init__(
                llc, recv_miu=options.recv_miu, recv_buf=options.recv_buf)
        self.select_carrier = select_carrier_func

    def process_handover_request_message(self, records):
        return self.select_carrier(records)


class DefaultSnepServer(nfc.snep.SnepServer):
    def __init__(self, llc):
        super(DefaultSnepServer, self).__init__(llc, 'urn:nfc:sn:snep')

    def process_put_request(self, ndef_message):
        log.info("default snep server got put request")
        log.info('\n  '.join(str(record) for record in ndef_message))
        return nfc.snep.Success

    def process_get_request(self, ndef_message):
        log.info("default snep server got GET request")
        log.info('\n  '.join(str(record) for record in ndef_message))
        return nfc.snep.NotImplemented


description = """
Run a connection handover server component with various test options.
"""


class TestProgram(cli.CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
                usage='%(prog)s [OPTION]... [CARRIER]...',
                formatter_class=argparse.RawDescriptionHelpFormatter,
                description=description)
        parser.add_argument(
                "carriers", metavar="CARRIER", nargs="*",
                type=argparse.FileType('rb'),
                help="supported carrier")
        parser.add_argument(
                "--select", metavar="NUM", type=int, default=1,
                help="select up to NUM carriers (default: %(default)s))")
        parser.add_argument(
                "--delay", type=int, metavar="INT",
                help="delay the response for INT milliseconds")

        def miu(string):
            value = int(string)
            if value < 128 or value > 2176:
                msg = "invalid choice: %d (choose from 128 to 2176)" % value
                raise argparse.ArgumentTypeError(msg)
            return value

        parser.add_argument(
                "--recv-miu", type=miu, metavar="INT", default=128,
                help="data link connection receive miu (default: %(default)s)")

        def buf(string):
            value = int(string)
            if value < 0 or value > 15:
                msg = "invalid choice: %d (choose from 0 to 15)" % value
                raise argparse.ArgumentTypeError(msg)
            return value

        parser.add_argument(
            "--recv-buf", type=buf, metavar="INT", default=2,
            help="data link connection receive window (default: %(default)s)")

        super(TestProgram, self).__init__(
                parser, groups="llcp dbg clf iop")

        if sum([1 for f in self.options.carriers if f.name == "<stdin>"]) > 1:
            log.error("only one carrier file may be read from stdin")
            raise SystemExit(1)

        self.options.selectable = []
        for index, carrier in enumerate(self.options.carriers):
            data = carrier.read()
            try:
                data = binascii.unhexlify(data)
            except (binascii.Error, TypeError):
                pass
            records = list(ndef.message_decoder(data))
            records[0].name = 'carrier-{}'.format(index)
            log.info("add carrier: {}".format(records[0]))
            self.options.selectable.append(records)

        self.select_carrier_lock = threading.Lock()
        self.handover_service = None
        self.snep_service = None

    def on_llcp_startup(self, llc):
        self.handover_service = HandoverServer(
                llc, self.select_carrier, self.options)
        self.snep_service = DefaultSnepServer(llc)
        return llc

    def on_llcp_connect(self, llc):
        self.handover_service.start()
        self.snep_service.start()
        return True

    def select_carrier(self, hr_records):
        self.select_carrier_lock.acquire()
        log.info("<<< %s", '\n  '.join(str(r) for r in hr_records))

        hs_records = [ndef.HandoverSelectRecord('1.2')]

        if hr_records[0].version_info.minor == 0 and self.options.quirks:
            log.warning("quirks: accept handover version 1.0 as 1.1")
        elif hr_records[0].version_info.minor not in range(1, 3):
            log.warning("unsupported minor version")
            self.select_carrier_lock.release()
            return hs_records

        remote_carrier_records = dict(
            (record.name, record) for record in hr_records[1:] if record.name)

        for ac in hr_records[0].alternative_carriers:
            record = remote_carrier_records[ac.carrier_data_reference]
            if record.type == 'urn:nfc:wkt:Hc':
                remote_carrier_type = record.carrier_type
            else:
                remote_carrier_type = record.type

            for carrier_records in self.options.selectable:
                selected = len(hs_records[0].alternative_carriers)
                if not selected < self.options.select:
                    break

                if carrier_records[0].type == 'urn:nfc:wkt:Hc':
                    local_carrier_type = carrier_records[0].carrier_type
                else:
                    local_carrier_type = carrier_records[0].type

                if remote_carrier_type == local_carrier_type:
                    log.info("match for {0}".format(local_carrier_type))
                    cdr = carrier_records[0].name
                    adr = [record.name for record in carrier_records]
                    hs_records[0].add_alternative_carrier('active', cdr, *adr)
                    hs_records.extend(carrier_records)

        log.info(">>> %s", '\n  '.join(str(r) for r in hs_records))
        self.select_carrier_lock.release()

        if self.options.delay:
            log.info("delay response for {0} ms".format(self.options.delay))
            time.sleep(self.options.delay * 1e-3)

        return hs_records


if __name__ == '__main__':
    TestProgram().run()
