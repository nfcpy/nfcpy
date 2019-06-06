#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
from cli import TestFail
import argparse
import binascii
import logging
import ndef
import nfc
import cli
import os


log = logging.getLogger('main')

mime_btoob = "application/vnd.bluetooth.ep.oob"
mime_wfasc = "application/vnd.wfa.wsc"


def info(message, prefix="  "):
    log.info(prefix + message)


def handover_connect(llc, options):
    client = nfc.handover.HandoverClient(llc)
    try:
        client.connect(recv_miu=options.recv_miu, recv_buf=options.recv_buf)
        info("connected to the remote handover server")
        return client
    except nfc.llcp.ConnectRefused:
        raise TestFail("unable to connect to the handover server")


def handover_send(client, message, miu=128):
    if isinstance(message, (bytes, bytearray)):
        if not client.send_octets(message, miu):
            raise TestFail("error sending handover request octets")
    else:
        if not client.send_records(message):
            raise TestFail("error sending handover request records")


def handover_recv(client, timeout, raw=False):
    records = client.recv_records(timeout)

    if not records:
        raise TestFail("no answer within {0} seconds".format(int(timeout)))

    if not records[0].type == "urn:nfc:wkt:Hs":
        raise TestFail("unexpected message type '{0}'".format(records[0].type))

    return records


description = """
Execute connection handover tests. The peer device must have a
connection handover service running.
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
                "--relax", action="store_true",
                help="relax on verifying optional parts")

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
                parser, groups="test llcp dbg clf iop")

        if sum([1 for f in self.options.carriers if f.name == "<stdin>"]) > 1:
            log.error("only one carrier file may be read from stdin")
            raise SystemExit(1)

        carriers = []

        for index, carrier in enumerate(self.options.carriers):
            data = carrier.read()
            try:
                data = binascii.unhexlify(data)
            except (binascii.Error, TypeError):
                pass
            records = list(ndef.message_decoder(data))
            log.info("add carrier: {}".format(records[0]))
            carriers.append(records)

        self.options.carriers = carriers

    def test_01(self, llc):
        """Presence and connectivity"""

        info("1st attempt to connect to the remote handover server")
        client = handover_connect(llc, self.options)
        client.close()
        info("2nd attempt to connect to the remote handover server")
        client = handover_connect(llc, self.options)
        client.close()

    def test_02(self, llc):
        """Empty carrier list"""

        client = handover_connect(llc, self.options)
        try:
            hr_record = ndef.HandoverRequestRecord("1.2", os.urandom(2))
            handover_send(client, [hr_record])
            records = handover_recv(client, timeout=3.0)
            if len(records[0].alternative_carriers) > 0:
                raise TestFail("handover select message returned carriers")
        finally:
            client.close()

    def test_03(self, llc):
        """Version handling"""

        bt_record = ndef.BluetoothEasyPairingRecord('01:02:03:04:05:06')
        bt_record.name = 'carrier-1'

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.2")
            hr_record = ndef.HandoverRequestRecord('1.2', os.urandom(2))
            hr_record.add_alternative_carrier('active', bt_record.name)
            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            if records[0].version_string != "1.2":
                raise TestFail("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.1")
            hr_record = ndef.HandoverRequestRecord('1.1', os.urandom(2))
            hr_record.add_alternative_carrier('active', bt_record.name)
            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            if records[0].version_string != "1.2":
                raise TestFail("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.15")
            hr_record = ndef.HandoverRequestRecord('1.15', os.urandom(2))
            hr_record.add_alternative_carrier('active', bt_record.name)
            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            if records[0].version_string != "1.2":
                raise TestFail("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 15.0")
            hr_record = ndef.HandoverRequestRecord('15.0', os.urandom(2))
            hr_record.add_alternative_carrier('active', bt_record.name)
            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            if records[0].version_string != "1.2":
                raise TestFail("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

    def test_04(self, llc):
        """Bluetooth just-works pairing"""

        client = handover_connect(llc, self.options)
        try:
            bt_record = ndef.BluetoothEasyPairingRecord("01:02:03:04:05:06")
            bt_record.name = "carrier-1"
            bt_record.device_name = "Handover Test Client"
            bt_record.device_class = 0x10010C
            bt_record.add_service_class(0x1105)
            bt_record.add_service_class(0x1106)

            hr_record = ndef.HandoverRequestRecord("1.2", os.urandom(2))
            hr_record.add_alternative_carrier("active", bt_record.name)

            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))
            hs_record, bt_record = records

            if len(hs_record.alternative_carriers) != 1:
                raise TestFail("one selected carrier is expected")
            if bt_record.type != "application/vnd.bluetooth.ep.oob":
                raise TestFail("a Bluetooth carrier is expected")
            if bt_record.device_name is None:
                if self.options.relax:
                    log.warning("no local device name attribute")
                else:
                    raise TestFail("no local device name attribute")
            if bt_record.device_name == "":
                raise TestFail("empty local device name attribute")
            if bt_record.device_class is None:
                log.warning("there is no class of device attribute")
            if len(bt_record.service_class_list) == 0:
                log.warning("there are no service class UUIDs")
            if bt_record.simple_pairing_hash_256 is not None:
                if self.options.relax:
                    log.warning("ssp hash not expected in just-works mode")
                else:
                    raise TestFail("ssp hash not expected in just-works mode")
            if bt_record.simple_pairing_randomizer_256 is not None:
                if self.options.relax:
                    log.warning("ssp rand not expected in just-works mode")
                else:
                    raise TestFail("ssp rand not expected in just-works mode")
        finally:
            client.close()

    def test_05(self, llc):
        """Bluetooth secure pairing"""

        client = handover_connect(llc, self.options)
        try:
            bt_record = ndef.BluetoothEasyPairingRecord("01:02:03:04:05:06")
            bt_record.name = "carrier-1"
            bt_record.device_name = "Handover Test Client"
            bt_record.device_class = 0x10010C
            bt_record.add_service_class(0x1105)
            bt_record.add_service_class(0x1106)
            bt_record.simple_pairing_hash_256 = \
                0x1234567890ABCDEF1234567890ABCDEF
            bt_record.simple_pairing_randomizer_256 = \
                0x010203040506070809000A0B0C0D0E0F

            hr_record = ndef.HandoverRequestRecord("1.2", os.urandom(2))
            hr_record.add_alternative_carrier("active", bt_record.name)

            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))
            hs_record, bt_record = records

            if len(hs_record.alternative_carriers) != 1:
                raise TestFail("one selected carrier is expected")
            if bt_record.type != "application/vnd.bluetooth.ep.oob":
                raise TestFail("a Bluetooth carrier is expected")
            if bt_record.device_name is None:
                if self.options.relax:
                    log.warning("no local device name attribute")
                else:
                    raise TestFail("no local device name attribute")
            if bt_record.device_name == "":
                raise TestFail("empty local device name attribute")
            if bt_record.device_class is None:
                log.warning("there is no class of device attribute")
            if len(bt_record.service_class_list) == 0:
                log.warning("there are no service class UUIDs")
            if bt_record.simple_pairing_hash_256 is None:
                if self.options.relax:
                    log.warning("ssp hash required for secure pairing")
                else:
                    raise TestFail("ssp hash required for secure pairing")
            if bt_record.simple_pairing_randomizer_256 is None:
                if self.options.relax:
                    log.warning("ssp rand required for secure pairing")
                else:
                    raise TestFail("ssp rand required for secure pairing")
        finally:
            client.close()

    def test_06(self, llc):
        """Unknown carrier type"""

        client = handover_connect(llc, self.options)
        try:
            unknown_carrier = "urn:nfc:ext:nfcpy.org:unknown-carrier-type"
            records = [ndef.HandoverRequestRecord("1.2", os.urandom(2)),
                       ndef.Record(unknown_carrier, "unknown-carrier")]
            records[0].add_alternative_carrier("active", records[1].name)

            handover_send(client, records)
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))

            if records[0].version_info.major != 1:
                raise TestFail("handover major version is not 1")
            if len(records[0].alternative_carriers) != 0:
                raise TestFail("an empty carrier selection is expected")
        finally:
            client.close()

    def test_07(self, llc):
        """Two handover requests"""

        client = handover_connect(llc, self.options)
        try:
            unknown_carrier = "urn:nfc:ext:nfcpy.org:unknown-carrier-type"
            records = [ndef.HandoverRequestRecord("1.2", os.urandom(2)),
                       ndef.Record(unknown_carrier, "unknown-carrier")]
            records[0].add_alternative_carrier("active", records[1].name)

            info("request carrier {}".format(records[1].type))
            handover_send(client, records)
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))

            if records[0].version_info.major != 1:
                raise TestFail("handover major version is not 1")
            if len(records[0].alternative_carriers) != 0:
                raise TestFail("an empty carrier selection is expected first")

            bt_record = ndef.BluetoothEasyPairingRecord("01:02:03:04:05:06")
            bt_record.name = "carrier-1"
            bt_record.device_name = "Handover Test Client"
            bt_record.device_class = 0x10010C
            bt_record.add_service_class(0x1105)
            bt_record.add_service_class(0x1106)

            hr_record = ndef.HandoverRequestRecord("1.2", os.urandom(2))
            hr_record.add_alternative_carrier("active", bt_record.name)

            info("propose carrier {}".format(bt_record.type))
            handover_send(client, [hr_record, bt_record])
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))

        finally:
            client.close()

    def test_08(self, llc):
        """Skip meaningless records"""

        client = handover_connect(llc, self.options)
        try:
            bt_record = ndef.BluetoothEasyPairingRecord("01:02:03:04:05:06")
            bt_record.name = "carrier-1"
            bt_record.device_name = "Handover Test Client"
            bt_record.device_class = 0x10010C
            bt_record.add_service_class(0x1105)
            bt_record.add_service_class(0x1106)

            hr_record = ndef.HandoverRequestRecord("1.2", os.urandom(2))
            hr_record.add_alternative_carrier("active", bt_record.name)

            handover_send(client, [hr_record, ndef.TextRecord("X"), bt_record])
            records = handover_recv(client, timeout=3.0)
            info("received {}".format(records[0].type))
            hs_record, bt_record = records

            if len(hs_record.alternative_carriers) != 1:
                raise TestFail("one selected carrier is expected")
            if bt_record.type != "application/vnd.bluetooth.ep.oob":
                raise TestFail("a Bluetooth carrier is expected")
        finally:
            client.close()


if __name__ == '__main__':
    TestProgram().run()
