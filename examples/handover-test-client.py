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

import os
import sys
import time
import argparse
import random

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface, TestError

import nfc
import nfc.llcp
import nfc.ndef
import nfc.snep
import nfc.handover

import gobject
import dbus.mainloop.glib

mime_btoob = "application/vnd.bluetooth.ep.oob"
mime_wfasc = "application/vnd.wfa.wsc"

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
gobject.threads_init()

def info(message, prefix="  "):
    log.info(prefix + message)

class BluetoothAdapter(object):
    def __init__(self):
	self.mainloop = gobject.MainLoop()
	bus = dbus.SystemBus()
        proxy = bus.get_object("org.bluez", "/")
	manager = dbus.Interface(proxy, "org.bluez.Manager")
	adapter_path = manager.DefaultAdapter()
        proxy = bus.get_object("org.bluez", adapter_path)
	self.adapter = dbus.Interface(proxy, "org.bluez.Adapter")
	self.oob_adapter = dbus.Interface(proxy, "org.bluez.OutOfBand")

    @property
    def device_address(self):
        return str(self.adapter.GetProperties()["Address"])

    @property
    def device_class(self):
        return int(self.adapter.GetProperties()["Class"])

    @property
    def device_name(self):
        return str(self.adapter.GetProperties()["Name"])

    @property
    def service_uuids(self):
        return map(str, self.adapter.GetProperties()["UUIDs"])

    def get_ssp_data(self):
        ssp_hash, ssp_rand = self.oob_adapter.ReadLocalData()
        return bytearray(ssp_hash), bytearray(ssp_rand)

    def set_ssp_data(self, bdaddr, ssp_hash, ssp_rand):
        ssp_hash = dbus.Array(ssp_hash)
        ssp_rand = dbus.Array(ssp_rand)
	self.oob_adapter.AddRemoteData(bdaddr, ssp_hash, ssp_rand)
        
    def create_pairing(self, bdaddr, ssp_hash=None, ssp_rand=None):
        def create_device_reply(device):
            info("Bluetooth pairing succeeded!")
            self.connected = True
            self.mainloop.quit()

        def create_device_error(error):
            info("Bluetooth pairing failed!")
            self.connected = False
            self.mainloop.quit()

        if ssp_hash and ssp_rand:
            self.oob_adapter.AddRemoteData(bdaddr, ssp_hash, ssp_rand)
            pairing_mode = "DisplayYesNo"
        else:
            pairing_mode = "NoInputNoOutput"
            
        self.adapter.CreatePairedDevice(
            bdaddr, "/test/agent_oob", pairing_mode,
            reply_handler=create_device_reply,
            error_handler=create_device_error)

        self.connected = False
        self.mainloop.run()
        return self.connected
    
def handover_connect(llc, options):
    client = nfc.handover.HandoverClient(llc)
    try:
        client.connect(recv_miu=options.recv_miu, recv_buf=options.recv_buf)
        info("connected to the remote handover server")
        return client
    except nfc.llcp.ConnectRefused:
        if not options.quirks:
            raise TestError("unable to connect to the handover server")
        
    log.error("unable to connect to the handover server")
    log.warning("[quirks] trying the snep server get method")
    client = nfc.snep.SnepClient()
    try:
        client.connect("urn:nfc:sn:snep")
        info("[quirks] connected to the remote default snep server")
        return client
    except nfc.llcp.ConnectRefused:
        raise TestError("unable to connect to the default snep server")

# global object to store the handover response in quirks mode when the
# handover message exchange is via the snep default server, as done by
# the initial Android Jelly Bean release.
quirks_handover_snep_response = None

def handover_send(client, message, miu=128):
    if isinstance(client, nfc.handover.HandoverClient):
        if isinstance(message, str):
            if not client._send(message, miu):
                raise TestError("error sending handover request")
        else:
            if not client.send(message):
                raise TestError("error sending handover request")
    elif isinstance(client, nfc.snep.SnepClient):
        global quirks_handover_snep_response
        quirks_handover_snep_response = None
        try:
            message = client.get(message, timeout=3.0)
        except nfc.snep.SnepError as err:
            raise TestError("remote snep server returned '{0}'".format(err))
        else:
            quirks_handover_snep_response = message
    else:
        raise ValueError("wrong client argument type")

def handover_recv(client, timeout, raw=False):
    message = None
    
    if isinstance(client, nfc.handover.HandoverClient):
        message = client._recv(timeout)
    elif isinstance(client, nfc.snep.SnepClient):
        global quirks_handover_snep_response
        if quirks_handover_snep_response:
            message = quirks_handover_snep_response
            quirks_handover_snep_response = None
    else:
        raise ValueError("wrong client argument type")
    
    if message is None:
        raise TestError("no answer within {0} seconds".format(int(timeout)))
    if not message.type == "urn:nfc:wkt:Hs":
        raise TestError("unexpected message type '{0}'".format(message.type))
    
    if not raw:
        try:
            message = nfc.ndef.HandoverSelectMessage(message)
        except nfc.ndef.DecodeError:
            raise TestError("invalid handover select message")
        
    return message
    
description = """
Execute connection handover tests. The peer device must have a
connection handover service running.
"""
class TestProgram(CommandLineInterface):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]... [CARRIER]...',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=description)
        parser.add_argument(
            "carriers", metavar="CARRIER", nargs="*",
            type=argparse.FileType('r'),
            help="supported carrier")
        parser.add_argument(
            "--relax", action="store_true",
            help="relax on verifying optional parts")        
        parser.add_argument(
            "--skip-local", action="store_true",
            help="skip local carrier detection")
        def miu(string):
            value = int(string)
            if value <128 or value > 2176:
                msg = "invalid choice: %d (choose from 128 to 2176)" % value
                raise argparse.ArgumentTypeError(msg)
            return value
        parser.add_argument(
            "--recv-miu", type=miu, metavar="INT", default=128,
            help="data link connection receive miu (default: %(default)s)")
        def buf(string):
            value = int(string)
            if value <0 or value > 15:
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

        if self.options.quirks:
            self.options.relax = True
            
        requestable = nfc.ndef.HandoverRequestMessage(version="1.0")
        
        for index, carrier in enumerate(self.options.carriers):
            data = carrier.read()
            try: data = data.decode("hex")
            except TypeError: pass
            message = nfc.ndef.Message(data)
            if message.type in ("urn:nfc:wkt:Hs", "urn:nfc:wkt:Hr"):
                message = (nfc.ndef.HandoverSelectMessage(message)
                           if message.type == "urn:nfc:wkt:Hs" else
                           nfc.ndef.HandoverRequestMessage(message))
                for carrier in message.carriers:
                    requestable.add_carrier(
                        carrier.record, carrier.power_state,
                        carrier.auxiliary_data_records)
                    log.info("add specified carrier: {0}".format(carrier.type))
            else:
                requestable.add_carrier(message[0], "active", message[1:])
                log.info("add specified carrier: {0}".format(message.type))
            
        if not self.options.skip_local:
            if sys.platform == "linux2":
                hci0 = BluetoothAdapter()
                record = nfc.ndef.BluetoothConfigRecord()
                record.device_address = hci0.device_address
                record.class_of_device = hci0.device_class
                record.local_device_name = hci0.device_name
                record.service_class_uuid_list = hci0.service_uuids
                requestable.add_carrier(record, "active")
                log.info("add discovered carrier: {0}".format(record.type))

        self.options.carriers = requestable.carriers
        
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
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            if len(message.carriers) > 0:
                raise TestError("handover select message returned carriers")
        finally:
            client.close()

    def test_03(self, llc):
        """Version handling"""

        record = nfc.ndef.BluetoothConfigRecord()
        record.device_address = "01:02:03:04:05:06"

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.2")
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            if message.version.major != 1 and message.version.minor != 2:
                raise TestError("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.1")
            message = nfc.ndef.HandoverRequestMessage(version="1.1")
            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            if message.version.major != 1 and message.version.minor != 2:
                raise TestError("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 1.15")
            message = nfc.ndef.HandoverRequestMessage(version="1.15")
            message.nonce = random.randint(0, 0xffff)
            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            if message.version.major != 1 and message.version.minor != 2:
                raise TestError("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

        client = handover_connect(llc, self.options)
        try:
            info("send handover request message with version 15.0")
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            message.add_carrier(record, "active")
            data = bytearray(str(message))
            data[5] = 0xf0 # set desired version number
            handover_send(client, str(data), miu=128)
            message = handover_recv(client, timeout=3.0)
            if message.version.major != 1 and message.version.minor != 2:
                raise TestError("handover select message version is not 1.2")
            info("received handover select message version 1.2")
        finally:
            client.close()

    def test_04(self, llc):
        """Bluetooth just-works pairing"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            record = nfc.ndef.BluetoothConfigRecord()
            record.device_address = "01:02:03:04:05:06"
            record.local_device_name = "Handover Test Client"
            record.class_of_device = 0x10010C
            record.service_class_uuid_list = [
                "00001105-0000-1000-8000-00805f9b34fb",
                "00001106-0000-1000-8000-00805f9b34fb"]
            record.simple_pairing_hash = None
            record.simple_pairing_rand = None

            for carrier in self.options.carriers:
                if carrier.type == mime_btoob:
                    record = carrier.record

            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

            if len(message.carriers) != 1:
                raise TestError("one selected carrier is expected")
            if message.carriers[0].type != "application/vnd.bluetooth.ep.oob":
                raise TestError("a Bluetooth carrier is expected")
            record = message.carriers[0].record
            if record.local_device_name is None:
                if self.options.relax:
                    log.warning("no local device name attribute")
                else:
                    raise TestError("no local device name attribute")
            if record.local_device_name == "":
                raise TestError("empty local device name attribute")
            if record.class_of_device is None:
                log.warning("there is no class of device attribute")
            if len(record.service_class_uuid_list) == 0:
                log.warning("there are no service class uuids attribute")
            if not record.simple_pairing_hash is None:
                if self.options.relax:
                    log.warning("ssp hash not expected in just-works mode")
                else:
                    raise TestError("ssp hash not expected in just-works mode")
            if not record.simple_pairing_rand is None:
                if self.options.relax:
                    log.warning("ssp rand not expected in just-works mode")
                else:
                    raise TestError("ssp rand not expected in just-works mode")
        finally:
            client.close()

        hci0 = BluetoothAdapter()
        connected = hci0.create_pairing(record.device_address)
        if not connected:
            raise TestError("Bluetooth connection was not established")

    def test_05(self, llc):
        """Bluetooth secure pairing"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            record = nfc.ndef.BluetoothConfigRecord()
            record.device_address = "01:02:03:04:05:06"
            record.local_device_name = "Handover Test Client"
            record.class_of_device = 0x10010C
            record.service_class_uuid_list = [
                "00001105-0000-1000-8000-00805f9b34fb",
                "00001106-0000-1000-8000-00805f9b34fb"]
            record.simple_pairing_hash = os.urandom(16)
            record.simple_pairing_rand = os.urandom(16)

            for carrier in self.options.carriers:
                if carrier.type == mime_btoob:
                    hci0 = BluetoothAdapter()
                    if carrier.record.device_address == hci0.device_address:
                        ssp_hash, ssp_rand = hci0.get_ssp_data()
                        carrier.record.simple_pairing_hash = ssp_hash
                        carrier.record.simple_pairing_rand = ssp_rand
                    record = carrier.record

            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

            if len(message.carriers) != 1:
                raise TestError("one selected carrier is expected")
            if message.carriers[0].type != "application/vnd.bluetooth.ep.oob":
                raise TestError("a Bluetooth carrier is expected")
            record = message.carriers[0].record
            if record.local_device_name is None:
                if self.options.relax:
                    log.warning("no local device name attribute")
                else:
                    raise TestError("no local device name attribute")
            if record.local_device_name == "":
                raise TestError("empty local device name attribute")
            if record.class_of_device is None:
                log.warning("there is no class of device attribute")
            if len(record.service_class_uuid_list) == 0:
                log.warning("there are no service class uuids attribute")
            if record.simple_pairing_hash is None:
                if self.options.relax:
                    log.warning("ssp hash required for secure pairing")
                else:
                    raise TestError("ssp hash required for secure pairing")
            if record.simple_pairing_rand is None:
                if self.options.relax:
                    log.warning("ssp rand required for secure pairing")
                else:
                    raise TestError("ssp rand required for secure pairing")
        finally:
            client.close()

        ssp_hash = record.simple_pairing_hash
        ssp_rand = record.simple_pairing_rand
        connected = hci0.create_pairing(record.device_address,
                                        ssp_hash, ssp_rand)
        if not connected:
            raise TestError("Bluetooth connection was not established")

    def test_06(self, llc):
        """Unknown carrier type"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            unknown_carrier = "urn:nfc:ext:nfcpy.org:unknown-carrier-type"
            record = nfc.ndef.Record(unknown_carrier)
            message.add_carrier(record, "active")

            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

            if message.version.major != 1:
                raise TestError("handover major version is not 1")
            if len(message.carriers) != 0:
                raise TestError("an empty carrier selection is expected")
        finally:
            client.close()

    def test_07(self, llc):
        """Two handover requests"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            unknown_carrier = "urn:nfc:ext:nfcpy.org:unknown-carrier-type"
            record = nfc.ndef.Record(unknown_carrier)
            message.add_carrier(record, "active")

            info("propose carrier {0!r}".format(message.carriers[0].type))
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

            if message.version.major != 1:
                raise TestError("handover major version is not 1")
            if len(message.carriers) != 0:
                raise TestError("an empty carrier selection is expected first")

            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            record = nfc.ndef.BluetoothConfigRecord()
            record.device_address = "01:02:03:04:05:06"
            record.local_device_name = "Handover Test Client"
            record.class_of_device = 0x10010C
            record.service_class_uuid_list = [
                "00001105-0000-1000-8000-00805f9b34fb",
                "00001106-0000-1000-8000-00805f9b34fb"]
            record.simple_pairing_hash = None
            record.simple_pairing_rand = None
            for carrier in self.options.carriers:
                if carrier.type == mime_btoob:
                    record = carrier.record
            message.add_carrier(record, "active")

            info("propose carrier {0!r}".format(message.carriers[0].type))
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

        finally:
            client.close()

    def test_08(self, llc):
        """Reserved-future-use check"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            record = nfc.ndef.BluetoothConfigRecord()
            record.device_address = "01:02:03:04:05:06"
            record.local_device_name = "Handover Test Client"
            record.class_of_device = 0x10010C
            record.service_class_uuid_list = [
                "00001105-0000-1000-8000-00805f9b34fb",
                "00001106-0000-1000-8000-00805f9b34fb"]
            record.simple_pairing_hash = None
            record.simple_pairing_rand = None

            for carrier in self.options.carriers:
                if carrier.type == mime_btoob:
                    record = carrier.record

            message.add_carrier(record, "active")
            handover_send(client, message)
            message = handover_recv(client, timeout=3.0, raw=True)
            try:
                info("received {0!r}\n".format(message.type) +
                         nfc.ndef.HandoverSelectMessage(message).pretty(2))
            except nfc.ndef.DecodeError:
                raise TestError("decoding errors in received message")

            if message[0].data[0] != "\x12":
                raise TestError("handover message version 1.2 is required")
            if len(message[0].data) == 1:
                raise TestError("non-empty carrier selection is required")

            try:
                message = nfc.ndef.Message(message[0].data[1:])
            except nfc.ndef.FormatError as e:
                raise TestError(str(e))
            else:
                record = message[0]
                if record.type != "urn:nfc:wkt:ac":
                    raise TestError("no alternative carrier record")
                data = bytearray(record.data)
                if data[0] & 0xfc != 0:
                    raise TestError("rfu bits set in 1st octet of ac record")
                data = data[2+data[1]:] # carrier data reference
                aux_ref_count = data.pop(0)
                for i in range(aux_ref_count):
                    data = data[1+data[1]:] # auxiliary data reference
                if len(data) != 0:
                    raise TestError("reserved bytes used at end of ac record")

        finally:
            client.close()

    def test_09(self, llc):
        """Skip meaningless records"""

        client = handover_connect(llc, self.options)
        try:
            message = nfc.ndef.HandoverRequestMessage(version="1.2")
            message.nonce = random.randint(0, 0xffff)
            record = nfc.ndef.BluetoothConfigRecord()
            record.device_address = "01:02:03:04:05:06"
            record.local_device_name = "Handover Test Client"
            record.class_of_device = 0x10010C
            record.service_class_uuid_list = [
                "00001105-0000-1000-8000-00805f9b34fb",
                "00001106-0000-1000-8000-00805f9b34fb"]
            record.simple_pairing_hash = None
            record.simple_pairing_rand = None

            for carrier in self.options.carriers:
                if carrier.type == mime_btoob:
                    record = carrier.record

            message.add_carrier(record, "active")

            message = nfc.ndef.Message(str(message))
            hr_records = nfc.ndef.Message(message[0].data[1:])
            hr_records.insert(i=0, record=nfc.ndef.TextRecord("text"))
            message[0].data = '\x12' + str(hr_records)

            handover_send(client, message)
            message = handover_recv(client, timeout=3.0)
            info("received {0!r}\n".format(message.type)
                     + message.pretty(2))

            if len(message.carriers) != 1:
                raise TestError("one selected carrier is expected")
            if message.carriers[0].type != "application/vnd.bluetooth.ep.oob":
                raise TestError("a Bluetooth carrier is expected")
        finally:
            client.close()

if __name__ == '__main__':
    TestProgram().run()
