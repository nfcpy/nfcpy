#!/usr/bin/python
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
log = logging.getLogger()

import os
import sys
import time
import argparse
import random

sys.path.insert(1, os.path.split(sys.path[0])[0])
from llcp_test_base import TestBase

import nfc
import nfc.llcp
import nfc.ndef
import nfc.snep
import nfc.handover

import gobject
import dbus.mainloop.glib

mime_btoob = "application/vnd.bluetooth.ep.oob"
mime_wfasc = "application/vnd.wfa.wsc"

class BluetoothAdapter(object):
    def __init__(self):
	dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
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
            log.info("Bluetooth pairing succeeded!")
            self.mainloop.quit()

        def create_device_error(error):
            log.error("Bluetooth pairing failed!")
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

        self.mainloop.run()
    
class TestError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return str(self.value)

def handover_connect():
    client = nfc.handover.HandoverClient()
    try:
        client.connect()
        log.info("connected to the remote handover server")
        return client
    except nfc.llcp.ConnectRefused:
        raise TestError("unable to connect to the handover server")

def handover_send(client, message, miu=128):
    if isinstance(message, str):
        if not client._send(message, miu):
            raise TestError("error sending handover request")
    else:
        if not client.send(message):
            raise TestError("error sending handover request")

def handover_recv(client, timeout):
    message = client._recv(timeout)
    if message is None:
        raise TestError("no answer within {0} seconds".format(int(timeout)))
    if not message.type == "urn:nfc:wkt:Hs":
        raise TestError("unexpected message type '{0}'".format(message.type))
    try:
        message = nfc.ndef.HandoverSelectMessage(message)
    except nfc.ndef.DecodeError:
        raise TestError("invalid handover select message")
    return message
        
    
def test_01(options):
    """Presence and connectivity.

    Verify that the remote device has the connection handover service
    active and that the client can open, close and re-open a connection
    with the server.
    """
    log.info("1st attempt to connect to the remote handover server")
    client = handover_connect()
    client.close()
    log.info("2nd attempt to connect to the remote handover server")
    client = handover_connect()
    client.close()

def test_02(options):
    """Empty carrier list.
    
    Verify that the handover server responds to a handover request
    without alternative carriers with a handover select message that
    also has no alternative carriers.
    """
    client = handover_connect()
    try:
        message = nfc.ndef.HandoverRequestMessage(version="1.2")
        message.nonce = random.randint(0, 0xffff)
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if len(message.carriers) > 0:
            raise TestError("handover select message returned carriers")
    finally:
        client.close()

def test_03(options):
    """Version handling.
    
    Verify that the remote handover server handles historic and future
    handover request version numbers.
    """
    record = nfc.ndef.BluetoothConfigRecord()
    record.device_address = "01:02:03:04:05:06"
    
    client = handover_connect()
    try:
        log.info("send handover request message with version 1.2")
        message = nfc.ndef.HandoverRequestMessage(version="1.2")
        message.nonce = random.randint(0, 0xffff)
        message.add_carrier(record, "active")
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")
    finally:
        client.close()

    client = handover_connect()
    try:
        log.info("send handover request message with version 1.1")
        message = nfc.ndef.HandoverRequestMessage(version="1.1")
        message.add_carrier(record, "active")
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")
    finally:
        client.close()

    client = handover_connect()
    try:
        log.info("send handover request message with version 1.15")
        message = nfc.ndef.HandoverRequestMessage(version="1.15")
        message.nonce = random.randint(0, 0xffff)
        message.add_carrier(record, "active")
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")
    finally:
        client.close()

    client = handover_connect()
    try:
        log.info("send handover request message with version 15.0")
        message = nfc.ndef.HandoverRequestMessage(version="1.2")
        message.nonce = random.randint(0, 0xffff)
        message.add_carrier(record, "active")
        data = bytearray(str(message))
        data[5] = 0xf0 # set desired version number
        handover_send(client, str(data), miu=128)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")
    finally:
        client.close()

def test_04(options):
    """Bluetooth just-works pairing.

    Verify that the `application/vnd.bluetooth.ep.oob` alternative
    carrier is correctly evaluated and replied with a all mandatory and
    recommended information. This test is only applicable if the peer
    device does have Bluetooth connectivity.
    """
    client = handover_connect()
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
        
        for carrier in options.carriers:
            if carrier.type == mime_btoob:
                record = carrier.record
        
        message.add_carrier(record, "active")
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        log.info(message.pretty())
        
        if len(message.carriers) != 1:
            raise TestError("one selected carrier is expected")
        if message.carriers[0].type != "application/vnd.bluetooth.ep.oob":
            raise TestError("a Bluetooth carrier is expected")
        record = message.carriers[0].record
        if record.local_device_name is None:
            if options.relax:
                log.warning("[relax] no local device name attribute")
            else:
                raise TestError("no local device name attribute")
        if record.local_device_name == "":
            raise TestError("empty local device name attribute")
        if record.class_of_device is None:
            log.warning("there is no class of device attribute")
        if len(record.service_class_uuid_list) == 0:
            log.warning("there are no service class uuids attribute")
        if not record.simple_pairing_hash is None:
            if options.relax:
                log.warning("[relax] ssp hash not expected in just-works mode")
            else:
                raise TestError("ssp hash not expected in just-works mode")
        if not record.simple_pairing_rand is None:
            if options.relax:
                log.warning("[relax] ssp rand not expected in just-works mode")
            else:
                raise TestError("ssp rand not expected in just-works mode")
    finally:
        client.close()

    hci0 = BluetoothAdapter()
    hci0.create_pairing(record.device_address)

def test_05(options):
    """Bluetooth secure pairing.

    Verify that the `application/vnd.bluetooth.ep.oob` alternative
    carrier is correctly evaluated and replied with a all mandatory and
    recommended information. This test is only applicable if the peer
    device does have Bluetooth connectivity.
    """
    client = handover_connect()
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

        for carrier in options.carriers:
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
        log.info(message.pretty())
        
        if len(message.carriers) != 1:
            raise TestError("one selected carrier is expected")
        if message.carriers[0].type != "application/vnd.bluetooth.ep.oob":
            raise TestError("a Bluetooth carrier is expected")
        record = message.carriers[0].record
        if record.local_device_name is None:
            if options.relax:
                log.warning("[relax] no local device name attribute")
            else:
                raise TestError("no local device name attribute")
        if record.local_device_name == "":
            raise TestError("empty local device name attribute")
        if record.class_of_device is None:
            log.warning("there is no class of device attribute")
        if len(record.service_class_uuid_list) == 0:
            log.warning("there are no service class uuids attribute")
        if record.simple_pairing_hash is None:
            if options.relax:
                log.warning("[relax] ssp hash required for secure pairing")
            else:
                raise TestError("ssp hash required for secure pairing")
        if record.simple_pairing_rand is None:
            if options.relax:
                log.warning("[relax] ssp rand required for secure pairing")
            else:
                raise TestError("ssp rand required for secure pairing")
    finally:
        client.close()

    ssp_hash = record.simple_pairing_hash
    ssp_rand = record.simple_pairing_rand
    hci0.create_pairing(record.device_address, ssp_hash, ssp_rand)

class HandoverTestClient(TestBase):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]... [CARRIER]...',
            description="")
        parser.add_argument(
            "carriers", metavar="CARRIER", nargs="*",
            type=argparse.FileType('r'),
            help="supported carrier")
        parser.add_argument(
            "-t", "--test", action="append", type=int, metavar="N", default=[],
            help="run test number N")
        parser.add_argument(
            "--relax", action="store_true",
            help="relax on verifying optional parts")        
        parser.add_argument(
            "--skip-local", action="store_true",
            help="skip local carrier detection")        
        
        super(HandoverTestClient, self).__init__(parser)

        if sum([1 for f in self.options.carriers if f.name == "<stdin>"]) > 1:
            log.error("only one carrier file may be read from stdin")
            raise SystemExit(1)

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
        
        #if self.options.quirks:
        #    log.warning("quirks: will accept SNEP PUT 'Hr' requests "
        #                "used by Android 4.1.0 devices")

    def main(self):
        test_suite = sorted([globals().get(k) for k in globals().keys()
                             if k.startswith("test_")])
    
        for test in self.options.test:
            if test > 0 and test <= len(test_suite):
                test_mode = ("in quirks mode" if self.options.quirks else
                             "in relax mode" if self.options.relax else "")
                try:
                    test_func = test_suite[test-1]
                    test_name = test_func.__doc__.splitlines()[0]
                    test_name = test_name.lower().strip('.')
                    log.info("*** test scenario {0!r} ***".format(test_name))
                    test_func(self.options)
                    log.info("PASSED {0!r} {1}".format(test_name, test_mode))
                except TestError as error:
                    log.error("FAILED {0!r} because {1}"
                              .format(test_name, error))
            else:
                log.info("invalid test number '{0}'".format(test))

        if self.options.quirks:
            log.warning("quirks: waiting for device removal to avoid Android "
                        "(before 4.1) crash on intentional link deactivation")
            while nfc.llcp.connected():
                time.sleep(1)
                
        raise SystemExit
        
if __name__ == '__main__':
    HandoverTestClient().start()
