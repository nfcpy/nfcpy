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

    def make_oob_record(self, secure=True):
        record = nfc.ndef.BluetoothConfigRecord()
        record.device_address = str(self.adapter.GetProperties()["Address"])
        record.class_of_device = int(self.adapter.GetProperties()["Class"])
        record.local_device_name = str(self.adapter.GetProperties()["Name"])
        if secure:
            sp_hash, sp_rand = self.oob_adapter.ReadLocalData()
            record.simple_pairing_hash = bytearray(sp_hash)
            record.simple_pairing_rand = bytearray(sp_rand)
        return record

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
        self.remote_bdaddr = dbus.String(bdaddr)
        ssp_hash = dbus.Array(ssp_hash)
        ssp_rand = dbus.Array(ssp_rand)
	self.oob_adapter.AddRemoteData(self.remote_bdaddr, ssp_hash, ssp_rand)
        
    def create_pairing(self):
        def create_device_reply(device):
            print "Pairing succeed!"
            self.mainloop.quit()

        def create_device_error(error):
            print "Pairing failed."
            self.mainloop.quit()
      
        self.adapter.CreatePairedDevice(
            self.remote_bdaddr, "/test/agent_oob", "DisplayYesNo",
            reply_handler=create_device_reply,
            error_handler=create_device_error)

        self.mainloop.run()
    
    def register_agent(self):
        self.adapter.RegisterAgent("/test/agent_oob", "NoInputNoOutput")
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
    client = handover_connect()
    try:
        log.info("send handover request message with version 1.2")
        message = nfc.ndef.HandoverRequestMessage(version="1.2")
        message.nonce = random.randint(0, 0xffff)
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")

        log.info("send handover request message with version 1.1")
        message = nfc.ndef.HandoverRequestMessage(version="1.1")
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")

        log.info("send handover request message with version 1.15")
        message = nfc.ndef.HandoverRequestMessage(version="1.15")
        message.nonce = random.randint(0, 0xffff)
        handover_send(client, message)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")

        log.info("send handover request message with version 15.0")
        handover_send(client, "d102014872f0".decode("hex"), miu=128)
        message = handover_recv(client, timeout=3.0)
        if message.version.major != 1 and message.version.minor != 2:
            raise TestError("handover select message version is not 1.2")
    finally:
        client.close()

def test_04(options):
    """Single Bluetooth carrier.

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
        record.simple_pairing_hash = os.urandom(16)
        record.simple_pairing_rand = os.urandom(16)
        record.class_of_device = 0x10010C
        record.service_class_uuid_list = [
            "00001105-0000-1000-8000-00805f9b34fb",
            "00001106-0000-1000-8000-00805f9b34fb"]
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
            if options.relax:
                log.warning("[relax] ")
            else:
                raise TestError("no class of device attribute")
        if record.simple_pairing_hash is None:
            if options.relax:
                log.warning("[relax] no simple pairing hash attribute")
            else:
                raise TestError("no simple pairing hash attribute")
        if record.simple_pairing_rand is None:
            if options.relax:
                log.warning("[relax] no simple pairing randomizer attribute")
            else:
                raise TestError("no simple pairing randomizer attribute")
        if len(record.service_class_uuid_list) == 0:
            if options.relax:
                log.warning("[relax] no service class uuids attribute")
            else:
                raise TestError("no service class uuids attribute")
    finally:
        client.close()

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
                self.hci0 = BluetoothAdapter()
                record = nfc.ndef.BluetoothConfigRecord()
                record.device_address = self.hci0.device_address
                record.class_of_device = self.hci0.device_class
                record.local_device_name = self.hci0.device_name
                record.service_class_uuid_list = self.hci0.service_uuids
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
