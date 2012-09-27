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

def trace(func):
    def _func(*args, **kwargs):
        scenario = func.__doc__.splitlines()[0].lower().strip('.')
        log.info("*** running scenario '{0}' ***".format(scenario))
        return func(*args, **kwargs)
    return _func

@trace
def test_01():
    """Connect and disconnect.

    Verify that the remote device has a connection handover server
    running and a client can open and close a connection with the
    server.
    """
    client = nfc.handover.HandoverClient()
    try:
        client.connect()
        log.info("connected to the remote handover server")
    except nfc.llcp.ConnectRefused:
        raise TestError("remote device does not have a handover service")

@trace
def test_02():
    """Connect and reconnect.

    Verify that the handover server accepts a subsequent connection
    after a first one was established and released.
    """
    client = nfc.handover.HandoverClient()
    try:
        client.connect()
        client.close()
        log.info("connected to the remote handover server")
    except nfc.llcp.ConnectRefused:
        raise TestError("remote device does not have a handover service")
    try:
        client.connect()
        log.info("reconnected to the remote handover server")
    except nfc.llcp.ConnectRefused:
        raise TestError("remote device refused the subsequent connect")

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
            "--skip-local", action="store_true",
            help="skip local carrier detection")        
        
        super(HandoverTestClient, self).__init__(parser)

        #if self.options.quirks:
        #    log.warning("quirks: will accept SNEP PUT 'Hr' requests "
        #                "used by Android 4.1.0 devices")

    def main(self):
        test_suite = sorted([globals().get(k) for k in globals().keys()
                             if k.startswith("test_")])
    
        for test in self.options.test:
            if test > 0 and test <= len(test_suite):
                try:
                    test_suite[test-1]()
                    log.info("PASS")
                except TestError as error:
                    log.error("FAIL: {0}".format(error))
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
