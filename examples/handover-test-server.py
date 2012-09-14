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
import threading

import gobject
import dbus.mainloop.glib

bluetooth_oob_mime_type = "application/vnd.bluetooth.ep.oob"

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

    def set_oob_data(self, bt_record):
        self.remote_bdaddr = dbus.String(bt_record.device_address)
        sp_hash = dbus.Array(bt_record.simple_pairing_hash)
        sp_rand = dbus.Array(bt_record.simple_pairing_rand)
	self.oob_adapter.AddRemoteData(self.remote_bdaddr, sp_hash, sp_rand)
        
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
    
def process_handover_request(message):
    request = nfc.ndef.HandoverRequestMessage(message)
    log.info("received connection handover request message")
    for line in request.pretty(indent=2).split('\n'):
        log.info(line)
    if request.version.major != 1:
        log.warning("unsupported major version")
        return nfc.ndef.HandoverSelectMessage(version="1.2")
    if request.version.minor == 0 and options.quirks:
        log.warning("quirks: accept handover version 1.0 as 1.1")
    elif request.version.minor not in range(1,3):
        log.warning("unsupported minor version")
        return nfc.ndef.HandoverSelectMessage(version="1.2")
    for carrier in request.carriers:
        carrier_type = carrier.record.type
        if carrier_type == "urn:nfc:wkt:Hc":
            carrier_type = carrier.record.carrier_type
        if options.quirks:
            if carrier_type == "urn:nfc:wkt:application/vnd.bluetooth.ep.oob":
                carrier_type = "application/vnd.bluetooth.ep.oob"
                log.warning("quirks: correct Sony Xperia carrier type encoding")
            if carrier_type == "urn:nfc:wkt:application/vnd.wfa.wsc":
                carrier_type = "application/vnd.wfa.wsc"
                log.warning("quirks: correct Sony Xperia carrier type encoding")
        if carrier_type == "application/vnd.bluetooth.ep.oob":
            bluetooth_adapter = BluetoothAdapter()
            oob_record = bluetooth_adapter.make_oob_record()
            select = nfc.ndef.HandoverSelectMessage(version="1.2")
            select.add_carrier(oob_record, "active")
            #bluetooth_adapter.set_oob_data(carrier.record)
            log.debug("returning handover select record")
            for line in select.pretty(2).split('\n'):
                log.debug(line)
            return select
        
class HandoverServer(nfc.handover.HandoverServer):
    def __init__(self, select_carrier_func):
        super(HandoverServer, self).__init__()
        self.select_carrier = select_carrier_func

    def process_request__(self, request):
        if request.type == 'urn:nfc:wkt:Hr':
            hr = nfc.ndef.HandoverRequestMessage(request)
            return self.select_carrier(hr)
        else:
            log.error("unexpected message type {0!r}".format(request.type))
    
class DefaultSnepServer(nfc.snep.SnepServer):
    def __init__(self, select_carrier_func):
        super(DefaultSnepServer, self).__init__('urn:nfc:sn:snep')
        self.select_carrier = select_carrier_func

    def put(self, data):
        log.info("default snep server got PUT request")
        log.info("ndef data length is {0} octets".format(len(data)))
        file("snep-put.ndef", "w").write(data)
        ndef_message = nfc.ndef.Message(data)
        log.info("type is '{m.type}', id is '{m.name}'".format(m=ndef_message))
        return nfc.snep.Success
    
    def get(self, acceptable_length, data):
        log.info("default snep server got GET request")
        message = nfc.ndef.Message(data)
        if message.type == 'urn:nfc:wkt:Hr':
            try: hr = nfc.ndef.HandoverRequestMessage(message)
            except nfc.ndef.FormatError as e:
                log.error("error - {0}".format(e))
                log.warning("quirks: set handover request version to 1.1")
                message = nfc.ndef.Message(data[:5] + '\x11' + data[6:])
                hr = nfc.ndef.HandoverRequestMessage(message)
            hs = self.select_carrier(hr)
            return str(hs)
        return nfc.snep.NotFound

class HandoverTestServer(TestBase):
    def __init__(self):
        parser = argparse.ArgumentParser(
            usage='%(prog)s [OPTION]... [CARRIER]...',
            description="")
        parser.add_argument(
            "carriers", metavar="CARRIER", nargs="*",
            type=argparse.FileType('r'),
            help="supported carrier")
        
        super(HandoverTestServer, self).__init__(parser)

        if sum([1 for f in self.options.carriers if f.name == "<stdin>"]) > 1:
            log.error("only one carrier may be read from stdin")
            raise SystemExit(1)
        
        for index, carrier in enumerate(self.options.carriers):
            data = carrier.read()
            try: data = data.decode("hex")
            except TypeError: pass
            message = nfc.ndef.Message(data)
            self.options.carriers[index] = message

        if self.options.quirks:
            log.warning("quirks: will accept SNEP GET 'Hr' requests "
                        "as used by Android 4.1.0 devices")

        self.select_carrier_lock = threading.Lock()
        
    def register_llcp_services(self):
        #self.handover_service = HandoverService()
        if self.options.quirks:
            self.snep_service = DefaultSnepServer(self.select_carrier)
        
    def startup_llcp_services(self):
        #self.handover_service.start()
        if self.options.quirks:
            self.snep_service.start()
        
    def main(self):
        while nfc.llcp.connected():
            time.sleep(1)

    def select_carrier(self, handover_request):
        self.select_carrier_lock.acquire()
        log.info("<<< Handover Request\n" + handover_request.pretty(2))
        handover_select = nfc.ndef.HandoverSelectMessage(version="1.2")
        
        for carrier in handover_request.carriers:
            for my_carrier in self.options.carriers:
                if carrier.type == my_carrier.type:
                    log.info("matching {0!r}".format(my_carrier))
                    handover_select.add_carrier(my_carrier[0], "active")
                    break

        log.info(">>> Handover Select\n" + handover_select.pretty(2))
        self.select_carrier_lock.release()
        return handover_select

if __name__ == '__main__':
    HandoverTestServer().start()
