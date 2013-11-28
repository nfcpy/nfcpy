#!/usr/bin/env python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

sys.path.insert(1, os.path.split(sys.path[0])[0])
from cli import CommandLineInterface

import nfc
import nfc.llcp
import nfc.ndef
import nfc.snep
import nfc.handover
import threading
from copy import deepcopy

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
        self.remote_bdaddr = dbus.String(bdaddr)
        ssp_hash = dbus.Array(ssp_hash)
        ssp_rand = dbus.Array(ssp_rand)
	self.oob_adapter.AddRemoteData(self.remote_bdaddr, ssp_hash, ssp_rand)
            
class HandoverServer(nfc.handover.HandoverServer):
    def __init__(self, llc, select_carrier_func, options):
        super(HandoverServer, self).__init__(
            llc, recv_miu=options.recv_miu, recv_buf=options.recv_buf)
        self.select_carrier = select_carrier_func

    def process_request(self, request):
        return self.select_carrier(request)
    
class DefaultSnepServer(nfc.snep.SnepServer):
    def __init__(self, llc, select_carrier_func):
        super(DefaultSnepServer, self).__init__(llc, 'urn:nfc:sn:snep')
        self.select_carrier = select_carrier_func

    def put(self, ndef_message):
        log.info("default snep server got put request")
        log.info(ndef_message.pretty())
        return nfc.snep.Success

    def get(self, acceptable_length, message):
        log.info("default snep server got GET request")
        if message.type == 'urn:nfc:wkt:Hr':
            try: hr = nfc.ndef.HandoverRequestMessage(message)
            except nfc.ndef.FormatError as e:
                log.error("error - {0}".format(e))
                log.warning("quirks: set handover request version to 1.1")
                message = nfc.ndef.Message(data[:5] + '\x11' + data[6:])
                hr = nfc.ndef.HandoverRequestMessage(message)
            return self.select_carrier(hr)
        return nfc.snep.NotFound

description = """
Run a connection handover server component with various test options.
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
            "--skip-local", action="store_true",
            help="skip local carrier detection")
        parser.add_argument(
            "--select", metavar="NUM", type=int, default=1,
            help="select up to NUM carriers (default: %(default)s))")
        parser.add_argument(
            "--delay", type=int, metavar="INT",
            help="delay the response for INT milliseconds")
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
            parser, groups="llcp dbg clf iop")

        if sum([1 for f in self.options.carriers if f.name == "<stdin>"]) > 1:
            log.error("only one carrier file may be read from stdin")
            raise SystemExit(1)

        selectable = nfc.ndef.HandoverSelectMessage(version="1.2")
        
        for index, carrier in enumerate(self.options.carriers):
            data = carrier.read()
            try: data = data.decode("hex")
            except TypeError: pass
            message = nfc.ndef.Message(data)
            if message.type == "urn:nfc:wkt:Hs":
                message = nfc.ndef.HandoverSelectMessage(message)
                for carrier in message.carriers:
                    selectable.add_carrier(carrier.record, carrier.power_state,
                                           carrier.auxiliary_data_records)
                    log.info("add specified carrier: {0}".format(carrier.type))
            else:
                selectable.add_carrier(message[0], "active", message[1:])
                log.info("add specified carrier: {0}".format(message.type))
            
        if not self.options.skip_local:
            if sys.platform == "linux2":
                self.hci0 = BluetoothAdapter()
                record = nfc.ndef.BluetoothConfigRecord()
                record.device_address = self.hci0.device_address
                record.class_of_device = self.hci0.device_class
                record.local_device_name = self.hci0.device_name
                record.service_class_uuid_list = self.hci0.service_uuids
                selectable.add_carrier(record, "active")
                log.info("add discovered carrier: {0}".format(record.type))

        self.options.selectable = selectable
        
        if self.options.quirks:
            log.warning("quirks: will accept SNEP GET 'Hr' requests "
                        "used by Android 4.1.0 devices")

        self.select_carrier_lock = threading.Lock()
        
    def on_llcp_startup(self, clf, llc):
        self.handover_service = HandoverServer(
            llc, self.select_carrier, self.options)
        if self.options.quirks:
            self.snep_service = DefaultSnepServer(
                llc, self.select_carrier)
        return llc
        
    def on_llcp_connect(self, llc):
        self.handover_service.start()
        if self.options.quirks:
            self.snep_service.start()
        return True
        
    def select_carrier(self, handover_request):
        self.select_carrier_lock.acquire()
        log.info("<<< Handover Request\n" + handover_request.pretty(2))
        handover_select = nfc.ndef.HandoverSelectMessage(version="1.2")
        
        if handover_request.version.minor == 0 and self.options.quirks:
            log.warning("quirks: accept handover version 1.0 as 1.1")
        elif handover_request.version.minor not in range(1,3):
            log.warning("unsupported minor version")
            self.select_carrier_lock.release()
            return handover_select
        
        for remote_carrier in handover_request.carriers:
            remote_carrier_type = remote_carrier.type
            
            if self.options.quirks:
                if remote_carrier.type in ("urn:nfc:wkt:" + mime_btoob,
                                           "urn:nfc:wkt:" + mime_wfasc):
                    log.warning("quirks: correct xperia carrier request {0}"
                                .format(remote_carrier.type))
                    remote_carrier_type = remote_carrier.type[12:]
                    
                    
            for local_carrier in deepcopy(self.options.selectable.carriers):
                if remote_carrier_type == local_carrier.type:
                    if len(handover_select.carriers) < self.options.select:
                        log.info("match for {0}".format(local_carrier.type))
                        if (local_carrier.type == mime_btoob
                            and hasattr(self, 'hci0')
                            and remote_carrier.record.simple_pairing_hash
                            and remote_carrier.record.simple_pairing_rand):
                            record = local_carrier.record
                            bdaddr = self.hci0.device_address
                            if bdaddr == record.device_address:
                                ssp_hash, ssp_rand = self.hci0.get_ssp_data()
                                record.simple_pairing_hash = ssp_hash
                                record.simple_pairing_rand = ssp_rand
                                self.hci0.set_ssp_data(
                                    remote_carrier.record.device_address,
                                    remote_carrier.record.simple_pairing_hash,
                                    remote_carrier.record.simple_pairing_hash)
                        handover_select.add_carrier(
                            local_carrier.record, local_carrier.power_state,
                            local_carrier.auxiliary_data_records)
                    else: break

        log.info(">>> Handover Select\n" + handover_select.pretty(2))
        self.select_carrier_lock.release()
        
        if self.options.delay:
            log.info("delay response for {0} ms".format(self.options.delay))
            time.sleep(self.options.delay/1000.0)
        
        return handover_select

if __name__ == '__main__':
    TestProgram().run()
