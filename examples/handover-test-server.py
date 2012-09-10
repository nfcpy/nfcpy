#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.llcp
import nfc.ndef
from threading import Thread
import gobject
import dbus.mainloop.glib

bluetooth_oob_mime_type = "application/vnd.bluetooth.ep.oob"

def print_handover_message(message):
    number_suffix = ('st', 'nd', 'rd', 'th')
    if message.type == "urn:nfc:wkt:Hr":
        print "Connection Handover Request Message",
        message = nfc.ndef.HandoverRequestMessage(message)
    elif message.type == "urn:nfc:wkt:Hs":
        print "Connection Handover Select Message",
        message = nfc.ndef.HandoverSelectMessage(message)
    else:
        log.error("This is not a Connection Handover Message")
        return

    print("Version {version.major}.{version.minor}"
          .format(version=message.version))
    for i, carrier in enumerate(message.carriers):
        print carrier
        carrier_type = carrier.record.type
        if carrier_type == "application/vnd.wfa.wsc":
            carrier_name = "Wi-Fi (Simple Config)"
        elif carrier_type == "application/vnd.bluetooth.ep.oob":
            carrier_name = "Bluetooth (Easy Pairing)"
        else:
            carrier_name = carrier_type
        print "  %d%s carrier" % (i+1, number_suffix[min(i,3)]),
        print "is %s" % carrier_name
        print "    power    = %s" % carrier['power-state']
        config_data  = carrier['config-data']
        if carrier_type == "application/vnd.wfa.wsc":
            cfg = WiFiConfigData.fromstring(config_data)
            print "    version  = %d.%d" % cfg.version
            print "    network  = %s" % cfg.ssid
            print "    password = %s" % cfg.network_key
            print "    macaddr  = %s" % cfg.mac_address
            print "    security = %s / %s" % \
                (cfg.authentication, cfg.encryption)
        elif carrier_type == bluetooth_oob_mime_type:
            cfg = BluetoothConfigData.fromstring(config_data)
            sp_hash = ''.join(["%02x"%x for x in cfg.simple_pairing_hash])
            sp_rand = ''.join(["%02x"%x for x in cfg.simple_pairing_randomizer])
            print "    bdaddr   = %s" % cfg.device_address
            print "    class    = 0x%s" % cfg.class_of_device.encode("hex")
            print "    sp hash  = 0x%s" % sp_hash
            print "    sp rand  = 0x%s" % sp_rand
            print "    longname = %s" % cfg.long_name
            print "    partname = %s" % cfg.short_name
        else:
            print carrier

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

    def make_oob_record(self):
        bt_record = nfc.ndef.BluetoothConfigRecord()
        bt_record.device_address = str(self.adapter.GetProperties()["Address"])
        bt_record.class_of_device = int(self.adapter.GetProperties()["Class"])
        bt_record.local_device_name = str(self.adapter.GetProperties()["Name"])
        sp_hash, sp_rand = self.oob_adapter.ReadLocalData()
        bt_record.simple_pairing_hash = bytearray(sp_hash)
        bt_record.simple_pairing_rand = bytearray(sp_rand)
        return bt_record

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
      
	self.adapter.CreatePairedDevice(\
            self.remote_bdaddr, "/test/agent_oob", "DisplayYesNo",
            reply_handler=create_device_reply,
            error_handler=create_device_error)

        self.mainloop.run()
    
class HandoverServer(Thread):
    def __init__(self):
        super(HandoverServer, self).__init__()
        self.name = "HandoverServerThread"
        self.daemon = True

    def serve(self, socket):
        peer = nfc.llcp.getpeername(socket)
        log.info("serving handover client on remote addr {0}".format(peer))
        send_miu = nfc.llcp.getsockopt(socket, nfc.llcp.SO_SNDMIU)
        data = ""
        while nfc.llcp.poll(socket, "recv"):
            try:
                data += nfc.llcp.recv(socket)
                message = nfc.ndef.Message(data)
            except nfc.ndef.LengthError: continue # incomplete message
            except TypeError: break # recv() returned None
            print_handover_message(message)
            if message.type == "urn:nfc:wkt:Hr":
                handover_req = nfc.ndef.HandoverRequestMessage(message)
                for carrier in handover_req.carriers:
                    if carrier.record.type == bluetooth_oob_mime_type:
                        bluetooth_adapter = BluetoothAdapter()
                        oob_record = bluetooth_adapter.make_oob_record()
                        handover_select = HandoverSelectMessage()
                        handover_select.add_carrier(oob_record, "active")
                        bluetooth_adapter.set_oob_data(carrier.record)
                        data = str(handover_select)
                        print_handover_message(nfc.ndef.Message(data))
                        print "data = ", repr(data)
                        while len(data) > 0:
                            if nfc.llcp.send(socket, data[0:send_miu]):
                                data = data[send_miu:]
                            else: break
#                        else:
#                            bluetooth_adapter.create_pairing()
                        break
                        
        nfc.llcp.close(socket)
        log.info("server thread terminated")

    def run(self):
        socket = nfc.llcp.socket(nfc.llcp.DATA_LINK_CONNECTION)
        try:
            nfc.llcp.bind(socket, 'urn:nfc:sn:handover')
            addr = nfc.llcp.getsockname(socket)
            log.info("handover server bound to port {0}".format(addr))
            nfc.llcp.setsockopt(socket, nfc.llcp.SO_RCVBUF, 2)
            nfc.llcp.listen(socket, backlog=4)
            while True:
                client = nfc.llcp.accept(socket)
                peer = nfc.llcp.getpeername(client)
                log.info("client sap {0} connected".format(peer))
                Thread(target=self.serve, args=[client]).start()
        except nfc.llcp.Error as e:
            log.error(str(e))
        finally:
            nfc.llcp.close(socket)

def llcp_connect(clf, general_bytes, options):
    try:
        while True:
            if options.mode == "t" or options.mode is None:
                listen_time = 250 + ord(os.urandom(1))
                peer = clf.listen(listen_time, general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        return peer
            if options.mode == "i" or options.mode is None:
                peer = clf.poll(general_bytes)
                if isinstance(peer, nfc.DEP):
                    if peer.general_bytes.startswith("Ffm"):
                        return peer
    except KeyboardInterrupt:
        log.info("aborted by user")

def main(options):
    llcp_pax = nfc.llcp.startup({
        'recv-miu': options.miu,
        'send-lto': options.lto,
        'send-agf': not options.no_agf,
        })
    
    for device in options.device:
        try: clf = nfc.ContactlessFrontend(device); break
        except LookupError: pass
    else: return

    peer = llcp_connect(clf, llcp_pax, options)
    
    if peer is not None:
        nfc.llcp.activate(peer)
        try:
            handover_server = HandoverServer()
            handover_server.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("aborted by user")
        finally:
            nfc.llcp.shutdown()
            log.info("I was the " + peer.role)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(usage='%(prog)s [options]')

    parser.add_argument(
        "-q", "--quiet", dest="quiet", action="store_true",
        help="do not print any log messages except errors")
    parser.add_argument(
        "--debug-all", dest="debug_all", action="store_true",
        help="print all debug messages")
    parser.add_argument(
        "-d", metavar="MODULE", dest="debug", action="append",
        help="print debug messages for MODULE")
    parser.add_argument(
        "-f", dest="logfile", metavar="FILE",
        help="write log messages to file")
    parser.add_argument(
        "--mode", choices=["t", "i"],
        help="restrict DEP mode to Target 't' or Initiator 'i'")
    parser.add_argument(
        "--miu", dest="miu", metavar="INT", type=int, default=1024,
        help="set link maximum information unit size (default: %(default)s)")
    parser.add_argument(
        "--lto", metavar="INT", type=int, default=500,
        help="set link timeout in milliseconds (default: %(default)s)")
    parser.add_argument(
        "--no-agf", action="store_true",
        help="do not aggregate outbound packets")
    parser.add_argument(
        "--device", metavar="NAME", action="append",
        help="use specified contactless reader(s): "\
            "usb[:vendor[:product]] (vendor and product in hex), "\
            "usb[:bus[:dev]] (bus and device number in decimal), "\
            "tty[:(usb|com)[:port]] (usb virtual or com port)")

    args = parser.parse_args()

    verbosity = logging.INFO if not args.quiet else logging.ERROR
    logging.basicConfig(level=verbosity, format='%(message)s')

    if args.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(args.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    import inspect, os, os.path
    nfcpy_path = os.path.dirname(inspect.getfile(nfc))
    for name in os.listdir(nfcpy_path):
        if os.path.isdir(os.path.join(nfcpy_path, name)):
            logging.getLogger("nfc."+name).setLevel(verbosity)
        elif name.endswith(".py") and name != "__init__.py":
            logging.getLogger("nfc."+name[:-3]).setLevel(verbosity)
            
    if args.debug:
        logging.getLogger('').setLevel(logging.DEBUG)
        logging.getLogger('nfc').setLevel(logging.DEBUG)
        for module in args.debug:
            log.info("enable debug output for module '{0}'".format(module))
            logging.getLogger(module).setLevel(logging.DEBUG)

    log.debug("arguments {0}".format(vars(args)))
    
    if args.device is None:
        args.device = ['']

    ndef = file("xperia-p.hr-message.ndef").read()
    print_handover_message(nfc.ndef.Message(ndef))
    #main(args)
