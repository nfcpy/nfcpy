#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011 Alexander Knaub <sanyok.og@googlemail.com>
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
import string
import pickle
import gobject
import dbus.mainloop.glib

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc.ndef
from nfc.ndef.SmartPoster import SmartPosterRecord
from nfc.ndef.ConnectionHandover import HandoverSelectMessage
from nfc.ndef.WiFiSimpleConfig import WiFiConfigData, WiFiPasswordData
from nfc.ndef.BluetoothEasyPairing import BluetoothConfigData

BUS_NAME = "org.nfcpy.TagReader"

def make_printable(data):
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += make_printable(data[i:i+16])
    return '\n'.join(s)

def print_smartposter(message):
    print "Smart Poster"
    sp = SmartPosterRecord(message[0])
    for lang in sorted(sp.title):
        print "  title[%s] = %s" % (lang, sp.title[lang])
    print "  resource  = %s" % sp.uri
    print "  action    = %s" % sp.action
    if len(message) > 1:
        print "Further Records"
        for index, record in enumerate(message):
            if index == 0: continue
            record.data = make_printable(record.data)
            print "  [%d] type = %s" %(index, record.type)
            print "  [%d] name = %s" %(index, record.name)
            print "  [%d] data = %s" %(index, record.data)

def print_handover_select(message):
    print "Connection Handover Select Message"
    number_suffix = ('st', 'nd', 'rd', 'th')
    message = HandoverSelectMessage(message)
    for i, carrier in enumerate(message.carriers):
        carrier_type = carrier['carrier-type']
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
        elif carrier_type == "application/vnd.bluetooth.ep.oob":
            cfg = BluetoothConfigData.fromstring(config_data)
            print "    bdaddr   = %s" % cfg.device_address
            print "    class    = %s" % cfg.class_of_device.encode("hex")
            print "    sp hash  = %s" % cfg.simple_pairing_hash
            print "    sp rand  = %s" % cfg.simple_pairing_randomizer
            print "    longname = %s" % cfg.long_name
            print "    partname = %s" % cfg.short_name
        else:
            print carrier

def print_wifi_token(message):
    try:
        data = WiFiPasswordData.fromstring(message[0].data)
        print "  Wi-Fi Password Token"
        print "    version  = %d.%d" % data.version
        print "    PK Hash  = %s" % data.public_key_hash.encode("hex")
        print "    DevPwdID = %s" % data.device_password_id
        print "    Password = %s" % data.device_password.encode("hex")
        for key, val in data.other_attributes:
            print "    0x%04x   = %s" % (key, val.encode("hex"))
        return
    except ValueError:
        pass
    try:
        data = WiFiConfigData.fromstring(message[0].data)
        print "  Wi-Fi Configuration Token"
        print "    version  = %d.%d" % data.version
        print "    network  = %s" % data.ssid
        print "    password = %s" % data.network_key
        print "    macaddr  = %s" % data.mac_address
        print "    security = %s / %s" % \
            (data.authentication, data.encryption)
        return
    except ValueError:
        pass
    
class ReaderClient:
    def __init__(self, mainloop, reader):
        self._loop = mainloop
        self._message = None
        self._reader = reader
        
    def save_ndef(self, ndef_msg_string):
        print "Received %d Bytes: %s" % (len(ndef_msg_string), ndef_msg_string)
        if len(ndef_msg_string):
            self._message = nfc.ndef.Message(str(ndef_msg_string))
        else:
            print "Empty message received!"
    
    def show_ndef(self): 
        if self._message.type == "urn:nfc:wkt:Sp":
            print_smartposter(self._message)

        elif self._message.type == "urn:nfc:wkt:Hs":
            print_handover_select(self._message)

        elif self._message.type == "application/vnd.wfa.wsc":
            print_wifi_token(self._message)

        else:
            print "Unknown Message"
            for index, record in enumerate(self._message):
                record.data = make_printable(record.data)
                print "  [%d] record type = %s" %(index, record.type)
                print "  [%d] record name = %s" %(index, record.name)
                print "  [%d] record data = %s" %(index, record.data)
    
    def show_tag(self, tag_str):
        self._tag_info = pickle.loads(tag_str)
        print "NDEF container present"
        print "  version   = %s" % self._tag_info['version']
        print "  writeable = %s" % ("no", "yes")[self._tag_info['writeable']]
        print "  capacity  = %d byte" % self._tag_info['capacity']
        print "  data size = %d byte" % self._tag_info['size']
        if self._message:
            self.show_ndef()
        else:
            print "No message",
            time.sleep(0.5)
            if self._message:
                print "received yet. Waiting..."
                self.show_ndef()
            else:
                print "available."
        self._loop.quit()

def main():
    
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    object = bus.get_object(BUS_NAME, "/nfcpy/tagreader")
    loop = gobject.MainLoop()
    client = ReaderClient(mainloop=loop, reader=object)
    object.connect_to_signal(signal_name="NDEFMessage", 
                            handler_function=client.save_ndef, 
                            dbus_interface='org.nfcpy.TagReader',
                            byte_arrays=True)
    object.connect_to_signal(signal_name="TagInfo", 
                            handler_function=client.show_tag, 
                            dbus_interface='org.nfcpy.TagReader',
                            byte_arrays=True)
    try:
        loop.run()
    except KeyboardInterrupt:
        print "Exiting..."
        loop.quit()

if __name__ == '__main__':
    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-q", default=True,
                      action="store_false", dest="verbose",
                      help="be quiet, only print errors")
    parser.add_option("-d", default=False,
                      action="store_true", dest="debug",
                      help="print debug messages")
    parser.add_option("-f", type="string",
                      action="store", dest="logfile",
                      help="write log messages to LOGFILE")

    global options
    options, args = parser.parse_args()

    verbosity = logging.INFO if options.verbose else logging.ERROR
    verbosity = logging.DEBUG if options.debug else verbosity
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    try:
        main()
    except KeyboardInterrupt:
        pass

