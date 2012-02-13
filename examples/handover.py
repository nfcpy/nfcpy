#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
logging.basicConfig(level=logging.ERROR)

import os
import sys
import time
import string

sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc
import nfc.ndef
from nfc.ndef.WiFiSimpleConfig import WiFiConfigData
from nfc.ndef.BluetoothEasyPairing import BluetoothConfigData
from nfc.ndef.ConnectionHandover import HandoverSelectMessage

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

def write_configuration(tag):
    print
    print "Writing Wi-Fi Configuration"

    wifi_cfg = WiFiConfigData()
    wifi_cfg.ssid           = "HomeNetwork"
    wifi_cfg.network_key    = "secret"
    wifi_cfg.mac_address    = "00:07:E9:4C:A8:1C"
    wifi_cfg.authentication = "WPA-Personal"
    wifi_cfg.encryption     = "AES"

    bt21_cfg = BluetoothConfigData()
    bt21_cfg.device_address = "01:02:03:04:05:06"
    bt21_cfg.class_of_device = "\x00\x00\x00"
    bt21_cfg.simple_pairing_hash = range(16)
    bt21_cfg.simple_pairing_randomizer = [ord(x) for x in os.urandom(16)]
    bt21_cfg.short_name = "My Device"
    bt21_cfg.long_name = "My Most Expensive Device"

    message = HandoverSelectMessage()

    wifi_carrier = dict()
    wifi_carrier['carrier-type'] = 'application/vnd.wfa.wsc'
    wifi_carrier['config-data'] = wifi_cfg.tostring()
    wifi_carrier['power-state'] = "active"
    message.carriers.append(wifi_carrier)

    bt21_carrier = dict()
    bt21_carrier['carrier-type'] = 'application/vnd.bluetooth.ep.oob'
    bt21_carrier['config-data'] = bt21_cfg.tostring()
    bt21_carrier['power-state'] = "active"
    message.carriers.append(bt21_carrier)

    print format_data(message.tostring())
    if tag: tag.ndef.message = message.tostring()
    return

def main():
    # initialize the NFC reader, if installed
    clf = nfc.ContactlessFrontend()

    while True:
        # poll for a tag
        tag = clf.poll()

        if tag is None:
            time.sleep(0.5)
            continue

        print "found", str(tag)

        if isinstance(tag, nfc.Type3Tag):
            if tag.ndef is None:
                print "This tag is not NDEF compatible - try another one"
                continue

            print "NDEF container present"
            print "  version   = %s" % tag.ndef.version
            print "  writeable = %s" % ("no", "yes")[tag.ndef.writeable]
            print "  capacity  = %d byte" % tag.ndef.capacity
            print "  data size = %d byte" % len(tag.ndef.message)
            print format_data(tag.ndef.message)

            if not tag.ndef.writeable:
                print "This tag is not writable - try another one"
                continue

            write_configuration(tag)
            return

        time.sleep(0.5)

try:
    main()
except KeyboardInterrupt:
    pass

