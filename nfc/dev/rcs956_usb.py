# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
#
# rcs956_usb.py - support for Sony RC-S330/360/370 NFC readers
#

import logging
log = logging.getLogger(__name__)

import pn53x_usb
import rcs956

class rcs956_usb(pn53x_usb.pn53x_usb):
    pass

class Device(rcs956.Device):
    pass

def init(usb_dev):
    bus = rcs956_usb(usb_dev)
    dev = rcs956.rcs956(bus)
    device = Device(dev)
    device._vendor = "Sony"
    device._product = "RC-S330" if usb_dev.iProduct == 0 else \
        bus.dh.getString(usb_dev.iProduct, 100)
    return device
