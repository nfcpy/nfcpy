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

from struct import pack, unpack
import usb
import pn53x
import pn53x_usb
from pn53x import pn53x_cmd

class acr122(pn53x.pn53x):
    def command(self, cmd_code, cmd_data=None, timeout=100):
        """send chip command and return chip response as a bytearray"""
        log.debug(pn53x_cmd.get(cmd_code, "PN53x 0x{0:02X}".format(cmd_code)))

        if cmd_data is None: cmd_data = ""
        frame = bytearray([0xD4, cmd_code]) + bytearray(cmd_data)
        frame = bytearray([0xFF, 0x00, 0x00, 0x00, len(frame)]) + frame
        frame = bytearray([0x6B, len(frame)] + 8 * [0x00]) + frame

        self.bus.write(frame)
        frame = self.bus.read(timeout)
        
        if frame is None:
            raise pn53x.NoResponse("no response from pn53x")
        if frame[0] != 0x83:
            raise pn53x.FrameError("unexpected start of frame")
        if frame[-2] == 0x63:
            raise pn53x.NoResponse("no response from pn53x")

        return frame[12:-2]

class acr122_usb(pn53x_usb.pn53x_usb):
    def __init__(self, dev):
        configuration = dev.configurations[0]
        interface = configuration.interfaces[0]
        for ep in interface[0].endpoints:
            if ep.type == usb.ENDPOINT_TYPE_BULK:
                if ep.address & usb.ENDPOINT_DIR_MASK == usb.ENDPOINT_IN:
                    self.usb_inp = ep.address
                else:
                    self.usb_out = ep.address

        self.dh = dev.open()
        self.dh.reset()
        #dh.setConfiguration(configuration)
        self.dh.claimInterface(interface[0])
        self.dh.setAltInterface(interface[0])

    def close(self):
        self.dh.releaseInterface()
        self.dh = None
        
class Device(pn53x.Device):
    def __init__(self, bus):
        super(Device, self).__init__(bus)
        # ACR122 Firmware Version
        frame = bytearray([0xFF, 0x00, 0x48, 0x00, 0x00])
        frame = bytearray([0x6B, len(frame)] + 8 * [0x00]) + frame
        self.dev.bus.write(frame)
        frame = self.dev.bus.read(timeout=100)
        log.info("reader firmware {0}".format(frame[10:]))

    def close(self):
        self.dev.close()

    def listen(self, general_bytes, timeout):
        log.warning("ACR122U does not support the timeout for listen " +
                    "(will be ~5 sec for this device)")
        try:
            data = super(Device, self).listen(general_bytes, timeout=0)
        except pn53x.NoResponse:
            pass
        else:
            speed = ("106", "212", "424")[(data[0]>>4) & 0x07]
            cmode = ("passive", "active", "passive")[data[0] & 0x03]
            ttype = ("card", "p2p")[bool(data[0] & 0x04)]
            info = "activated as {0} target in {1} kbps {2} mode"
            log.info(info.format(ttype, speed, cmode))
            return str(data[18:])

def init(usb_dev):
    bus = acr122_usb(usb_dev)
    dev = acr122(bus)
    device = Device(dev)
    device._vendor = bus.dh.getString(usb_dev.iManufacturer, 100)
    device._product = bus.dh.getString(usb_dev.iProduct, 100)
    return device
