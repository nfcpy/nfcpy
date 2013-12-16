# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
# Driver for the Arygon ACR122U contactless reader
#
import logging
log = logging.getLogger(__name__)

import os
import time
import errno
import struct

import pn53x

class Chipset(pn53x.Chipset):
    def __init__(self, transport):
        frame = bytearray([0xFF, 0x00, 0x48, 0x00, 0x00])
        frame = bytearray([0x6B, len(frame)] + 8 * [0x00]) + frame
        transport.write(frame)
        frame = transport.read(1000)
        if not (frame[0] == 0x83 and frame[1] == len(frame) - 10 and
                frame[5:7] == "\x00\x00" and frame[8] == 0x81 and
                frame[10:17] == "ACR122U"):
            log.error("failed to retrieve ACR122U version string")
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        if int(chr(frame[17])) < 2:
            log.error("{0} is not supported, need version 2.xx"
                      .format(frame[10:]))
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        super(Chipset, self).__init__(transport)
            
    def close(self):
        self.transport.close()
        self.transport = None
        
    def command(self, cmd_code, cmd_data=None, timeout=100):
        """Send a chip command and return the chip response."""
        cmd_name = self.CMD.get(cmd_code, "PN53x 0x{0:02X}".format(cmd_code))
        log.debug("{0} called with timeout {1} ms".format(cmd_name, timeout))
        
        if cmd_data is None: cmd_data = ""
        frame = bytearray([0xD4, cmd_code]) + bytearray(cmd_data)
        frame = bytearray([0xFF, 0x00, 0x00, 0x00, len(frame)]) + frame
        frame = bytearray([0x6B, len(frame)] + 8 * [0x00]) + frame

        self.transport.write(frame)
        frame = self.transport.read(timeout)
        
        if len(frame) < 14:
            strerror = os.strerror(errno.EIO) + " - Received frame too short"
            raise IOError(errno.EIO, strerror)
        if frame[0] != 0x83:
            strerror = os.strerror(errno.EIO) + " - Unexpected start of frame"
            raise IOError(errno.EIO, strerror)
        if frame[-2] == 0x63:
            strerror = os.strerror(errno.EIO) + " - No response from PN53X"
            raise IOError(errno.EIO, strerror)

        return frame[12:-2]

class Device(pn53x.Device):
    def __init__(self, bus):
        super(Device, self).__init__(bus)

    def close(self):
        self.chipset.close()

    def listen_dep(self, target, timeout):
        # ACR122 would listen for about 5 seconds -> unusable
        log.warning("listen mode is disabled for this device")
        time.sleep(timeout)
        return None

def init(transport):
    chipset = Chipset(transport)
    device = Device(chipset)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device
