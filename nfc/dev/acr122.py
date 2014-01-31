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
        self.transport = transport
        
        # read ACR122U firmware version string
        reader_version = self.ccid_xfr_block(bytearray.fromhex("FF00480000"))
        if not reader_version.startswith("ACR122U"):
            log.error("failed to retrieve ACR122U version string")
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        
        if int(chr(reader_version[7])) < 2:
            log.error("{0} not supported, need 2.xx".format(frame[10:]))
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        log.debug("initialize " + str(reader_version))
        
        # set icc power on
        log.debug("CCID ICC-POWER-ON")
        frame = bytearray.fromhex("62000000000000000000")
        transport.write(frame); transport.read(100)
        
        # disable autodetection
        log.debug("Set PICC Operating Parameters")
        self.ccid_xfr_block(bytearray.fromhex("FF00517F00"))
        
        # switch red/green led off/on
        log.debug("Configure Buzzer and LED")
        self.ccid_xfr_block(bytearray.fromhex("FF00400E0400000000"))
        
        super(Chipset, self).__init__(transport)
        
    def close(self):
        self.ccid_xfr_block(bytearray.fromhex("FF00400C0400000000"))
        self.transport.close()
        self.transport = None

    def ccid_xfr_block(self, data, timeout=100):
        frame = struct.pack("<BI5B", 0x6F, len(data), 0, 0, 0, 0, 0) + data
        self.transport.write(bytearray(frame))
        frame = self.transport.read(timeout)
        if not frame or len(frame) < 10:
            log.error("insufficient data for decoding ccid response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if frame[0] != 0x80:
            log.error("expected a RDR_to_PC_DataBlock")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if len(frame) != 10 + struct.unpack("<I", buffer(frame, 1, 4))[0]:
            log.error("RDR_to_PC_DataBlock length mismatch")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        return frame[10:]
        
    def command(self, cmd_code, cmd_data=None, timeout=100):
        """Send a chip command and return the chip response."""
        cmd_name = "PN53x "+self.CMD.get(cmd_code, "0x{0:02X}".format(cmd_code))
        log.debug("{0} called with timeout {1} ms".format(cmd_name, timeout))
        
        if cmd_data is None: cmd_data = ""
        frame = bytearray([0xD4, cmd_code]) + bytearray(cmd_data)
        frame = bytearray([0xFF, 0x00, 0x00, 0x00, len(frame)]) + frame

        frame = self.ccid_xfr_block(frame, timeout)
        if not frame or len(frame) < 4:
            log.error("insufficient data for decoding chip response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if not (frame[0] == 0xD5 and frame[1] == cmd_code + 1):
            log.error("received invalid chip response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if not (frame[-2] == 0x90 and frame[-1] == 0x00):
            log.error("received pseudo apdu with error status")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        return frame[2:-2]
        
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
