# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
# Driver for the Arygon contactless reader with USB serial interface
#
import logging
log = logging.getLogger(__name__)

import os
import sys
import time
import errno

import pn531
from pn531 import ChipsetError

class Chipset(pn531.Chipset):
    def __init__(self, transport):
        self.transport = transport
        for speed in (230400, 9600, 19200, 38400, 57600, 115200):
            log.debug("try serial baud rate {0} kbps".format(speed))
            self.transport.tty = self.transport.serial.Serial(
                self.transport.tty.port, baudrate=speed, timeout=0.1)
            log.debug("read arygon firmware version")
            self.transport.tty.write("0av")
            version = self.transport.tty.readline()
            if version.startswith("FF0000"):
                log.debug("Arygon Reader {0}".format(version.strip()[-4:]))                
                self.transport.tty.timeout = 1.0
                self.transport.tty.writeTimeout = 1.0
                log.debug("set mcu-tama speed to 230.4 kbps")
                self.transport.tty.write("0at05")
                if self.transport.tty.readline().strip() != "FF000000":
                    log.debug("failed to set mcu-tama speed")
                    break
                if self.transport.tty.baudrate != 230400:
                    log.debug("set mcu-host speed to 230.4 kbps")
                    self.transport.tty.write("0ah05")
                    if self.transport.tty.readline().strip() != "FF000000":
                        log.debug("failed to set mcu-host speed")
                        break
                    time.sleep(0.5)
                    self.transport.tty.close()
                    self.transport.tty = self.transport.serial.Serial(
                        self.transport.tty.port, baudrate=230400,
                        timeout=1.0, writeTimeout=1.0)
                return super(Chipset, self).__init__(transport)
        raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        
    def close(self):
        self.transport.tty.write("0ar")
        self.transport.tty.readline()
        self.transport.close()
        self.transport = None

    def write_frame(self, frame):
        self.transport.write("2" + frame)

    def read_frame(self, timeout):
        return self.transport.read(timeout)

class Device(pn531.Device):
    pass
            
def init(transport):
    chipset = Chipset(transport)
    device = Device(chipset)
    
    device._vendor_name = "Arygon"
    device._device_name = "APPx-ADRx"
    
    return device
