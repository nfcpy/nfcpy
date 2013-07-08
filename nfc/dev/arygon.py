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
        for speed in (9600, 19200, 38400, 57600, 115200, 230400):
            self.transport.tty = self.transport.serial.Serial(
                self.transport.tty.port, baudrate=speed, timeout=0.05)
            self.transport.tty.write("0ar")
            if self.transport.tty.readline() == "FF000000\r\n":
                self.transport.tty.timeout = 1.0
                self.transport.tty.write("0av")
                version = self.transport.tty.readline().rstrip("\r\n")[-4:]
                log.debug("Arygon Reader {0}".format(version))
                if self.transport.tty.baudrate != 230400:
                    # set 230.4 kbps between MCU and TAMA
                    self.transport.tty.write("0at05")
                    self.transport.tty.readline()
                    # set 230.4 kbps between MCU and HOST
                    self.transport.tty.write("0ah05")
                    self.transport.tty.readline()
                    time.sleep(0.1)
                self.transport.tty.close()
                self.transport.tty = self.transport.serial.Serial(
                    self.transport.tty.port, baudrate=230400,
                    timeout=1.0, writeTimeout=1.0)
                self.transport.tty.write("0of00")
                self.transport.tty.readline()
                break
        else: raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        super(Chipset, self).__init__(transport)
        
    def close(self):
        self.transport.tty.write("0of00")
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
