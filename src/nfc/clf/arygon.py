# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
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
from . import pn531
from . import pn532

import os
import time
import errno

import logging
log = logging.getLogger(__name__)


class ChipsetA(pn531.Chipset):
    def write_frame(self, frame):
        self.transport.write(b"2" + frame)


class DeviceA(pn531.Device):
    def close(self):
        self.chipset.transport.tty.write(b"0au")  # device reset
        self.chipset.close()
        self.chipset = None


class ChipsetB(pn532.Chipset):
    def write_frame(self, frame):
        self.transport.write(b"2" + frame)


class DeviceB(pn532.Device):
    def close(self):
        self.chipset.transport.tty.write(b"0au")  # device reset
        self.chipset.close()
        self.chipset = None


def init(transport):
    transport.open(transport.port, 115200)
    transport.tty.write(b"0av")  # read version
    response = transport.tty.readline()
    if response.startswith(b"FF00000600V"):
        log.debug("Arygon Reader AxxB Version %s",
                  response[11:].strip().decode())
        transport.tty.timeout = 0.5
        transport.tty.write(b"0at05")
        if transport.tty.readline().startswith(b"FF0000"):
            log.debug("MCU/TAMA communication set to 230400 bps")
            transport.tty.write(b"0ah05")
            if transport.tty.readline().startswith(b"FF0000"):
                log.debug("MCU/HOST communication set to 230400 bps")
                transport.tty.baudrate = 230400
                transport.tty.timeout = 0.1
                time.sleep(0.1)
                chipset = ChipsetB(transport, logger=log)
                device = DeviceB(chipset, logger=log)
                device._vendor_name = "Arygon"
                device._device_name = "ADRB"
                return device

    transport.open(transport.port, 9600)
    transport.tty.write(b"0av")  # read version
    response = transport.tty.readline()
    if response.startswith(b"FF00000600V"):
        log.debug("Arygon Reader AxxA Version %s",
                  response[11:].strip().decode())
        transport.tty.timeout = 0.5
        transport.tty.write(b"0at05")
        if transport.tty.readline().startswith(b"FF0000"):
            log.debug("MCU/TAMA communication set to 230400 bps")
            transport.tty.write(b"0ah05")
            if transport.tty.readline().startswith(b"FF0000"):
                log.debug("MCU/HOST communication set to 230400 bps")
                transport.tty.baudrate = 230400
                transport.tty.timeout = 0.1
                time.sleep(0.1)
                chipset = ChipsetA(transport, logger=log)
                device = DeviceA(chipset, logger=log)
                device._vendor_name = "Arygon"
                device._device_name = "ADRA"
                return device

    raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
