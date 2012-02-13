# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# arygon_tty.py - driver module for serial Arygon reader
#

import logging
log = logging.getLogger(__name__)

import sys
import time
import serial
import fcntl
import pn53x

class arygon_tty(pn53x.pn53x):
    def __init__(self, portstr):
        self.tty = None
        for speed in (9600, 19200, 38400, 57600, 115200, 230400):
            tty = serial.Serial(portstr, baudrate=speed, timeout=0.05)
            tty.write("0ar")
            if tty.readline() == "FF000000\r\n":
                tty.timeout = 1
                tty.write("0av")
                version = tty.readline().rstrip("\r\n")[-4:]
                log.debug("Arygon Reader {0} at {1}".format(version, tty.port))
                if tty.baudrate != 230400:
                    tty.write("0at05") # set 230.4 kbps between MCU and TAMA
                    tty.readline().rstrip("\r\n")
                    tty.write("0ah05") # set 230.4 kbps between MCU and HOST
                    tty.readline().rstrip("\r\n")
                    time.sleep(0.1)
                tty.close()
                self.tty = serial.Serial(portstr, baudrate=230400,
                                         timeout=1, writeTimeout=1)
                break
            tty.close()
            continue
        
        if self.tty is None:
            raise IOError
        
        try: fcntl.flock(self.tty, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            log.debug("failed to exclusively lock {0}".format(self.tty.port))
            raise IOError
        
    def close(self):
        log.debug("closing {0}".format(self.tty.port))
        fcntl.flock(self.tty, fcntl.LOCK_UN)
        self.tty.close()
        self.tty = None

    def write(self, frame):
        if self.tty is not None:
            log.debug(">>> " + str(frame).encode("hex"))
            self.tty.flushInput()
            try: self.tty.write("2" + frame)
            except serial.SerialTimeoutException:
                raise IOError("serial communication error")

    def read(self, timeout):
        if self.tty is not None:
            self.tty.timeout = max(timeout / 1000.0, 0.05)
            #log.debug("tty timeout set to {0} sec".format(self.tty.timeout))
            frame = bytearray(self.tty.read(6))
            if frame:
                if not frame == "\x00\x00\xff\x00\xff\x00":
                    self.tty.timeout = 1
                    LEN = frame[3]
                    if LEN == 255:
                        frame += self.tty.read(3)
                        LEN = frame[5] * 256 + frame[6]
                    frame += self.tty.read(LEN + 1)
                log.debug("<<< " + str(frame).encode("hex"))
                return frame

class Device(pn53x.Device):
    def __init__(self, dev):
        super(Device, self).__init__(dev)

    def listen(self, general_bytes, timeout):
        try:
            data = super(Device, self).listen(general_bytes, timeout)
        except pn53x.NoResponse:
            try: self.dev.diagnose(0, "")
            except: pass
        else:
            speed = ("106", "212", "424")[(data[0]>>4) & 0x07]
            cmode = ("passive", "active", "passive")[data[0] & 0x03]
            ttype = ("card", "p2p")[bool(data[0] & 0x04)]
            info = "activated as {0} target in {1} kbps {2} mode"
            log.info(info.format(ttype, speed, cmode))
            return str(data[18:])
            
def init(devname):
    try: bus = arygon_tty(devname)
    except IOError: return None
    dev = pn53x.pn53x(bus)
    device = Device(dev)
    device._vendor = "Arygon"
    device._product = "APPx-ADRx"
    return device
