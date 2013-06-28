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

import logging
log = logging.getLogger(__name__)

import os
import re
import sys
import glob
import importlib

import transport

usb_device_map = {
    #(0x04cc, 0x0531) : "pn53x_usb", # Philips demo board
    #(0x054c, 0x0193) : "pn53x_usb", # Sony demo board
    #(0x04cc, 0x2533) : "pn53x_usb", # NXP PN533 demo board
    #(0x04cc, 0x0531) : "pn53x_usb", # SCM SCL3710
    #(0x04e6, 0x5591) : "pn53x_usb", # SCM SCL3711
    #(0x04e6, 0x5593) : "pn53x_usb", # SCM SCL3712
    #(0x054c, 0x02e1) : "rcs956_usb", # Sony RC-S330/360/370
    (0x054c, 0x06c1) : "rcs380", # Sony RC-S380
    (0x054c, 0x06c3) : "rcs380", # Sony RC-S380
    #(0x072f, 0x2200) : "acr122_usb", # Arygon ACR122U
    }

def connect(path=None):
    def import_driver(name):
        name = "nfc.dev.{0}".format(name)
        log.debug("import {0}".format(name))
        return importlib.import_module(name)
        
    if path is None:
        path = ""

    found = transport.USB.find(path)
    if found is not None:
        for vid, pid, bus, dev in found:
            module = usb_device_map.get((vid, pid))
            if module is not None:
                log.debug("trying usb:{0:04x}:{1:04x}".format(vid, pid))
                driver = import_driver(module)
                try:
                    usb = transport.USB(bus, dev)
                    device = driver.init(usb)
                except IOError:
                    continue
                device._path = "usb:{0:03}:{1:03}".format(bus, dev)
                return device

    if (path == "" or path.startswith("tty")) and os.name == "posix":
        log.info("searching for a tty reader")
        #
        # match "tty[:(usb|com)][:port]"
        #
        match = re.match(r"tty(?:\:(usb|com))?(?:\:([0-9]{1,2}))?$", path)
        if match is not None or path == "":
            line, port = match.groups() if match else (None, None)
            if line is None or line == "usb":
                if port is not None:
                    devname = "/dev/ttyUSB{0}".format(port)
                    log.debug("trying usb tty reader {0}".format(devname))
                    for module in ("arygon_tty", "pn53x_tty"):
                        driver = import_driver(module)
                        device = driver.init(devname)
                        if device is not None:
                            device._path = "tty:usb:{0}".format(port)
                            return device
                else:
                    log.info("searching for a usb tty reader")
                    for devname in glob.glob("/dev/ttyUSB[0-9]"):
                        log.debug("trying usb tty reader {0}".format(devname))
                        for module in ("arygon_tty", "pn53x_tty"):
                            driver = import_driver(module)
                            device = driver.init(devname)
                            if device is not None:
                                port = devname[-1]
                                device._path = "tty:usb:{0}".format(port)
                                return device
    
    elif path.startswith("tty"):
        log.info("sorry, tty readers are only supported on posix systems")

    if path.startswith("udp"):
        path = path.split(':')
        host = str(path[1]) if len(path) > 1 and path[1] else 'localhost'
        port = int(path[2]) if len(path) > 2 and path[2] else 54321
        driver = import_driver("udp")
        device = driver.init(host, port)
        device._path = "udp:{0}:{1}".format(host, port)
        return device

class Device(object):
    def __str__(self):
        return "{dev.vendor} {dev.product} at {dev.path}".format(dev=self)
        
    @property
    def vendor(self):
        return self._vendor
        
    @property
    def product(self):
        return self._product
        
    @property
    def path(self):
        return self._path

    def sense(self, targets):
        """Send discovery and activation requests to find a
        target. Targets is a list of target specifications (TTA, TTB,
        TTF defined in clf.py). Not all drivers may support all
        possible target types. The return value is an activated target
        with a possibly updated specification (bitrate) or None."""
        log.warning("Driver.sense() should be implemented.")
        return None

    def listen(self, targets, timeout):
        """Listen for the number of seconds given in timeout to become
        activated as a target. Targets is a list of target
        specifications (TTA, TTB, TTF defined in clf.py). Not all
        drivers may support all possible target types, especially
        combinations thereof. Generally most drivers will listen for
        all supported activations if none of the targets was defined
        with a specific bitrate, and listen for the first target only
        if a bitrate is set. The return value is an activated target
        with a possibly updated specification (bitrate) or None."""
        log.warning("Driver.listen() should be implemented.")
        return None

    def exchange(self, data, timeout):
        """Exchange data with an activated target (data is a command
        frame) or as an activated target (data is a response
        frame). Returns a target response frame (if data is send to an
        activated target) or a next command frame (if data is send
        from an activated target). Returns None if the communication
        link died during exchange (if data is sent as a target). The
        timeout is the number of seconds to wait for data to return,
        if the timeout expires an nfc.clf.TimeoutException is
        raised. Other nfc.clf.DigitalProtocolExceptions may be raised
        if an error is detected during communication."""
        log.warning("Driver.exchange() should be implemented.")
        return None

    def set_communication_mode(self, brm, **kwargs):
        """Set the hardware communication mode. The effect of calling
        this method depends on the hardware support, some drivers may
        purposely ignore this function. If supported, the parameter
        *brm* specifies the communication mode to choose as a string
        composed of the bitrate and modulation type, for example
        '212F' shall switch to 212 kbps Type F communication. Other
        communication parameters may be changed with optional keyword
        arguments. Currently implemented by the RC-S380 driver are the
        parameters 'add-crc' and 'check-crc' when running as
        initator. It is possible to set *brm* to an empty string if
        bitrate and modulation shall not be changed but only optional
        parameters executed."""
        log.warning("Driver.set_communication_mode() should be implemented.")
        return None
