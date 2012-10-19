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

import logging
log = logging.getLogger(__name__)

import os
import re
import sys
import glob

__all__ = ["pn53x"]

usb_device_map = {
    (0x04cc, 0x0531) : "pn53x_usb", # Philips demo board
    (0x054c, 0x0193) : "pn53x_usb", # Sony demo board
    (0x04cc, 0x2533) : "pn53x_usb", # NXP PN533 demo board
    (0x04cc, 0x0531) : "pn53x_usb", # SCM SCL3710
    (0x04e6, 0x5591) : "pn53x_usb", # SCM SCL3711
    (0x04e6, 0x5593) : "pn53x_usb", # SCM SCL3712
    (0x054c, 0x02e1) : "rcs956_usb", # Sony RC-S330/360/370
    (0x072f, 0x2200) : "acr122_usb", # Arygon ACR122U
    }

def connect(path=None):
    def import_driver(name):
        name = "nfc.dev.{0}".format(name)
        log.debug("import {0}".format(name))
        __import__(name)
        return sys.modules[name]
        
    if path is None:
        path = ""
        
    if path == "" or path.startswith("usb"):
        log.info("searching for a usb bus reader")
        import usb
        #
        # match "usb:vendor:[product]"
        #
        match = re.match(r"usb:([0-9a-fA-F]{4}):([0-9a-fA-F]{4})?$", path)
        if match is not None:
            log.debug("path match for 'usb:vendor:[product]'")
            vendor, product = [int(x,16) if x else None for x in match.groups()]
            for bus in usb.busses():
                for dev in bus.devices:
                    if dev.idVendor == vendor:
                        if product is None or dev.idProduct == product:
                            log.debug("trying usb:{0:04x}:{1:04x}"
                                      .format(dev.idVendor, dev.idProduct))
                            if (vendor, dev.idProduct) in usb_device_map:
                                product = dev.idProduct
                                module = usb_device_map[(vendor, product)]
                                driver = import_driver(module)
                                try:
                                    device = driver.init(dev)
                                except IOError:
                                    continue
                                device._path = "usb:{0}:{1}".format(
                                    bus.dirname, dev.filename)
                                return device
        #
        # match "usb:[[bus]:][devnum]" or "usb" or None
        #
        match = re.match("usb:([0-9]{1,3})?[:]?([0-9]{1,3})?$", path)
        if match is not None:
            log.debug("path match for 'usb:[[bus]:][devnum]'")
            busnum, devnum = [int(x) if x else None for x in match.groups()]
            for bus in usb.busses():
                if busnum is None or int(bus.dirname) == busnum:
                    for dev in bus.devices:
                        if devnum is None or int(dev.filename) == devnum:
                            log.debug("trying usb:{0}:{1}"
                                      .format(bus.dirname, dev.filename))
                            vendor, product = dev.idVendor, dev.idProduct
                            if (vendor, product) in usb_device_map:
                                module = usb_device_map[(vendor, product)]
                                driver = import_driver(module)
                                try:
                                    device = driver.init(dev)
                                except IOError:
                                    continue
                                device._path = "usb:{0}:{1}".format(
                                    bus.dirname, dev.filename)
                                return device
        #
        # match "usb" or ""
        #
        if path == "usb" or path == "":
            log.debug("path match for 'usb' (or no path given)")
            for bus in usb.busses():
                for dev in bus.devices:
                    log.debug("trying usb:{0}:{1}"
                              .format(bus.dirname, dev.filename))
                    vendor, product = dev.idVendor, dev.idProduct
                    if (vendor, product) in usb_device_map:
                        module = usb_device_map[(vendor, product)]
                        driver = import_driver(module)
                        try:
                            device = driver.init(dev)
                        except IOError:
                            continue
                        device._path = "usb:{0}:{1}".format(
                            bus.dirname, dev.filename)
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

class Device(object):
    def __init__(self, dev):
        raise NotImplemented
    
    def close(self):
        raise NotImplemented
    
    def poll(self, p2p_activation_data=None):
        raise NotImplemented

    def listen(self, general_bytes, timeout):
        raise NotImplemented
        
    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, data, timeout):
        raise NotImplemented

    def dep_get_data(self, timeout):
        raise NotImplemented
    
    def dep_set_data(self, data, timeout):
        raise NotImplemented
        
    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        raise NotImplemented

    def tt2_exchange(self, cmd):
        raise NotImplemented

    def tt3_exchange(self, cmd, timeout=500):
        raise NotImplemented

    def tt4_exchange(self, cmd):
        raise NotImplemented

    @property
    def vendor(self):
        return self._vendor
        
    @property
    def product(self):
        return self._product
        
    @property
    def path(self):
        return self._path

    def __str__(self):
        return "{dev.vendor} {dev.product} at {dev.path}".format(dev=self)
        
