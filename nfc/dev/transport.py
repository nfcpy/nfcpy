# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# transport.py
#

import logging
log = logging.getLogger(__name__)

import importlib
import errno
import sys
import os
import re

class USB(object):
    @classmethod
    def find(cls, path):
        cls.pyusb_version = None

        try:
            cls.usb_core = importlib.import_module("usb.core")
            cls.usb_util = importlib.import_module("usb.util")
            cls.pyusb_version = 1
        except ImportError: pass
        
        if cls.pyusb_version is None:
            try: 
                cls.usb = importlib.import_module("usb")
                cls.pyusb_version = 0
            except ImportError: pass

        if cls.pyusb_version is None:
            log.error("no python usb library could be loaded")
            return None
        
        log.debug("using pyusb version {0}.x".format(cls.pyusb_version))
        
        usb_or_none = re.compile(r'^(usb|)$')
        usb_vid_pid = re.compile(r'^usb(:[0-9a-fA-F]{4})(:[0-9a-fA-F]{4})?$')
        usb_bus_dev = re.compile(r'^usb(:[0-9]{1,3})(:[0-9]{1,3})?$')
        match = None

        for regex in (usb_vid_pid, usb_bus_dev, usb_or_none):
            m = regex.match(path)
            if m is not None:
                log.debug("path matches {0!r}".format(regex.pattern))
                if regex is usb_vid_pid:
                    match = [int(s.strip(':'), 16) for s in m.groups() if s]
                    match = dict(zip(['idVendor', 'idProduct'], match))
                if regex is usb_bus_dev:
                    match = [int(s.strip(':'), 10) for s in m.groups() if s]
                    match = dict(zip(['bus', 'address'], match))
                if regex is usb_or_none:
                    match = dict()
                break
        else: return None

        if cls.pyusb_version == 1:
            return [(d.idVendor, d.idProduct, d.bus, d.address)
                    for d in cls.usb_core.find(find_all=True, **match)]

        if cls.pyusb_version == 0:
            # get all devices for all busses first, then filter
            devices = [(d, b) for b in cls.usb.busses() for d in b.devices]
            vid, pid = match.get('idVendor'), match.get('idProduct')
            bus, dev = match.get('bus'), match.get('address')
            if vid is not None:
                devices = [d for d in devices if d[0].idVendor == vid]
            if pid is not None:
                devices = [d for d in devices if d[0].idProduct == pid]
            if bus is not None:
                devices = [d for d in devices if int(d[1].dirname) == bus]
            if dev is not None:
                devices = [d for d in devices if int(d[0].filename) == dev]
            return [(d[0].idVendor, d[0].idProduct, d[1].dirname,
                     d[0].filename) for d in devices]

    def __init__(self, bus_id, dev_id):
        self.usb_out = None
        self.usb_inp = None
        
        if self.pyusb_version == 0:
            self.open  = self._PYUSB0_open
            self.read  = self._PYUSB0_read
            self.write = self._PYUSB0_write
            self.close = self._PYUSB0_close
            self.get_string = self._PYUSB0_get_string
        elif self.pyusb_version == 1:
            self.open  = self._PYUSB1_open
            self.read  = self._PYUSB1_read
            self.write = self._PYUSB1_write
            self.close = self._PYUSB1_close
            self.get_string = self._PYUSB1_get_string
        else:
            log.error("unexpected pyusb version")
            raise SystemExit

        self.open(bus_id, dev_id)

    @property
    def manufacturer_name(self):
        if self.manufacturer_name_id:
            return self.get_string(100, self.manufacturer_name_id)
        
    @property
    def product_name(self):
        if self.product_name_id:
            return self.get_string(100, self.product_name_id)

    def _PYUSB0_get_string(self, length, index, langid=-1):
        return self.usb_dev.getString(index, length, langid)
        
    def _PYUSB1_get_string(self, length, index, langid=None):
        return self.usb_util.get_string(self.usb_dev, length, index, langid)
        
    def _PYUSB0_open(self, bus_id, dev_id):
        bus = [b for b in self.usb.busses() if b.dirname == bus_id][0]
        dev = [d for d in bus.devices if d.filename == dev_id][0]
        self.usb_dev = dev.open()
        try:
            self.usb_dev.setConfiguration(dev.configurations[0])
            self.usb_dev.claimInterface(0)
        except self.usb.USBError:
            raise IOError("unusable device")
        self.usb_dev.reset()
        interface = dev.configurations[0].interfaces[0]
        endpoints = interface[0].endpoints
        bulk_inp = lambda ep: (\
            (ep.type == self.usb.ENDPOINT_TYPE_BULK) and
            (ep.address & self.usb.ENDPOINT_DIR_MASK == self.usb.ENDPOINT_IN))
        bulk_out = lambda ep: (\
            (ep.type == self.usb.ENDPOINT_TYPE_BULK) and
            (ep.address & self.usb.ENDPOINT_DIR_MASK == self.usb.ENDPOINT_OUT))
        self.usb_out = [ep for ep in endpoints if bulk_out(ep)].pop().address
        self.usb_inp = [ep for ep in endpoints if bulk_inp(ep)].pop().address
        self.manufacturer_name_id = dev.iManufacturer
        self.product_name_id = dev.iProduct
    
    def _PYUSB1_open(self, bus_id, dev_id):
        self.usb_dev = self.usb_core.find(bus=bus_id, address=dev_id)
        self.usb_dev.set_configuration()
        interface = self.usb_util.find_descriptor(self.usb_dev[0])
        bulk_inp = lambda ep: (\
            (self.usb_util.endpoint_type(ep.bmAttributes) ==
             self.usb_util.ENDPOINT_TYPE_BULK) and
            (self.usb_util.endpoint_direction(ep.bEndpointAddress) ==
             self.usb_util.ENDPOINT_IN))
        bulk_out = lambda ep: (\
            (self.usb_util.endpoint_type(ep.bmAttributes) ==
             self.usb_util.ENDPOINT_TYPE_BULK) and
            (self.usb_util.endpoint_direction(ep.bEndpointAddress) ==
             self.usb_util.ENDPOINT_OUT))
        self.usb_out = [ep for ep in interface if bulk_out(ep)].pop()
        self.usb_inp = [ep for ep in interface if bulk_inp(ep)].pop()
        try:
            # implicitely claim interface
            self.usb_out.write('')
        except self.usb_core.USBError:
            raise IOError(errno.EACCES, os.strerror(errno.EACCES))
        self.manufacturer_name_id = self.usb_dev.iManufacturer
        self.product_name_id = self.usb_dev.iProduct
        
    def _PYUSB0_read(self, timeout):
        if self.usb_inp is not None:
            try:
                frame = self.usb_dev.bulkRead(self.usb_inp, 300, timeout)
            except self.usb.USBError as error:
                if error.message == "Connection timed out":
                    ETIMEDOUT = errno.ETIMEDOUT
                    raise IOError(ETIMEDOUT, os.strerror(ETIMEDOUT))
                else:
                    log.error("{0!r}".format(error))
                    raise IOError(errno.EIO, os.strerror(errno.EIO))
            else:
                frame = bytearray(frame)
                log.debug("<<< " + str(frame).encode("hex"))
                return frame
    
    def _PYUSB1_read(self, timeout):
        if self.usb_inp is not None:
            try:
                frame = self.usb_inp.read(300, timeout)
            except self.usb_core.USBError as error:
                if error.errno != errno.ETIMEDOUT:
                    log.error("{0!r}".format(error))
                raise error
            else:
                frame = bytearray(frame)
                log.debug("<<< " + str(frame).encode("hex"))
                return frame

    def _PYUSB0_write(self, frame):
        if self.usb_out is not None:
            log.debug(">>> " + str(frame).encode("hex"))
            try:
                self.usb_dev.bulkWrite(self.usb_out, frame)
                if len(frame) % 64 == 0: # must end bulk transfer
                    self.usb_dev.bulkWrite(self.usb_out, '')
            except self.usb.USBError as error:
                if error.message == "Connection timed out":
                    ETIMEDOUT = errno.ETIMEDOUT
                    raise IOError(ETIMEDOUT, os.strerror(ETIMEDOUT))
                else:
                    log.error("{0!r}".format(error))
                    raise IOError(errno.EIO, os.strerror(errno.EIO))
        
    def _PYUSB1_write(self, frame):
        if self.usb_out is not None:
            log.debug(">>> " + str(frame).encode("hex"))
            try:
                self.usb_out.write(frame)
                if len(frame) % self.usb_out.wMaxPacketSize == 0:
                    self.usb_out.write('') # end bulk transfer
            except self.usb_core.USBError as error:
                if error.errno != errno.ETIMEDOUT:
                    log.error("{0!r}".format(error))
                raise error
        
    def _PYUSB0_close(self):
        if self.usb_dev is not None:
            self.usb_dev.releaseInterface()
        self.usb_dev = self.usb_out = self.usb_inp = None

    def _PYUSB1_close(self):
        if self.usb_dev is not None:
            self.usb_util.dispose_resources(self.usb_dev)
        self.usb_dev = self.usb_out = self.usb_inp = None
