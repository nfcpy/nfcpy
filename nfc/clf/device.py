# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import sys
import errno
import importlib
from . import transport

usb_device_map = {
    (0x054c, 0x0193) : "pn531", # PN531 (Sony VID/PID)
    (0x04cc, 0x0531) : "pn531", # PN531 (Philips VID/PID), SCM SCL3710
    (0x04cc, 0x2533) : "pn533", # NXP PN533 demo board
    (0x04e6, 0x5591) : "pn533", # SCM SCL3711
    (0x04e6, 0x5593) : "pn533", # SCM SCL3712
    (0x054c, 0x02e1) : "rcs956", # Sony RC-S330/360/370
    (0x054c, 0x06c1) : "rcs380", # Sony RC-S380
    (0x054c, 0x06c3) : "rcs380", # Sony RC-S380
    (0x072f, 0x2200) : "acr122", # ACS ACR122U
}

def connect(path):
    """Search a local device identified by *path* and load the associated
    device driver. Construction of the *path* argument is as
    documented for the :meth:`nfc.clf.ContactlessFrontend.open`
    method. The return value is either a :class:`Device` instance or
    :const:`None`.

    """
    assert isinstance(path, str) and len(path) > 0
 
    found = transport.USB.find(path)
    if found is not None:
        for vid, pid, bus, dev in found:
            module = usb_device_map.get((vid, pid))
            if module is None: continue

            log.debug("loading {mod} driver for usb:{vid:04x}:{pid:04x}"
                      .format(mod=module, vid=vid, pid=pid))
            
            if sys.platform.startswith("linux"):
                devnode = "/dev/bus/usb/%03d/%03d" % (int(bus), int(dev))
                if not os.access(devnode, os.R_OK | os.W_OK):
                    log.debug("access denied to " + devnode)
                    if len(path.split(':')) < 3: continue
                    raise IOError(errno.EACCES, os.strerror(errno.EACCES))

            driver = importlib.import_module("nfc.clf." + module)
            try:
                device = driver.init(transport.USB(bus, dev))
            except IOError as error:
                log.debug(error)
                if len(path.split(':')) < 3: continue
                raise error

            device._path = "usb:{0:03}:{1:03}".format(int(bus), int(dev))
            return device

    found = transport.TTY.find(path) 
    if found is not None:
        port, module = found
        log.debug("trying {0} on '{1}'".format(module, path))
        driver = importlib.import_module("nfc.clf." + module)
        try:
            tty = transport.TTY(port)
            device = driver.init(tty)
            device._path = port
            return device
        except IOError:
            pass
        
    if path.startswith("udp"):
        path = path.split(':')
        host = str(path[1]) if len(path) > 1 and path[1] else 'localhost'
        port = int(path[2]) if len(path) > 2 and path[2] else 54321
        driver = importlib.import_module("nfc.clf.udp")
        device = driver.init(host, port)
        device._path = "udp:{0}:{1}".format(host, port)
        return device

class Device(object):
    """Base class for all device drivers. It mostly serves as an interface
    definition with only a few convinience methods implemented.

    """
    def __str__(self):
        n = filter(bool,(self.vendor_name,self.product_name,self.chipset_name))
        return ' '.join(n) + " at " + self.path
        
    @property
    def vendor_name(self):
        """The device vendor name. An empty string if the vendor name could
        not be determined.

        """
        return self._vendor_name if hasattr(self, "_vendor_name") else ''
        
    @property
    def product_name(self):
        """The device product name. An empty string if the product name could
        not be determined.

        """
        return self._device_name if hasattr(self, "_device_name") else ''
        
    @property
    def chipset_name(self):
        """The name of the chipset embedded in the device."""
        return self._chipset_name
        
    @property
    def path(self):
        return self._path

    def sense(self, *targets, **options):
        # A driver must implement the sense() method to probe for a
        # contactless Target. The target types and parameters are
        # provided as positional arguments. Additional options are
        # provided as keyword arguments. Possible target types are
        # subclasses of nfc.clf.TechnologyType. All targets are
        # sequentially probed within a single iteration. The number of
        # iterations and the time interval between the start of two
        # successive iterations may be set as options, the default is
        # to run a single iteration. The return value is a single
        # target type holding response data received from a
        # contactless card/device, or None.
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError(cname + ".sense() is not implemented")

    def sense_tta(self, target, timeout):
        """A device driver must implement this method to discover a Type A
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("sense_tta() is not implemented by "+cname)

    def sense_ttb(self, target, timeout):
        """A device driver must implement this method to discover a Type B
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("sense_ttb() is not implemented by "+cname)

    def sense_ttf(self, target, timeout):
        """A device driver must implement this method to discover a Type F
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("sense_ttf() is not implemented by "+cname)

    def sense_dep(self, target, timeout):
        """A device driver must implement this method to discover a DEP
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("sense_dep() is not implemented by "+cname)

    def listen_tta(self, target, timeout):
        """A device driver must implement this method to listen as a Type A
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("listen_tta() is not implemented by "+cname)

    def listen_ttb(self, target, timeout):
        """A device driver must implement this method to listen as a Type B
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("listen_ttb() is not implemented by "+cname)

    def listen_ttf(self, target, timeout):
        """A device driver must implement this method to listen as a Type F
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("listen_ttf() is not implemented by "+cname)

    def listen_dep(self, target, timeout):
        """A device driver must implement this method to listen as a DEP
        Target. The :exc:`~exceptions.NotImplementedError` exception is
        raised by default.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("listen_dep() is not implemented by "+cname)

    def exchange(self, data, timeout):
        """A device driver must implement this method for exchange of *data*
        with a remote device.

        """
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("exchange() is not implemented by "+cname)

    @staticmethod
    def add_crc_a(data):
        """Calculate the CRC-A for bytearray *data* and return *data* extended
        with the two CRC bytes.

        """
        crc = calculate_crc(data, len(data), 0x6363)
        return data + bytearray([crc & 0xff, crc >> 8])

    @staticmethod
    def check_crc_a(data):
        """Calculate the CRC-A for the leading *len(data)-2* bytes of the
        bytearray *data* and return True if the result matches the
        trailing two bytes of *data*, return False if they do not
        match.

        """
        crc = calculate_crc(data, len(data)-2, 0x6363)
        return (data[-2], data[-1]) == (crc & 0xff, crc >> 8)

    @staticmethod
    def add_crc_b(data):
        """Calculate the CRC-B for bytearray *data* and return *data* extended
        with the two CRC bytes.

        """
        crc = ~calculate_crc(data, len(data), 0xFFFF) & 0xFFFF
        return data + bytearray([crc & 0xff, crc >> 8])

    @staticmethod
    def check_crc_b(data):
        """Calculate the CRC-B for the leading *len(data)-2* bytes of the
        bytearray *data* and return True if the result matches the
        trailing two bytes of *data*, return False if they do not
        match.

        """
        crc = ~calculate_crc(data, len(data)-2, 0xFFFF) & 0xFFFF
        return (data[-2], data[-1]) == (crc & 0xff, crc >> 8)

def calculate_crc(data, size, reg):
    for octet in data[:size]:
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit: reg = reg ^ 0x8408
    return reg
