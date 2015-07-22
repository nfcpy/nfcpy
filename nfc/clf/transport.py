# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
# Transport layer for host to reader communication.
#
import logging
log = logging.getLogger(__name__)

import os, sys, re, errno, importlib
from binascii import hexlify

PATH = re.compile(r'^([a-z]+)(?::|)([a-zA-Z0-9]+|)(?::|)([a-zA-Z0-9]+|)$')

class TTY(object):
    TYPE = "TTY"
    
    @classmethod
    def find(cls, path):
        try:
            cls.serial = importlib.import_module("serial")
        except ImportError:
            log.error("python serial library not found")
            return None
        
        match = PATH.match(path)
        
        if match and match.group(1) == "tty":
            import termios
            if re.match(r'^\D+\d+$', match.group(2)):
                TTYS = re.compile(r'^tty{0}$'.format(match.group(2)))
            elif re.match(r'^\D+$', match.group(2)):
                TTYS = re.compile(r'^tty{0}\d+$'.format(match.group(2)))
            elif re.match(r'^$', match.group(2)):
                TTYS = re.compile(r'^tty(S|ACM|AMA|USB)\d+$')
            else:
                log.error("invalid port in 'tty' path: %r", match.group(2))
                return
            
            ttys = [fn for fn in os.listdir('/dev') if TTYS.match(fn)]
            if len(ttys) == 0: return

            # Sort ttys with custom function to correctly order numbers.
            ttys.sort(key=lambda s:"%s%3s"%(re.match('(\D+)(\d+)',s).groups()))
            log.debug('trying /dev/tty%s', ' '.join([tty[3:] for tty in ttys]))

            # Eliminate tty nodes that are not physically present or
            # inaccessible by the current user. Propagate IOError when
            # path designated exactly one device, otherwise just log.
            for i, tty in enumerate(ttys):
                try:
                    try: termios.tcgetattr(open('/dev/%s' % tty))
                    except termios.error: pass
                    else: ttys[i] = '/dev/%s' % tty
                except IOError as error:
                    if not TTYS.pattern.endswith(r'\d+$'): raise
                    else: log.debug(error)

            ttys = [tty for tty in ttys if tty.startswith('/dev/')]
            log.debug('avail: %s', ' '.join([tty for tty in ttys]))
            return ttys, match.group(3), TTYS.pattern.endswith(r'\d+$')
        
        if match and match.group(1) == "com":
            if re.match(r'^COM\d+$', match.group(2)):
                return [match.group(2)], match.group(3), False
            if re.match(r'^\d+$', match.group(2)):
                return ["COM" + match.group(2)], match.group(3), False
            if re.match(r'^$', match.group(2)):
                import serial.tools.list_ports
                ports = [p[0] for p in serial.tools.list_ports.comports()]
                log.debug('serial ports: %s', ' '.join([p for p in ports]))
                return ports, match.group(3), True
            log.error("invalid port in 'com' path: %r", match.group(2))

    @property
    def manufacturer_name(self):
        return None
        
    @property
    def product_name(self):
        return None

    def __init__(self, port=None):
        self.tty = None
        self.open(port)

    def open(self, port, baudrate=115200):
        self.close()
        self.tty = self.serial.Serial(port, baudrate, timeout=0.05)

    @property
    def port(self):
        return self.tty.port if self.tty else ''

    @property
    def baudrate(self):
        return self.tty.baudrate if self.tty else 0

    @baudrate.setter
    def baudrate(self, value):
        if self.tty:
            self.tty.baudrate = value

    def read(self, timeout):
        if self.tty is not None:
            self.tty.timeout = max(timeout/1E3, 0.05)
            frame = bytearray(self.tty.read(6))
            if frame is None or len(frame) == 0:
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
            if frame.startswith("\x00\x00\xff\x00\xff\x00"):
                log.log(logging.DEBUG-1, "<<< %s", str(frame).encode("hex"))
                return frame
            LEN = frame[3]
            if LEN == 0xFF:
                frame += self.tty.read(3)
                LEN = frame[5]<<8 | frame[6]
            frame += self.tty.read(LEN + 1)
            log.log(logging.DEBUG-1, "<<< %s", str(frame).encode("hex"))
            return frame

    def write(self, frame):
        if self.tty is not None:
            log.log(logging.DEBUG-1, ">>> %s", str(frame).encode("hex"))
            self.tty.flushInput()
            try:
                self.tty.write(str(frame))
            except self.serial.SerialTimeoutException:
                raise IOError(errno.EIO, os.strerror(errno.EIO))

    def close(self):
        if self.tty is not None:
            self.tty.flushOutput()
            self.tty.close()
            self.tty = None
        
class USB(object):
    TYPE = "USB"
    
    @classmethod
    def find(cls, path):
        if not path.startswith("usb"):
            return
        
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
            log.error("python usb library not found")
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
            return self.get_string(self.manufacturer_name_id)
        
    @property
    def product_name(self):
        if self.product_name_id:
            return self.get_string(self.product_name_id)

    def _PYUSB0_get_string(self, index, langid=-1):
        return self.usb_dev.getString(index, 126, langid)
        
    def _PYUSB1_get_string(self, index, langid=None):
        # Prior to version 1.0.0b2 pyusb's' util.get_string() needed a
        # length parameter which has since been removed. The try/except
        # clause helps support older versions until pyusb 1.0.0 is
        # finally released and sufficiently spread.
        try:
            return self.usb_util.get_string(self.usb_dev, index, langid)
        except TypeError:
            return self.usb_util.get_string(self.usb_dev, 126, index, langid)
        
    def _PYUSB0_open(self, bus_id, dev_id):
        bus = [b for b in self.usb.busses() if b.dirname == bus_id][0]
        dev = [d for d in bus.devices if d.filename == dev_id][0]
        self.usb_dev = dev.open()
        if sys.platform.startswith("darwin"):
            self.usb_dev.setConfiguration(dev.configurations[0])
        try:
            self.usb_dev.claimInterface(0)
        except self.usb.USBError:
            raise IOError(errno.EBUSY, os.strerror(errno.EBUSY))
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
        if sys.platform.startswith("darwin"):
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
            raise IOError(errno.EBUSY, os.strerror(errno.EBUSY))
        self.manufacturer_name_id = self.usb_dev.iManufacturer
        self.product_name_id = self.usb_dev.iProduct
        
    def _PYUSB0_read(self, timeout=None):
        if self.usb_inp is not None:
            while timeout is None or timeout > 0:
                try:
                    poll_wait = 500 if timeout is None else min(500, timeout)
                    frame = self.usb_dev.bulkRead(self.usb_inp, 300, poll_wait)
                except self.usb.USBError as error:
                    if str(error) != "Connection timed out":
                        log.error("%r", error)
                        raise IOError(errno.EIO, os.strerror(errno.EIO))
                    if timeout is not None:
                        timeout -= poll_wait
                else:
                    if not frame:
                        log.error("bulk read returned without data")
                        raise IOError(errno.EIO, os.strerror(errno.EIO))
                    else:
                        frame = bytearray(frame)
                        log.log(logging.DEBUG-1, "<<< %s", hexlify(frame))
                        return frame
            else:
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
    
    def _PYUSB1_read(self, timeout=None):
        if self.usb_inp is not None:
            while timeout is None or timeout > 0:
                try:
                    poll_wait = 500 if timeout is None else min(500, timeout)
                    frame = self.usb_inp.read(300, poll_wait)
                except self.usb_core.USBError as error:
                    if error.errno != errno.ETIMEDOUT:
                        log.error("%r", error)
                        raise IOError(error.errno, error.strerror)
                    if timeout is not None:
                        timeout -= poll_wait
                else:
                    if not frame:
                        log.error("bulk read returned without data")
                        raise IOError(errno.EIO, os.strerror(errno.EIO))
                    else:
                        frame = bytearray(frame)
                        log.log(logging.DEBUG-1, "<<< %s", hexlify(frame))
                        return frame
            else:
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))

    def _PYUSB0_write(self, frame):
        if self.usb_out is not None:
            log.log(logging.DEBUG-1, ">>> %s", hexlify(frame))
            try:
                self.usb_dev.bulkWrite(self.usb_out, frame)
                if len(frame) % 64 == 0: # end bulk transfer
                    self.usb_dev.bulkWrite(self.usb_out, '')
            except self.usb.USBError as error:
                if error.message == "Connection timed out":
                    ETIMEDOUT = errno.ETIMEDOUT
                    raise IOError(ETIMEDOUT, os.strerror(ETIMEDOUT))
                else:
                    log.error("%r", error)
                    raise IOError(errno.EIO, os.strerror(errno.EIO))
        
    def _PYUSB1_write(self, frame):
        if self.usb_out is not None:
            log.log(logging.DEBUG-1, ">>> %s", hexlify(frame))
            try:
                self.usb_out.write(frame)
                if len(frame) % self.usb_out.wMaxPacketSize == 0:
                    self.usb_out.write('') # end bulk transfer
            except self.usb_core.USBError as error:
                if error.errno != errno.ETIMEDOUT:
                    log.error("%r", error)
                raise IOError(error.errno, error.strerror)
        
    def _PYUSB0_close(self):
        if self.usb_dev is not None:
            self.usb_dev.releaseInterface()
        self.usb_dev = self.usb_out = self.usb_inp = None

    def _PYUSB1_close(self):
        if self.usb_dev is not None:
            self.usb_util.dispose_resources(self.usb_dev)
        self.usb_dev = self.usb_out = self.usb_inp = None

