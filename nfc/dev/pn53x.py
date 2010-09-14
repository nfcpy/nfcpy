# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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
# pn53x.py - hardware access module for the PN53x family of NFC chips
#

import logging
log = logging.getLogger(__name__)

import os, time, usb

supported_devices = [
    (0x054c, 0x02e1), # Sony RC-S330
    ]

class pn53x_usb(object):
    def __init__(self):
        self.fd = None
        self.dh = None

        if os.name == "posix":
            import glob
            for fname in glob.glob("/dev/nfc*"):
                try: self.fd = os.open(fname, os.O_RDWR | os.O_EXCL)
                except OSError: pass
                else: break

        if self.fd is None:
            log.info("Searching USB bus for contactless reader")
            for bus in usb.busses():
                for dev in bus.devices:
                    if (dev.idVendor, dev.idProduct) in supported_devices:
                        log.info("found device at USB port %s:%s"
                                 % (bus.dirname, dev.filename))
                        self.dh = dev.open()
                        self.dh.setConfiguration(dev.configurations[0])
                        self.dh.claimInterface(0)
                        intf = dev.configurations[0].interfaces[0]
                        self.usb_out = intf[0].endpoints[0].address
                        self.usb_inp = intf[0].endpoints[1].address
                        break
                if self.dh: break

        if self.fd is None and self.dh is None:
            raise LookupError("couldn't find any usable pn53x hardware module")

    def __del__(self):
        log.debug("pn53x: closing device")
        if self.fd:
            os.close(self.fd)
        if self.dh:
            self.write("\xD4\x18\x00")
            self.read(); self.write("")

    def write(self, data):
        log.debug("pn53x: write %d byte\n" % len(data) + format_data(data))
        if self.fd:
            return len(data) if os.write(self.fd, data) == len(data) else None
        if self.dh:
            return self.usb_write(data)

    def read(self, timeout = 500):
        data = ""
        if self.fd:
            # need to use select, poll or similar to implement the timeout 
            try: data = os.read(self.fd, 256)
            except OSError: return ""
        if self.dh:
            try: data = self.usb_read(timeout)
            except usb.USBError: return ""
        log.debug("read %d byte\n" % len(data) + format_data(data))
        return data

    def usb_write(self, data):
        if len(data) == 0: # send ack frame to pn53x
            self.dh.bulkWrite(self.usb_out, "\x00\x00\xFF\x00\xFF\x00")
            return
        cmd = tuple([ord(c) for c in data]); size = len(cmd)
        cmd = (0, 0, 0xFF, size, 256-size) + cmd + (256-sum(cmd)%256, 0)
        log.debug("cmd: " + ' '.join(["%02x" % x for x in cmd]))
        self.dh.bulkWrite(self.usb_out, cmd)
        ack = self.dh.bulkRead(self.usb_inp, 256, 100)
        return size if ack == (0, 0, 255, 0, 255, 0) else 0

    def usb_read(self, timeout):
        data = self.dh.bulkRead(self.usb_inp, 256, timeout)
        log.debug("rsp: " + ' '.join(["%02x" % x for x in data]))
        return ''.join([chr(x) for x in data[5:-2]])


class device(object):
    def __init__(self):
        self.dev = pn53x_usb()
        # set response timeouts (ATR: 102.4 ms, Thru: 204.8 ms)
        self.dev.write("\xD4\x32\x02\x00\x0B\x0C")
        self.dev.read()

    def poll_dep(self, gb):
        log.debug("pn53x: poll for dep")
        self.dev.write("\xD4\x18\x01")
        self.dev.read(); self.dev.write("")
        pollrq = "\x00\xFF\xFF\x00\x00"
        nfcid3 = "\x01\xfe" + 8 * "\x12"
        self.dev.write("\xD4\x56\x00\x02\x07" + pollrq + nfcid3 + gb)
        data = self.dev.read()
        if data.startswith("\xD5\x57\x00") and len(data) >= 19:
            return data[19:]

    def poll_tt1(self):
        pass

    def poll_tt2(self):
        pass

    def poll_tt3(self):
        log.debug("pn53x: polling for a type 3 tag")
        self.dev.write("\xD4\x18\x01")
        self.dev.read(); self.dev.write("")
        self.dev.write("\xD4\x4A\x01\x02\x00\xff\xff\x01\x00")
        data = self.dev.read()
        if data.startswith("\xD5\x4B\x01\x01\x14\x01"):
            return data[6:]
        self.dev.write("\xD4\x4A\x01\x01\x00\xff\xff\x01\x00")
        data = self.dev.read()
        if data.startswith("\xD5\x4B\x01\x01\x14\x01"):
            return data[6:]

    def listen(self, gb, timeout):
        log.debug("pn53x: listen")
        self.dev.write("\xD4\x18\x01")
        self.dev.read(); self.dev.write("")
        mifare = "\x01\x01\x00\x00\x00\x40" # "\x08\x00\x12\x34\x56\x40"
        felica = "\x01\xFE" + os.urandom(6) + 8*"\x00" + "\xFF\xFF"
        nfcid3 = felica[0:8] + "\x00\x00"
        gbytes = chr(len(gb)) + gb
        self.dev.write("\xD4\x8C\x00" + mifare + felica + nfcid3 + gbytes)
        data = self.dev.read(timeout)
        return data[20:]

    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, cmd, timeout, mtu):
        mtu = 240 if mtu is None else mtu
        for i in range(0, len(cmd), mtu)[0:-1]:
            self.dev.write("\xD4\x40\x41" + cmd[i:i+mtu])
            self.dev.read()
        self.dev.write("\xD4\x40\x01" + cmd[-(len(cmd)%mtu):])
        resp = self.dev.read(timeout)
        if not resp.startswith("\xD5\x41"):
            raise IOError
        data = resp[3:]
        while resp.startswith('\xD5\x41\x40'):
            resp = self.dev.read(timeout)
            data = data + resp[3:]
        if not resp.startswith("\xD5\x41\x00"):
            raise IOError
        return data

    def dep_get_data(self, timeout):
        self.dev.write("\xD4\x86")
        resp = self.dev.read(timeout)
        if not resp.startswith("\xD5\x87"):
            raise IOError
        data = resp[3:]
        while resp.startswith('\xD5\x87\x40'):
            resp = self.dev.read(timeout)
            data = data + resp[3:]
        if not resp.startswith("\xD5\x87\x00"):
            raise IOError
        return data

    def dep_set_data(self, data, mtu):
        mtu = 240 if mtu is None else mtu
        for i in range(0, len(data), mtu)[0:-1]:
            self.dev.write("\xD4\x94" + data[i:i+mtu])
            if not self.dev.read().startswith("\xD5\x95"):
                raise IOError
        self.dev.write("\xD4\x8E" + data[-(len(data) % mtu):])
        if not self.dev.read().startswith("\xD5\x8F"):
            raise IOError

    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        # UNTESTED
        self.dev.write("\xD4\x40\x01" + cmd)
        resp = self.dev.read()
        if not resp.startswith("\xD5\x41\x00"):
            raise IOError
        return resp[3:]

    def tt2_exchange(self, cmd):
        # UNTESTED
        return self.tt1_exchange(cmd)

    def tt3_exchange(self, cmd):
        log.debug("tt3_exchange")
        self.dev.write("\xD4\x42" + cmd)
        resp = self.dev.read()
        if not resp.startswith("\xD5\x43\x00"):
            raise IOError
        return resp[3:]

def format_data(data):
    import string
    printable = string.digits + string.letters + string.punctuation + ' '
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+16]])
    return '\n'.join(s)

