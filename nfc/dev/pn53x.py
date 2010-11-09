# -*- coding: latin-1 -*-
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

supported_devices = []
supported_devices.append((0x054c,0x02e1)) # Sony RC-S330
supported_devices.append((0x04cc,0x0531)) # Philips demo board
supported_devices.append((0x054c,0x0193)) # Sony demo board

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
                        self.vid = dev.idVendor
                        self.pid = dev.idProduct
                        try:
                            self.dh = dev.open()
                            self.dh.claimInterface(0)
                            conf = dev.configurations[0]
                            intf = conf.interfaces[0]
                            self.ep = intf[0].endpoints[0].address
                            self.usb_out = intf[0].endpoints[0].address
                            self.usb_inp = intf[0].endpoints[1].address
                        except usb.USBError:
                            self.dh = None
                            continue
                        break
                if self.dh: break

        if self.fd is None and self.dh is None:
            raise LookupError("couldn't find any usable pn53x hardware module")

    def __del__(self):
        log.debug("closing device")
        if self.fd:
            os.close(self.fd)
        if self.dh:
            if (self.vid, self.pid) == (0x054c, 0x02e1):
                self.write("\xD4\x18\x00")
                self.read(timeout=100); self.write("")
            else: self.dh.reset()

    @property
    def vendor_id(self):
        if self.dh:
            return self.vid
        else:
            raise NotImplemented("no vendor id with /dev/nfc driver")

    @property
    def product_id(self):
        if self.dh:
            return self.pid
        else:
            raise NotImplemented("no vendor id with /dev/nfc driver")

    def write(self, data):
        log.debug("write {0} byte".format(len(data)) + format_data(data))
        if self.fd:
            return len(data) if os.write(self.fd, data) == len(data) else None
        if self.dh:
            return self.usb_write(data)

    def read(self, timeout):
        if self.fd:
            # FIXME: use select or poll to implement the timeout 
            try: data = os.read(self.fd, 256)
            except OSError: return None
        if self.dh:
            try: data = self.usb_read(timeout)
            except usb.USBError: return None
        log.debug("read {0} byte".format(len(data)) + format_data(data))
        return data

    def usb_write(self, data):
        if len(data) == 0: # send just an ack frame to pn53x
            self.dh.bulkWrite(self.usb_out, "\x00\x00\xFF\x00\xFF\x00")
            return
        if len(data) < 256:
            frame = [0, 0, 255, len(data), 256 - len(data)]
        else:
            len_msb = len(data) / 256
            len_lsb = len(data) % 256
            len_lcs = (256 - (len_msb + len_lsb)) % 256
            frame = [0, 0, 255, 255, 255, len_msb, len_lsb, len_lcs]
        frame += [ord(c) for c in data]
        frame += [(256 - sum(frame[-len(data):])) % 256, 0]
        #log.debug("cmd: " + ' '.join(["%02x" % x for x in frame]))
        self.dh.bulkWrite(self.usb_out, frame)
        ack = self.dh.bulkRead(self.usb_inp, 256, 100)
        return True if ack == (0, 0, 255, 0, 255, 0) else False

    def usb_read(self, timeout):
        data = self.dh.bulkRead(self.usb_inp, 1024, timeout)
        if data:
            #log.debug("rsp: " + ' '.join(["%02x" % x for x in data]))
            index = 8 if data[3] == 255 and data[4] == 255 else 5
            return ''.join([chr(x) for x in data[index:-2]])


class device(object):
    def __init__(self):
        self.dev = pn53x_usb()
        self.dev.write("\xD4\x02")
        data = self.dev.read(timeout=100)
        if not data.startswith("\xD5\x03"):
            raise IOError(0, "could not read firmware information")
        vendor_id, product_id = self.dev.vendor_id, self.dev.product_id
        if ((vendor_id, product_id) == (0x04cc, 0x0531) or
            (vendor_id, product_id) == (0x054c, 0x0193)):
            self.ic = "PN531"
            self.fw = "{0}.{1}".format(ord(data[2]), ord(data[3]))
        elif (vendor_id, product_id) == (0x054c, 0x02e1):
            self.ic = "PN5" + data[2].encode("hex")
            self.fw = "{0}.{1}".format(ord(data[3]), data[4].encode("hex"))
        else: raise RuntimeError("enumerated unknown (vendor,product) id")
        log.info("chipset is a {0} version {1}".format(self.ic, self.fw))

        self._mtu = 251

        if self.ic == "PN533":
            self._rwt = 8
            self._wtx = 1

        if self.ic == "PN532":
            self._rwt = 14
            self._wtx = 7

        if self.ic == "PN531":
            self._rwt = 14
            self._wtx = 7

        # set ATR_RES timeout: 409.6 ms, Thru timeout: 204.8 ms)
        atr_res_to = 13 # T = 100 * 2^(x-1) µs
        non_dep_to = 12 # T = 100 * 2^(x-1) µs
        log.debug("ATR_RES timeout: {0:7.1f} ms".format(0.1*2**(atr_res_to-1)))
        log.debug("non-DEP timeout: {0:7.1f} ms".format(0.1*2**(non_dep_to-1)))
        atr_res_to = chr(atr_res_to); non_dep_to = chr(non_dep_to)
        self.dev.write("\xD4\x32\x02\x00" + atr_res_to + non_dep_to)
        # retries for ATR_REQ, PSL_REQ, target activation
        self.dev.write("\xD4\x32\x05\xFF\xFF\x00")

        if self.ic == "PN533":
            self._pn533_init()

    @property
    def rwt(self):
        return (256 * 16/13.56E6) * 2**self._rwt

    @property
    def mtu(self):
        return self._mtu

    def _pn533_init(self):
        self.dev.write("\xD4\x32\x82"+chr(self._rwt)+chr(self._wtx)+"\x08")
        self.dev.read(timeout=100)
        self.dev.write("\xD4\x08\x63\x0d\x00")
        self.dev.read(timeout=100)
        regs = ''.join([chr(0xa0) + chr(reg) for reg in range(0x1b,0x23)])
        self.dev.write("\xD4\x06" + regs)
        data = self.dev.read(timeout=100)
        if data.startswith("\xD5\x07") and len(data) == 10:
            self.dev.write("\xD4\x32\x0B" + data[2:])

    def _pn533_reset_mode(self):
        self.dev.write("\xD4\x18\x01")
        self.dev.read(timeout=100)
        self.dev.write('')

    def poll_dep(self, gb):
        log.debug("polling for a dep target")
        if self.ic == "PN533":
            self._pn533_reset_mode()

        mode = "\x01" # 0 -> passive, 1 -> active
        baud = "\x02" # 424 kbps
        next = "\x05" # pollrq, !nfcid3, gb

        pollrq = "\x00\xFF\xFF\x00\x00"
        nfcid3 = "\x01\xfe" + os.urandom(8)

        if self.dev.write("\xD4\x56"+mode+baud+next+pollrq+gb):
            data = self.dev.read(timeout=500)
            if data and data.startswith("\xD5\x57\x00"):
                try: return data[19:]
                except IndexError: pass

    def poll_tt1(self):
        pass

    def poll_tt2(self):
        pass

    def poll_tt3(self):
        def poll(sc, br):
            cmd = "\xD4\x4A\x01" + br + "\x00" + sc + "\x01\x03"
            if self.dev.write(cmd):
                rsp = self.dev.read(timeout=1000)
                if rsp and rsp.startswith("\xD5\x4B\x01\x01\x14\x01"):
                    return rsp[6:]

        log.debug("polling for a type 3 tag")
        if self.ic == "PN533":
            self._pn533_reset_mode()

        for br in ("\x01", "\x02"): # 421 and 212 kbps
            data = poll(sc="\xFF\xFF", br=br)
            if data and data[-2:] != "\x12\xFC":
                data2 = poll(sc="\x12\xFC", br=br)
                if data2: data = data2
            if data:
                log.info(("212kbps", "424kbps")[ord(br)-1])
                return data

    def listen(self, gb, timeout):
        log.debug("listen: gb={0} timeout={1} ms"
                  .format(gb.encode("hex"), timeout))
        if self.ic == "PN533":
            self._pn533_reset_mode()

        mifare = "\x01\x01\x00\x00\x00\x40" # "\x08\x00\x12\x34\x56\x40"
        felica = "\x01\xFE" + os.urandom(6) + 8*"\x00" + "\xFF\xFF"
        nfcid3 = felica[0:8] + "\x00\x00"
        if len(gb) == 20 and self.ic in ("PN531","PN533"):
            # avoid chipset error when len(gb) is 20
            # this is ok for LLCP initialization bytes
            gb = gb + "\x00\x00"
        if self.ic == "PN532":
            gb = len(gb) + gb + '\x00'

        if self.dev.write("\xD4\x8C\x02" + mifare + felica + nfcid3 + gb):
            data = self.dev.read(timeout)
            if data and data.startswith("\xD5\x8D"):
                return data[20:]

    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, cmd, timeout, mtu):
        mtu = self.mtu
        for i in range(0, len(cmd), mtu)[0:-1]:
            self.dev.write("\xD4\x40\x41" + cmd[i:i+mtu])
            self.dev.read(timeout)
        self.dev.write("\xD4\x40\x01" + cmd[-(len(cmd)%mtu):])
        resp = self.dev.read(timeout)
        if not resp:
            raise IOError(0, "no response data")
        if not resp.startswith("\xD5\x41"):
            raise IOError(0, "invalid response")
        if not ord(resp[2]) & 0x3F == 0:
            raise IOError(ord(resp[2]), "hardware error")
        data = resp[3:]
        while resp.startswith('\xD5\x41\x40'):
            self.dev.write("\xD4\x40\x01")
            resp = self.dev.read(timeout)
            if not resp:
                raise IOError(0, "no response data")
            if not resp.startswith("\xD5\x41"):
                raise IOError(0, "invalid response")
            if not ord(resp[2]) & 0x3F == 0:
                raise IOError(ord(resp[2]), "hardware error")
            data = data + resp[3:]
        return data

    def dep_get_data(self, timeout):
        if self.dev.write("\xD4\x86"):
            resp = self.dev.read(timeout)
            if resp is None:
                raise IOError(0, "no response")
            if not resp.startswith("\xD5\x87"):
                raise IOError(0, "invalid response")
            if not ord(resp[2]) & 0x3F == 0:
                raise IOError(ord(resp[2]) & 0x3F, "hardware error")
        data = resp[3:]
        while resp.startswith('\xD5\x87\x40'):
            self.dev.write("\xD4\x86")
            resp = self.dev.read(timeout)
            if resp is None:
                raise IOError(0, "no response")
            if not resp.startswith("\xD5\x87"):
                raise IOError(0, "invalid response")
            if not ord(resp[2]) & 0x3F == 0:
                raise IOError(ord(resp[2]) & 0x3F, "hardware error")
            data = data + resp[3:]
        return data

    def dep_set_data(self, data, timeout, mtu):
        mtu = self.mtu
        for i in range(0, len(data), mtu)[0:-1]:
            if self.dev.write("\xD4\x94" + data[i:i+mtu]):
                resp = self.dev.read(timeout)
                if resp is None:
                    raise IOError(0, "no response")
                if not resp.startswith("\xD5\x95"):
                    raise IOError(0, "invalid response")
                if not ord(resp[2]) & 0x3F == 0:
                    raise IOError(ord(resp[2]) & 0x3F, "hardware error")
        if self.dev.write("\xD4\x8E" + data[-(len(data) % mtu):]):
            resp = self.dev.read(timeout)
            if resp is None:
                raise IOError(0, "no response")
            if not resp.startswith("\xD5\x8F"):
                raise IOError(0, "invalid response")
            if not ord(resp[2]) & 0x3F == 0:
                raise IOError(ord(resp[2]) & 0x3F, "hardware error")

    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        raise NotImplemented

    def tt2_exchange(self, cmd):
        raise NotImplemented

    def tt3_exchange(self, cmd):
        log.debug("tt3_exchange")
        if self.dev.write("\xD4\x42" + cmd):
            resp = self.dev.read(timeout=500)
            if resp is None:
                raise IOError(0, "no response")
            if not resp.startswith("\xD5\x43"):
                raise IOError(0, "invalid response")
            if not ord(resp[2]) & 0x3F == 0:
                raise IOError(ord(resp[2]) & 0x3F, "hardware error")
            return resp[3:]

def format_data(data):
    import string
    if len(data) == 0:
        return ''
    printable = string.digits + string.letters + string.punctuation + ' '
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+16]])
    return '\n' + '\n'.join(s)

