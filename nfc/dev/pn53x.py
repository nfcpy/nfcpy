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

import os
import time
import usb
import sys
from array import array

if os.name == "posix":
    import serial
    import fcntl

supported_devices = []
supported_devices.append((0x054c,0x02e1)) # Sony RC-S330
supported_devices.append((0x04cc,0x0531)) # Philips demo board
supported_devices.append((0x054c,0x0193)) # Sony demo board
supported_devices.append((0x04e6,0x5591)) # SCM SCL3711

class pn53x(object):
    @staticmethod
    def search():
        if os.name == "posix":
            log.info("searching for a usb tty reader")
            import glob
            for name in glob.glob("/dev/ttyUSB*"):
                log.info("trying reader at {0}".format(name))
                try: return pn53x_tty(name)
                except IOError: pass

        log.info("searching for a usb bus reader")
        for bus in usb.busses():
            for dev in bus.devices:
                if (dev.idVendor, dev.idProduct) in supported_devices:
                    log.info("trying reader at usb port {0}:{1}"
                             .format(bus.dirname, dev.filename))
                    try: return pn53x_usb(dev)
                    except usb.USBError: pass

        raise LookupError("couldn't find any usable pn53x hardware module")

    def get_firmware_version(self):
        self.write("\xD4\x02")
        data = self.read(timeout=100)
        if data is not None and data.startswith("\xD5\x03"):
            return data[2:]
        else: raise IOError(0, "could not read firmware version")

    def reset_mode(self):
        if self.ic == "PN533" and self.fw == "1.48":
            self.write("\xD4\x18\x01")
            self.read(timeout=100)
            self.write('')
        
    def read_register(self, addr):
        if type(addr) == type(int):
            addr = [addr]
        addr = array("H", addr)
        if sys.byteorder == "little":
            addr.byteswap()
        self.write("\xd4\x06" + addr.tostring())
        data = self.read(timeout=100)
        if data is not None and data.startswith("\xd5\x07"):
            if self.ic == "PN533" and self.fw == "1.48":
                return array("B", data[2:])
            elif ord(data[2]) == 0:
                return array("B", data[3:])
            else:
                log.error("chip error {} at read register"
                          .format(ord(data[2])))

    def in_list_passive_target(self, max_tg, br_ty, initiator_data):
        br_ty = ("106A", "212F", "424F", "106B", "106J").index(br_ty)
        if self.write("\xD4\x4A" + chr(max_tg) + chr(br_ty) + initiator_data):
            targets = list()
            rsp = self.read(timeout=500)
            if rsp and len(rsp) >= 3 and rsp.startswith("\xD5\x4B"):
                nb_tg = ord(rsp[2])
                rsp = rsp[3:]
                for i in range(nb_tg):
                    if br_ty == 0:
                        nfcid_length = ord(rsp[4])
                        ats_length = ord(rsp[5] + nfcid_length)
                        targets.append(rsp[1:5+nfcid_length+ats_length])
                    elif br_ty == 1 or br_ty == 2:
                        pol_res_length = ord(rsp[1])
                        targets.append(rsp[1:1+pol_res_length])
                    elif br_ty == 3:
                        attrib_res_length = ord(rsp[13])
                        targets.append(rsp[1:14+pol_res_length])
                    rsp = rsp[1+len(targets[-1]):]
            return targets
        raise IOError("in_list_passive_target")

    def in_jump_for_dep(self, communication_mode, baud_rate,
                        passive_initiator_data=None,
                        nfcid3=None, general_bytes=None):
        if communication_mode == "passive":
            if baud_rate == "212" or baud_rate == "424":
                if passive_initiator_data is None:
                    raise ValueError("missing passive initiator data")
                if not nfcid3 is None:
                    log.debug("nfcid3 not used in 212/424 kbps passive mode")
                    nfcid3 = ''
        
        mode = ("passive", "active").index(communication_mode)
        baud = ("106", "212", "424").index(baud_rate)
        next = (bool(passive_initiator_data) |
                bool(nfcid3) << 1 |
                bool(general_bytes) << 2)

        if self.write("\xD4\x56" + chr(mode) + chr(baud) + chr(next) +
                      passive_initiator_data + nfcid3 + general_bytes):
            rsp = self.read(timeout=500)
            if rsp and len(rsp) >= 19 and rsp.startswith("\xD5\x57\x00\x01"):
                log.info("ATR_RES(nfcid3={0}, did={1:02x}, bs={2:02x},"
                         " br={3:02x}, to={4:02x}, pp={5:02x}, gb={6})"
                         .format(rsp[4:14].encode("hex"), ord(rsp[14]),
                                 ord(rsp[15]), ord(rsp[16]), ord(rsp[17]),
                                 ord(rsp[18]), rsp[19:].encode("hex")))
                return rsp[4:]
            else:
                self.write('') # send ack to abort command
    
    def tg_init_as_target(self, activation_mode, mifare_params,
                          felica_params, nfcid3t=None, general_bytes="",
                          historical_bytes="", timeout=None):
        if not len(mifare_params) == 6:
            raise ValueError("invalid length of mifare_params")
        if not len(felica_params) == 18:
            raise ValueError("invalid length of felica_params")
        if nfcid3t is not None and not len(nfcid3t) == 10:
            raise ValueError("invalid length of nfcid3t")
        
        cmd = "\xD4\x8C"
        cmd += "\x02" if activation_mode == "DEP" else "\x00"
        cmd += mifare_params + felica_params + nfcid3t
        
        if (self.ic == "PN531") or (self.ic == "PN533" and self.fw == "1.48"):
            cmd += general_bytes
            if historical_bytes:
                s = "historical_bytes can't' be used with a {0} V{1}"
                log.warning(s.format(self.ic, self.fw))
        else:
            cmd += chr(len(general_bytes)) + general_bytes
            cmd += chr(len(historical_bytes)) + historical_bytes

        if self.write(cmd) and timeout is not None:
            rsp = self.read(timeout)
            if rsp is None:
                self.write("") # send ack to abort command
            elif rsp.startswith("\xD5\x8D"):
                mode = ord(rsp[2])
                if self.ic == "PN533" and self.fw == "1.48":
                    self.write("\xd4\x04") # get general_status
                    if self.read(timeout = 15)[6] == "\x03":
                        mode = mode | 0x4 # operating as dep target
                return mode, rsp[3:]
        return None, None
    
    def _build_frame(self, data):
        if len(data) < 256:
            frame = [0, 0, 255, len(data), 256 - len(data)]
        else:
            len_msb = len(data) / 256
            len_lsb = len(data) % 256
            len_lcs = (256 - (len_msb + len_lsb)) % 256
            frame = [0, 0, 255, 255, 255, len_msb, len_lsb, len_lcs]
        frame += [ord(c) for c in data]
        frame += [(256 - sum(frame[-len(data):])) % 256, 0]
        return ''.join([chr(x) for x in frame])

class pn53x_usb(pn53x):
    def __init__(self, dev):
        self.dh = dev.open()
        self.usb_out = None
        self.usb_inp = None
        self.dh.setConfiguration(dev.configurations[0])
        self.dh.claimInterface(0)
        intf = dev.configurations[0].interfaces[0]
        self.usb_out = intf[0].endpoints[0].address
        self.usb_inp = intf[0].endpoints[1].address

        # get chip into good state
        self.write('') # send ack
        self.write("\xd4\x00\x00")
        self.read(timeout=100)
        
        fw = self.get_firmware_version()
        if len(fw) == 2:
            self.ic = "PN531"
            self.fw = "{0}.{1}".format(ord(fw[0]), ord(fw[1]))
        elif len(fw) == 4:
            self.ic = "PN5" + fw[0].encode("hex")
            self.fw = "{0}.{1}".format(ord(fw[1]), ord(fw[2]))
        else:
            raise RuntimeError("unexpected firmware version response")
        log.info("chipset is a {0} version {1}".format(self.ic, self.fw))

    def close(self):
        self.dh = None

    def __del__(self):
        if self.dh and self.usb_out and self.usb_inp:
            rf_off = "\x00\x00\xff\x04\xfc\xd4\x32\x01\x00\xf9\x00"
            self.dh.bulkWrite(self.usb_out, rf_off)
            self.dh.bulkRead(self.usb_inp, 256, 100)
        
    def write(self, data):
        if self.dh is None or self.usb_out is None:
            return None
        log.debug("write {0} byte".format(len(data)) + format_data(data))
        if len(data) == 0: # send an ack frame to pn53x
            cnt = self.dh.bulkWrite(self.usb_out, "\x00\x00\xFF\x00\xFF\x00")
            return cnt == 6
        frame = self._build_frame(data)
        #log.debug("cmd: " + frame.encode("hex"))
        self.dh.bulkWrite(self.usb_out, frame)
        if len(frame) % 64 == 0:
            # send zero-length frame to end bulk transfer
            self.dh.bulkWrite(self.usb_out, '')
        ack = self.dh.bulkRead(self.usb_inp, 256, 100)
        return ack == (0, 0, 255, 0, 255, 0)

    def read(self, timeout):
        if self.dh is None or self.usb_inp is None:
            return None
        try: data = self.dh.bulkRead(self.usb_inp, 300, timeout)
        except usb.USBError: return None
        if data:
            #log.debug("rsp: " + ' '.join(["%02x" % x for x in data]))
            index = 8 if data[3] == 255 and data[4] == 255 else 5
            data = ''.join([chr(x) for x in data[index:-2]])
        log.debug("read {0} byte".format(len(data)) + format_data(data))
        return data if len(data) else None

class pn53x_tty(pn53x):
    def __init__(self, tty):
        self.tty = serial.Serial(tty, 115200, 8, "N", 1)
        try:
            fcntl.flock(self.tty, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            log.debug("couldn't exclusively lock {0}"
                      .format(self.tty.name))
            raise
        try:
            fw = self.get_firmware_version()
        except IOError:
            log.debug("device at {0} doesn't provide firmware version"
                      .format(self.tty.name))
            raise
        self.ic = "PN5" + fw[0].encode("hex")
        self.fw = "{0}.{1}".format(ord(fw[1]), ord(fw[2]))
        log.info("chipset is a {0} version {1}".format(self.ic, self.fw))
        
    def close(self):
        log.debug("closing {0}".format(self.tty.name))
        fcntl.flock(self.tty, fcntl.LOCK_UN)
        self.tty.close()
        self.tty = None

    def write(self, data):
        self.tty.flushInput()
        log.debug("write {0} byte".format(len(data)) + format_data(data))
        if len(data) == 0: # send an ack frame to pn53x
            return self.tty.write("\x00\x00\xFF\x00\xFF\x00") == 6
        frame = self._build_frame(data)
        log.debug("cmd: " + frame.encode("hex"))
        if self.tty.write(frame) == len(frame):
            self.tty.timeout = 1
            frame = self.tty.read(6)
            log.debug("ack: " + frame.encode("hex"))
            return frame == "\x00\x00\xFF\x00\xFF\x00"

    def read(self, timeout):
        self.tty.timeout = max(timeout / 1000.0, 0.05)
        log.debug("tty read timeout set to {0} sec".format(self.tty.timeout))
        data = self.tty.read(1) # wait until timeout expires
        if data:
            self.tty.timeout = 0
            data += self.tty.read(300) # remaining data
            log.debug("rsp: " + data.encode("hex"))
            index = 8 if data[3] == 255 and data[4] == 255 else 5
            data = data[index:-2]
        log.debug("read {0} byte".format(len(data)) + format_data(data))
        return data if len(data) else None

class device(object):
    def __init__(self):
        self.dev = pn53x.search()
        self._mtu = 251

        if self.dev.ic == "PN533":
            self._rwt = 8
            self._wtx = 1

        if self.dev.ic == "PN532":
            self._rwt = 14
            self._wtx = 7

        if self.dev.ic == "PN531":
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

        if self.dev.ic == "PN533" and self.dev.fw == "1.48":
            self.dev.write("\xD4\x18\x01")
            self.dev.read(timeout=100)
            self.dev.write('')
            self._pn533_init()

    def close(self):
        self.dev.write("\xD4\x32\x01\x00") # RF off
        self.dev.read(timeout=100)
        self.dev.close()
    
    @property
    def rwt(self):
        return (256 * 16/13.56E6) * 2**self._rwt

    @property
    def mtu(self):
        return self._mtu

    def _pn533_init(self):
        self.dev.write("\xD4\x32\x01\x00") # RF off
        self.dev.read(timeout=100)
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
        self.dev.write("\xD4\x32\x01\x00") # RF off
        self.dev.read(timeout=100)
        self.dev.write("\xD4\x18\x01")
        self.dev.read(timeout=100)
        self.dev.write('')

    def poll_dep(self, general_bytes):
        log.debug("polling for a dep target")
        self.dev.reset_mode()

        pollrq = "\x00\xFF\xFF\x00\x03"
        nfcid3 = "\x01\xfe" + os.urandom(8)

        atr_rsp = self.dev.in_jump_for_dep("passive", "424", pollrq,
                                           nfcid3, general_bytes)
        if atr_rsp is not None:
            return atr_rsp[15:]

    def poll_tt1(self):
        pass

    def poll_tt2(self):
        pass

    def poll_tt3(self):
        log.debug("polling for a type 3 tag")
        self.dev.reset_mode()

        poll_ffff = "\x00\xFF\xFF\x01\x03"
        poll_12fc = "\x00\x12\xFC\x01\x03"
        
        for br in ("424F", "212F"):
            try: rsp = self.dev.in_list_passive_target(1, br, poll_ffff)[0]
            except IndexError: continue

            if rsp[-2:] != "\x12\xFC":
                try: rsp = self.dev.in_list_passive_target(1, br, poll_12fc)[0]
                except IndexError: pass
            
            log.debug("target found, bitrate is {0} kbps".format(br[0:3]))
            return rsp[2:]
        else:
            # no target found, shut off rf field
            self.dev.write("\xD4\x32\x01\x00")
            self.dev.read(timeout=100)
            
    def listen(self, general_bytes, timeout):
        log.debug("listen: gb={0} timeout={1} ms"
                  .format(general_bytes.encode("hex"), timeout))
        
        mifare_params = "\x01\x01\x00\x00\x00\x40" # "\x08\x00\x12\x34\x56\x40"
        felica_params = "\x01\xFE" + os.urandom(6) + 8*"\x00" + "\xFF\xFF"
        nfcid3t = felica_params[0:8] + "\x00\x00"

        self.dev.reset_mode()
        mode, atr_req = self.dev.tg_init_as_target(
            "DEP", mifare_params, felica_params, nfcid3t,
            general_bytes, timeout=timeout)

        if atr_req is not None:
            speed = ("106", "212", "424")[(mode>>4) & 0x07]
            cmode = ("passive", "active", "passive")[mode & 0x03]
            ttype = ("card", "dep")[bool(mode & 0x04)]
            log.info("activated as {} target in {} kbps {} mode"
                      .format(ttype, speed, cmode))
            return atr_req[17:]
        
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

    def tt3_exchange(self, cmd, timeout=500):
        log.debug("tt3_exchange")
        if self.dev.write("\xD4\x42" + cmd):
            resp = self.dev.read(timeout)
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

