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
supported_devices.append((0x04cc,0x2533)) # NXP PN533 demo board

pn53x_cmd = {
    0x00: "Diagnose",
    0x02: "GetFirmwareVersion",
    0x04: "GetGeneralStatus",
    0x06: "ReadRegister",
    0x08: "WriteRegister",
    0x0C: "ReadGPIO",
    0x0E: "WriteGPIO",
    0x10: "SetSerialBaudrate",
    0x12: "SetParameters",
    0x16: "PowerDown",
    0x32: "RFConfiguration",
    0x58: "RFRegulationTest",
    0x18: "ResetMode",
    0x56: "InJumpForDEP",
    0x46: "InJumpForPSL",
    0x4A: "InListPassiveTarget",
    0x50: "InATR",
    0x4E: "InPSL",
    0x40: "InDataExchange",
    0x42: "InCommunicateThru",
    0x44: "InDeselect",
    0x52: "InRelease",
    0x54: "InSelect",
    0x8C: "TgInitAsTarget",
    0x92: "TgSetGeneralBytes",
    0x86: "TgGetData",
    0x8E: "TgSetData",
    0x94: "TgSetMetaData",
    0x88: "TgGetInitiatorCommand",
    0x90: "TgResponseToInitiator",
    0x8A: "TgGetTargetStatus",
    }

pn53x_err = {
    0x01: "time out, the target has not answered",
    0x02: "checksum error during rf communication",
    0x03: "parity error during rf communication",
    0x04: "erroneous bit count in anticollision",
    0x05: "framing error during mifare operation",
    0x06: "abnormal bit collision in 106 kbps anticollision",
    0x07: "insufficient communication buffer size",
    0x09: "rf buffer overflow detected by ciu",
    0x0a: "rf field not activated in time by active mode peer",
    0x0b: "protocol error during rf communication",
    0x0d: "overheated - antenna drivers deactivated",
    0x0e: "internal buffer overflow",
    0x10: "invalid command parameter",
    0x12: "unsupported command from initiator",
    0x13: "format error during rf communication",
    0x14: "mifare authentication error",
    0x23: "wrong uid check byte (14443-3)",
    0x25: "command invalid in current dep state",
    0x26: "operation not allowed in this configuration",
    0x29: "released by initiator while operating as target",
    0x2f: "deselected by initiator while operating as target",
    0x31: "initiator rf-off state detected in passive mode",
    0x7F: "pn53x application level error"
    }

class CommandError(IOError):
    def __init__(self, errno):
        strerror = pn53x_err.get(errno, "PN53x error 0x{0:02x}".format(errno))
        super(CommandError, self).__init__(errno, strerror)

class FrameError(IOError):
    def __init__(self, strerror):
        super(FrameError, self).__init__(-1, strerror)

class NoResponse(IOError):
    pass

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

    def command(self, cmd_code, cmd_data=None, timeout=100):
        """Send a chip command. Returns a byte array with the chip response.
        """
        log.debug(pn53x_cmd.get(cmd_code, "PN53x 0x{0:02X}".format(cmd_code)))
        frame = array("B", [0, 0, 255])
        LEN = 2 + len(cmd_data) if cmd_data is not None else 2
        if LEN < 256:
            frame.extend([LEN, 256 - LEN, 0xd4, cmd_code])
        else:
            LENmsb = LEN / 256
            LENlsb = LEN % 256
            LCS = (256 - (LENmsb + LENlsb)) % 256
            frame.extend([255, 255, LENmsb, LENlsb, LCS, 0xd4, cmd_code])
            pass
        if cmd_data is not None:
            frame = frame + array("B", cmd_data)
        frame.extend([(256 - sum(frame[-LEN:])) % 256, 0])
        
        self.write(frame)
        frame = self.read(timeout=100)

        if frame is None:
            raise FrameError("no response from pn53x")
        if not (frame[0] == 0 and frame[1] == 0 and frame[2] == 255):
            raise FrameError("invalid frame start")

        if frame[3] == 0 and frame[4] == 255 and frame[5] == 0:
            frame = self.read(timeout)
            if frame is None:
                raise NoResponse("no response from pn53x")
            if not (frame[0] == 0 and frame[1] == 0 and frame[2] == 255):
                raise FrameError("invalid frame start")
        else: log.warning("missing ack frame from pn53x")

        if frame[3] == 255 and frame[4] == 255:
            # extended information frame
            LEN, LCS = frame[5] * 256 + frame[6], frame[7]
            TFI, PD0 = frame[8], frame[9]
        else:
            # normal information frame 
            LEN, LCS = frame[3], frame[4]
            TFI, PD0 = frame[5], frame[6]

        if not (LEN + LCS) % 256 == 0:
            raise FrameError("lenght checksum error")
        if not TFI == 0xd5:
            if not TFI == 0x7f:
                raise FrameError("invalid frame identifier")
            else:
                raise CommandError(0x7f)
        if not PD0 == cmd_code + 1:
            raise FrameError("unexpected response code")
    
        if frame[3] == 255 and frame[4] == 255:
            # extended information frame
            if sum(frame[8:8+LEN+1]) % 256 == 0:
                return frame[10:8+LEN]
        else:
            # normal information frame 
            if sum(frame[5:5+LEN+1]) % 256 == 0:
                return frame[7:5+LEN]
            
        raise FrameError("data checksum error")

    def diagnose(self, num_tst, in_param=""):
        rsp = self.command(0x00, chr(num_tst) + in_param)
        return data if (self.ic, self.fw) == ("PN533", "1.48") else data[1:]

    def get_firmware_version(self):
        rsp = self.command(0x02)
        if len(rsp) == 2:
            ic, ver, rev, support = 0x31, rsp[0], rsp[1], 0x00
        else: ic, ver, rev, support = rsp
        return ic, ver, rev, support

    def get_general_status(self):
        return self.command(0x04)
        
    def read_register(self, addr):
        addr = array("H", list(addr) if type(addr) is type(int()) else addr)
        if sys.byteorder == "little": addr.byteswap()
        data = self.command(0x06, addr.tostring())
        if (self.ic, self.fw) == ("PN533", "1.48"):
            return data
        elif data[0] == 0:
            return data[1:]
        else: raise CommandError(data[0])

    def reset_mode(self):
        if (self.ic, self.fw) == ("PN533", "1.48"):
            self.command(0x18, [1])
            self.write(array("B", [0, 0, 255, 0, 255, 0])) # ack
            time.sleep(0.010)

    def rf_configuration(self, cfg_item, cfg_data):
        cfg_data = array("B", cfg_data)
        return self.command(0x32, array("B", [cfg_item]) + cfg_data)

    def in_list_passive_target(self, br_ty, initiator_data):
        br_ty = ("106A", "212F", "424F", "106B", "106J").index(br_ty)
        cmd_data = chr(1) + chr(br_ty) + initiator_data
        rsp_data = self.command(0x4A, cmd_data, timeout=100)
        return rsp_data[2:] if rsp_data[0] == 1 else None
            
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

        cmd_data = chr(mode) + chr(baud) + chr(next) \
            + passive_initiator_data + nfcid3 + general_bytes
        
        rsp = self.command(0x56, cmd_data, timeout=1000)
        if rsp[0] != 0:
            raise CommandError(rsp[0])
        return rsp[2:]
    
    def in_data_exchange(self, tg, data_out, timeout):
        rsp = self.command(0x40, chr(tg) + data_out, timeout)
        status, data_in = rsp[0], rsp[1:]
        if status & 0x3f:
            raise CommandError(status & 0x3f)
        return status, data_in
    
    def in_communicate_thru(self, data):
        data = self.command(0x42, data)
        status = data.pop(0) & 0x3f
        if not status == 0:
            raise CommandError(status)
        return data

    def in_deselect(self, target=0):
        if (self.ic, self.fw) == ("PN533", "1.48"):
            rsp = self.command(0x44, "\x01\x01")
            status = rsp[1] & 0x3f
        else:
            rsp = self.command(0x44, chr(target))
            status = rsp[0] & 0x3f
        if status != 0:
            raise CommandError(status)

    def in_release(self, target=0):
        if (self.ic, self.fw) == ("PN533", "1.48"):
            rsp = self.command(0x52, "\x01\x01")
            status = rsp[1] & 0x3f
        else:
            rsp = self.command(0x52, chr(target))
            status = rsp[0] & 0x3f
        if status != 0:
            raise CommandError(status)
        
    def in_select(self, target=1):
        rsp = self.command(0x54, chr(target))
        status = rsp[0] & 0x3f
        if status != 0:
            raise CommandError(status)

    def tg_init_as_target(self, activation_mode, mifare_params,
                          felica_params, nfcid3t=None, general_bytes="",
                          historical_bytes="", timeout=None):
        if not len(mifare_params) == 6:
            raise ValueError("invalid length of mifare_params")
        if not len(felica_params) == 18:
            raise ValueError("invalid length of felica_params")
        if nfcid3t is not None and not len(nfcid3t) == 10:
            raise ValueError("invalid length of nfcid3t")
        
        cmd = "\x02" if activation_mode == "DEP" else "\x00"
        cmd += mifare_params + felica_params + nfcid3t
        
        if (self.ic == "PN531") or ((self.ic, self.fw) == ("PN533", "1.48")):
            cmd += general_bytes
            if historical_bytes:
                s = "historical_bytes can't' be used with a {0} V{1}"
                log.warning(s.format(self.ic, self.fw))
        else:
            cmd += chr(len(general_bytes)) + general_bytes
            cmd += chr(len(historical_bytes)) + historical_bytes

        try:
            rsp = self.command(0x8c, cmd, timeout)
        except NoResponse:
            # send ack to abort the command processing
            self.write(array("B", [0, 0, 255, 0, 255, 0]))
        else:
            return rsp

    def tg_get_data(self, timeout):
        rsp = self.command(0x86, None, timeout)
        status, data_in = rsp[0], rsp[1:]
        if status & 0x3f != 0:
            raise CommandError(status & 0x3f)
        return status, data_in

    def tg_set_data(self, data_out, timeout):
        rsp = self.command(0x8E, data_out, timeout)
        status = rsp[0]
        if status & 0x3f != 0:
            raise CommandError(status & 0x3f)
        return status

    def tg_set_meta_data(self, data_out):
        rsp = self.command(0x94, data_out, timeout=100)
        status = rsp[0]
        if status & 0x3f != 0:
            raise CommandError(status & 0x3f)
        return status

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

        # try to get chip into a good state
        self.write(array("B", [0, 0, 255, 0, 255, 0])) # ack

        ic, ver, rev, support = self.get_firmware_version()
        self.ic = "PN5{0:02x}".format(ic)
        self.fw = "{0}.{1}".format(ver, rev)
        log.info("chipset is a {0} version {1}".format(self.ic, self.fw))

        self.reset_mode()

    def close(self):
        self.dh.releaseInterface()
        self.dh = None

    def __del__(self):
        if self.dh and self.usb_out and self.usb_inp:
            rf_off = "\x00\x00\xff\x04\xfc\xd4\x32\x01\x00\xf9\x00"
            self.dh.bulkWrite(self.usb_out, rf_off)
            self.dh.bulkRead(self.usb_inp, 256, 100)
        
    def write(self, frame):
        if self.dh is not None and self.usb_out is not None:
            log.debug(">>> " + frame.tostring().encode("hex"))
            self.dh.bulkWrite(self.usb_out, frame.tolist())
            if len(frame) % 64 == 0:
                # send zero-length frame to end bulk transfer
                self.dh.bulkWrite(self.usb_out, '')

    def read(self, timeout):
        if self.dh is not None and self.usb_inp is not None:
            try: frame = self.dh.bulkRead(self.usb_inp, 300, timeout)
            except usb.USBError as error:
                if not error.message == "No error": raise
            else:
                frame = array("B", frame)
                log.debug("<<< " + frame.tostring().encode("hex"))
                return frame

class pn53x_tty(pn53x):
    def __init__(self, tty):
        self.tty = serial.Serial(tty, 115200, 8, "N", 1)
        try:
            fcntl.flock(self.tty, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            log.debug("failed to exclusively lock {0}".format(self.tty.name))
            raise
        try:
            ic, ver, rev, support = self.get_firmware_version()
        except IOError:
            log.debug("no firmware version from {0}".format(self.tty.name))
            raise
        self.ic = "PN5{0:02x}".format(ic)
        self.fw = "{0}.{1}".format(ver, rev)
        log.info("chipset is a {0} version {1}".format(self.ic, self.fw))

    def close(self):
        log.debug("closing {0}".format(self.tty.name))
        fcntl.flock(self.tty, fcntl.LOCK_UN)
        self.tty.close()
        self.tty = None

    def write(self, frame):
        if self.tty is not None:
            self.tty.flushInput()
            log.debug(">>> " + frame.tostring().encode("hex"))
            if self.tty.write(frame) != len(frame):
                raise IOError("serial communication error")

    def read(self, timeout):
        if self.tty is not None:
            self.tty.timeout = max(timeout / 1000.0, 0.05)
            log.debug("tty timeout set to {0} sec".format(self.tty.timeout))
            frame = self.tty.read(6) # wait until timeout expires
            if frame:
                if not frame == "\x00\x00\xff\x00\xff\x00":
                    self.tty.timeout = 0
                    frame += self.tty.read(300) # remaining data
                frame = array("B", frame)
                log.debug("<<< " + frame.tostring().encode("hex"))
                return frame

class device(object):
    def __init__(self):
        self.dev = pn53x.search()
        self.miu = 251

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
        atr_res_to = 11 # T = 100 * 2^(x-1) µs
        non_dep_to = 12 # T = 100 * 2^(x-1) µs
        log.debug("ATR_RES timeout: {0:7.1f} ms".format(0.1*2**(atr_res_to-1)))
        log.debug("non-DEP timeout: {0:7.1f} ms".format(0.1*2**(non_dep_to-1)))
        atr_res_to = chr(atr_res_to); non_dep_to = chr(non_dep_to)
        self.dev.rf_configuration(0x02, chr(0x0b) + atr_res_to + non_dep_to)
        
        # retries for ATR_REQ, PSL_REQ, target activation
        self.dev.rf_configuration(0x05, "\x02\x01\x00")

        if self.dev.ic == "PN533" and self.dev.fw == "1.48":
            self.dev.reset_mode()
            cfg_data = chr(self._rwt) + chr(self._wtx) + "\x08"
            self.dev.rf_configuration(0x82, cfg_data)
            self.dev.command(0x08, "\x63\x0d\x00")
            regs = self.dev.read_register(range(0xa01b, 0xa023))
            self.dev.rf_configuration(0x0b, regs)

    def close(self):
        self.dev.reset_mode()
        try: self.dev.rf_configuration(0x01, "\x00") # RF off
        except CommandError: pass
        self.dev.close()
    
    @property
    def rwt(self):
        return (256 * 16/13.56E6) * 2**self._rwt

    def poll(self, p2p_activation_data=None):
        for poll in (self.poll_nfca, self.poll_nfcb, self.poll_nfcf):
            target = poll()
            if target is not None:
                if target['type'] is not "DEP":
                    return target
                if p2p_activation_data is not None:
                    return self.poll_dep(p2p_activation_data)

    def poll_nfca(self):
        log.debug("polling for NFC-A technology")
        self.dev.reset_mode()

        rsp = self.dev.in_list_passive_target("106A", "")        
        if rsp is not None:
            log.debug("NFC-A target found at 106 kbps")
            atq = rsp[1] * 256 + rsp[0]
            sak = rsp[2]
            uid = bytearray(rsp[4:4+rsp[3]])
            platform = ("T2T", "T4T", "DEP", "DEP/TT4")[(sak >> 5) & 0b11]
            log.debug("NFC-A configured for {0}".format(platform))
            if sak == 0b00000000:
                return {"type": "TT2", "ATQ": atq, "SAK": sak, "UID": uid}
            elif sak & 0b00100000 == 0b00100000:
                return {"type": "TT4", "ATQ": atq, "SAK": sak, "UID": uid}
            elif sak & 0b01000000 == 0b01000000:
                return {"type": "DEP", "ATQ": atq, "SAK": sak, "UID": uid}
        else:
            rsp = self.dev.in_list_passive_target("106J", "")
            if rsp is not None:
                log.debug("NFC-J tag found at 106 kbps")
                print rsp.tostring().encode("hex")
                atq = rsp[1] * 256 + rsp[0]
                uid = bytearray(rsp[2:])
                RALL = "\x00\x00" + str(rsp[2:])
                self.dev.in_data_exchange(0x01, RALL , 100)
                return {"type": "TT1", "ATQ": atq, "SAK": 0, "UID": rsp[2:]}

        # no target found, shut off rf field
        self.dev.rf_configuration(0x01, "\x00")

    def poll_nfcb(self):
        return None
    
    def poll_nfcf(self):
        log.debug("polling for NFC-F technology")
        self.dev.reset_mode()

        poll_ffff = "\x00\xFF\xFF\x01\x03"
        poll_12fc = "\x00\x12\xFC\x01\x03"

        for br in ("424F", "212F"):
            rsp = self.dev.in_list_passive_target(br, poll_ffff)
            if rsp is None: continue

            if (rsp[2], rsp[3]) == (0x01, 0xFE):
                return {"type": "DEP"}

            if (rsp[-2], rsp[-1]) != (0x12, 0xFC):
                tmp_rsp = self.dev.in_list_passive_target(br, poll_12fc)
                if tmp_rsp is not None: rsp = tmp_rsp
            
            idm = bytearray(rsp[2:10])
            pmm = bytearray(rsp[10:18])
            sys = bytearray(rsp[18:20])
            log.debug("NFC-F target found at {0} kbps".format(br[0:3]))
            return {"type": "TT3", "IDm": idm, "PMm": pmm, "SYS": sys}
        else:
            # no target found, shut off rf field
            self.dev.rf_configuration(0x01, "\x00")
            
    def poll_dep(self, general_bytes):
        log.debug("polling for a dep target")
        self.dev.reset_mode()

        pollrq = "\x00\xFF\xFF\x00\x03"
        nfcid3 = "\x01\xfe" + os.urandom(8)

        try:
            rsp = self.dev.in_jump_for_dep("active", "424", pollrq,
                                           nfcid3, general_bytes)
        except CommandError as (errno, strerror):
            if errno != 1: raise
            
        log.info("ATR_RES(nfcid3={0}, did={1:02x}, bs={2:02x},"
                 " br={3:02x}, to={4:02x}, pp={5:02x}, gb={6})"
                 .format(rsp[0:10].tostring().encode("hex"),
                         rsp[10], rsp[11], rsp[12], rsp[13],
                         rsp[14], rsp[15:].tostring().encode("hex")))
        return {"type": "DEP", "data": rsp[15:].tostring()}

    def listen(self, general_bytes, timeout):
        log.debug("listen: gb={0} timeout={1} ms"
                  .format(general_bytes.encode("hex"), timeout))
        
        mifare_params = "\x01\x01\x00\x00\x00\x40" # "\x08\x00\x12\x34\x56\x40"
        felica_params = "\x01\xFE" + os.urandom(6) + 8*"\x00" + "\xFF\xFF"
        nfcid3t = felica_params[0:8] + "\x00\x00"

        self.dev.reset_mode()
        data = self.dev.tg_init_as_target(
            "DEP", mifare_params, felica_params, nfcid3t,
            general_bytes, timeout=timeout)

        if data is not None:
            if (self.dev.ic, self.dev.fw) == ("PN533", "1.48"):
                if self.dev.get_general_status()[4] == 3:
                    data[0] |= 0x4 # initialized as dep target
                
            speed = ("106", "212", "424")[(data[0]>>4) & 0x07]
            cmode = ("passive", "active", "passive")[data[0] & 0x03]
            ttype = ("card", "dep")[bool(data[0] & 0x04)]
            log.info("activated as {0} target in {1} kbps {2} mode"
                      .format(ttype, speed, cmode))
            return data[18:].tostring()
        
    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, data, timeout):
        for i in range(0, len(data), self.miu)[0:-1]:            
            self.dev.in_data_exchange(0x41, data[0:self.miu], timeout=100)
            data = data[self.miu:]
        status, data_in = self.dev.in_data_exchange(0x01, data, timeout)
        data = data_in.tostring()
        while bool(status & 0x40):
            status, data_in = self.dev.in_data_exchange(0x01, "", timeout=100)
            data = data + data_in.tostring()
        return data

    def dep_get_data(self, timeout):
        if (self.dev.ic, self.dev.fw) == ("PN533", "1.48"):
            if self.dev.get_general_status()[4] == 4:
                # initiator cmd was received in set data
                timeout = 100
        status, data_in = self.dev.tg_get_data(timeout)
        data = data_in.tostring()
        while status == 0x40:
            status, data_in = self.dev.tg_get_data(timeout=100)
            data = data + data_in.tostring()
        return data
    
    def dep_set_data(self, data, timeout):
        if (self.dev.ic, self.dev.fw) != ("PN533", "1.48"):
            timeout = 100
        for i in range(0, len(data), self.miu)[0:-1]:
            self.dev.tg_set_meta_data(data[0:self.miu])
            data = data[self.miu:]
        self.dev.tg_set_data(data, timeout)
        
    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        rsp = self.dev.in_data_exchange(0x01, cmd, timeout=100)
        return rsp[1].tostring()

    def tt2_exchange(self, cmd):
        rsp = self.dev.in_data_exchange(0x01, cmd, timeout=100)
        return rsp[1].tostring()

    def tt3_exchange(self, cmd, timeout=500):
        log.debug("tt3_exchange")
        rsp = self.dev.in_communicate_thru(cmd)
        return rsp.tostring()

    def tt4_exchange(self, cmd):
        raise NotImplemented

