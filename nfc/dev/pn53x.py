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
# pn53x.py - hardware access module for the PN53x family of NFC chips
#

import logging
log = logging.getLogger(__name__)

import os
import time
import sys
from array import array
import nfc.dev

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
    SOF = bytearray('\x00\x00\xFF')
    ACK = bytearray('\x00\x00\xFF\x00\xFF\x00')

    def __init__(self, bus):
        self.bus = bus
        ic, ver, rev, support = self.get_firmware_version()
        self.ic = "PN5{0:02x}".format(ic)
        self.fw = "{0}.{1}".format(ver, rev)
        log.debug("chipset is a {0} version {1}".format(self.ic, self.fw))

    def close(self):
        self.bus.close()
        self.bus = None

    def command(self, cmd_code, cmd_data=None, timeout=100):
        """Send a chip command. Returns a byte array with the chip response.
        """
        log.debug(pn53x_cmd.get(cmd_code, "PN53x 0x{0:02X}".format(cmd_code)))
        frame = bytearray([0, 0, 255])
        LEN = 2 + len(cmd_data) if cmd_data is not None else 2
        if LEN < 256:
            frame += bytearray([LEN, 256 - LEN, 0xd4, cmd_code])
        else:
            LENmsb = LEN / 256
            LENlsb = LEN % 256
            LCS = (256 - (LENmsb + LENlsb)) % 256
            frame += bytearray([255, 255, LENmsb, LENlsb, LCS, 0xd4, cmd_code])
        if cmd_data is not None:
            frame += bytearray(cmd_data)
        frame += bytearray([(256 - sum(frame[-LEN:])) % 256, 0])
        
        self.bus.write(frame)

        frame = self.bus.read(timeout=100)
        
        if frame is None: raise FrameError("no response from pn53x")
        if frame[0:3] != pn53x.SOF: raise FrameError("invalid start of frame")
        if frame != pn53x.ACK: log.warning("missing ack frame from pn53x")

        while frame == pn53x.ACK:
            frame = self.bus.read(timeout)
            if frame is None:
                raise NoResponse("no response from pn53x")

        if frame[3] == 255 and frame[4] == 255:
            # extended information frame
            if sum(frame[5:8]) & 0xFF != 0:
                raise FrameError("lenght checksum error")
            LEN, TFI, PD0 = frame[5]*256+frame[6], frame[8], frame[9]
        else:
            # normal information frame 
            if sum(frame[3:5]) & 0xFF != 0:
                raise FrameError("lenght checksum error")
            LEN, TFI, PD0 = frame[3], frame[5], frame[6]

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
        return self.command(0x00, chr(num_tst) + in_param)[1:]

    def get_firmware_version(self):
        rsp = self.command(0x02)
        if len(rsp) == 2:
            ic, ver, rev, support = 0x31, rsp[0], rsp[1], 0x00
        else: ic, ver, rev, support = rsp
        return ic, ver, rev, support

    def get_general_status(self):
        return self.command(0x04)

    def read_register(self, addr):
        if type(addr) is int: addr = [addr]
        addr = ''.join([chr(x/256)+chr(x%256) for x in addr])
        data = self.command(0x06, addr)
        if data[0] != 0:
            raise CommandError(data[0])
        return data[1:]

    def rf_configuration(self, cfg_item, cfg_data):
        return self.command(0x32, bytearray([cfg_item]) + bytearray(cfg_data))

    def in_list_passive_target(self, br_ty, initiator_data):
        br_ty = ("106A", "212F", "424F", "106B", "106J").index(br_ty)
        cmd_data = chr(1) + chr(br_ty) + initiator_data
        rsp_data = self.command(0x4A, cmd_data, timeout=1000)
        return rsp_data[2:] if rsp_data[0] == 1 else None
            
    def in_jump_for_dep(self, communication_mode, baud_rate,
                        passive_initiator_data=None,
                        nfcid3=None, general_bytes=None):
        if communication_mode == "passive":
            if baud_rate == "212" or baud_rate == "424":
                if passive_initiator_data is None:
                    raise ValueError("missing passive initiator data")
            if baud_rate == "106" and passive_initiator_data is not None:
                log.debug("passive initiator data not used for 106 kbps")
                passive_initiator_data = ''
            if nfcid3 is not None:
                log.debug("nfcid3 not used in passive mode")
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
    
    def in_communicate_thru(self, data, timeout):
        rsp = self.command(0x42, data, timeout)
        if (rsp[0] & 0x3f) != 0:
            raise CommandError(rsp[0] & 0x3f)
        return rsp[1:]

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

        return self.command(0x8c, cmd, timeout)

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

class Device(nfc.dev.Device):
    def __init__(self, dev):
        self.dev = dev
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

    def close(self):
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

        rsp = self.dev.in_list_passive_target("106A", "")        
        if rsp is not None:
            log.debug("NFC-A target found at 106 kbps")
            atq = rsp[1] * 256 + rsp[0]
            sak = rsp[2]
            uid = rsp[4:4+rsp[3]]
            platform = ("TT2", "TT4", "DEP", "DEP/TT4")[(sak >> 5) & 0b11]
            log.debug("NFC-A configured for {0}".format(platform))
            if sak == 0b00000000:
                return {"type": "TT2", "ATQ": atq, "SAK": sak, "UID": uid}
            elif sak & 0b00100000:
                ats = rsp[4+len(uid):4+len(uid)+1+rsp[4+len(uid)]]
                log.debug("ATS = " + str(ats).encode("hex"))
                return {"type": "TT4", "ATQ": atq, "SAK": sak, "UID": uid}
            elif sak & 0b01000000:
                return {"type": "DEP", "ATQ": atq, "SAK": sak, "UID": uid}
        elif self.dev.ic != "PN531":
            rsp = self.dev.in_list_passive_target("106J", "")
            if rsp is not None:
                log.debug("NFC-J tag found at 106 kbps")
                atq = rsp[1] * 256 + rsp[0]
                uid = bytearray(rsp[2:])
                hdr = self.tt1_exchange("\x78\x00\x00" + str(uid))[0:2]
                if hdr[0] & 0x10 == 0x10:
                    return {"type": "TT1", "ATQ": atq, "SAK": 0,
                            "UID": uid, "HDR": hdr}

        # no target found, shut off rf field
        self.dev.rf_configuration(0x01, "\x00")

    def poll_nfcb(self):
        return None
    
    def poll_nfcf(self):
        log.debug("polling for NFC-F technology")

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
        log.debug("polling for a p2p target")
        self.dev.rf_configuration(0x01, "\x00")

        pollrq = "\x00\xFF\xFF\x00\x03"
        nfcid3 = "\x01\xfe" + os.urandom(8)

        for mode, speed in (("active", "424"), ("passive", "424")):
            try:
                rsp = self.dev.in_jump_for_dep(mode, speed, pollrq,
                                               nfcid3, general_bytes)
                log.info("activated a p2p target in {0} kbps {1} mode"
                         .format(speed, mode))
                break
            except CommandError as (errno, strerror):
                if errno != 1: raise
        else:
            return None
        
        log.debug("ATR_RES(nfcid3={0}, did={1:02x}, bs={2:02x},"
                  " br={3:02x}, to={4:02x}, pp={5:02x}, gb={6})"
                  .format(str(rsp[0:10]).encode("hex"),
                          rsp[10], rsp[11], rsp[12], rsp[13],
                          rsp[14], str(rsp[15:]).encode("hex")))
        return {"type": "DEP", "data": str(rsp[15:])}

    def listen(self, general_bytes, timeout):
        log.debug("listen: gb={0} timeout={1} ms"
                  .format(general_bytes.encode("hex"), timeout))
        
        mifare_params = "\x01\x01\x00\x00\x00\x40" # "\x08\x00\x12\x34\x56\x40"
        felica_params = "\x01\xFE" + os.urandom(6) + 8*"\x00" + "\xFF\xFF"
        nfcid3t = felica_params[0:8] + "\x00\x00"

        return self.dev.tg_init_as_target(
            "DEP", mifare_params, felica_params, nfcid3t,
            general_bytes, timeout=timeout)
        
    ##
    ## data exchange protocol
    ##
    def dep_exchange(self, data, timeout):
        for i in range(0, len(data), self.miu)[0:-1]:            
            self.dev.in_data_exchange(0x41, data[0:self.miu], timeout=100)
            data = data[self.miu:]
        status, data_in = self.dev.in_data_exchange(0x01, data, timeout)
        data = str(data_in)
        while bool(status & 0x40):
            status, data_in = self.dev.in_data_exchange(0x01, "", timeout=100)
            data = data + str(data_in)
        return data

    def dep_get_data(self, timeout):
        status, data_in = self.dev.tg_get_data(timeout)
        data = str(data_in)
        while status == 0x40:
            status, data_in = self.dev.tg_get_data(timeout=100)
            data = data + str(data_in)
        return data
    
    def dep_set_data(self, data, timeout):
        for i in range(0, len(data), self.miu)[0:-1]:
            self.dev.tg_set_meta_data(data[0:self.miu])
            data = data[self.miu:]
        self.dev.tg_set_data(data, timeout)
        
    ##
    ## tag type (1|2|3) command/response exchange
    ##
    def tt1_exchange(self, cmd):
        log.debug("tt1_exchange")
        rsp = self.dev.in_data_exchange(0x01, cmd, timeout=100)
        return rsp[1]

    def tt2_exchange(self, cmd):
        log.debug("tt2_exchange")
        rsp = self.dev.in_data_exchange(0x01, cmd, timeout=100)
        return str(rsp[1])

    def tt3_exchange(self, cmd, timeout):
        log.debug("tt3_exchange")
        rsp = self.dev.in_communicate_thru(cmd, timeout)
        return str(rsp)

    def tt4_exchange(self, cmd):
        log.debug("tt4_exchange")
        rsp = self.dev.in_data_exchange(0x01, cmd, timeout=100)
        return rsp[1]

