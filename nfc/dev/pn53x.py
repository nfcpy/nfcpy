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
import errno
import struct

import nfc.dev
import nfc.clf

TIMEOUT_TABLE = (
    0.0, 0.0001, 0.0002, 0.0004, 0.0008, 0.0016, 0.0032, 0.0064, 0.0128,
    0.0256, 0.0512, 0.1024, 0.2048, 0.4096, 0.8192, 1.64, 3.28)

def timeout_to_index(timeout):
    for index in range(len(TIMEOUT_TABLE)):
        if TIMEOUT_TABLE[index] >= timeout:
            return (index, TIMEOUT_TABLE[index])
    else: return (len(TIMEOUT_TABLE)-1, TIMEOUT_TABLE[-1])

PN53X_CMD = {
    0x00: "Diagnose",
    0x02: "GetFirmwareVersion",
    0x04: "GetGeneralStatus",
    0x06: "ReadRegister",
    0x08: "WriteRegister",
    0x0C: "ReadGPIO",
    0x0E: "WriteGPIO",
    0x10: "SetSerialBaudrate",
    0x12: "SetParameters",
    0x14: "SAMConfiguration",
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

PN53X_ERR = {
    0x01: "Time out, the Target has not answered",
    0x02: "Checksum error during RF communication",
    0x03: "Parity error during RF communication",
    0x04: "Erroneous bit count in anticollision",
    0x05: "Framing error during mifare operation",
    0x06: "Abnormal bit collision in 106 kbps anticollision",
    0x07: "Insufficient communication buffer size",
    0x09: "RF buffer overflow detected by CIU",
    0x0a: "RF field not activated in time by active mode peer",
    0x0b: "Protocol error during RF communication",
    0x0d: "Overheated - antenna drivers deactivated",
    0x0e: "Internal buffer overflow",
    0x10: "Invalid command parameter",
    0x12: "Unsupported command from Initiator",
    0x13: "Format error during RF communication",
    0x14: "Mifare authentication error",
    0x23: "Wrong UID check byte (14443-3)",
    0x25: "Command invalid in current DEP state",
    0x26: "Operation not allowed in this configuration",
    0x29: "Released by Initiator while operating as Target",
    0x2f: "Deselected by Initiator while operating as Target",
    0x31: "Initiator RF-OFF state detected in passive mode",
    0x7f: "Invalid command syntax - received error frame",
    0xff: "No data received from executing chip command",
    }

class ChipsetError:
    def __init__(self, errno):
        try: self.errno = errno[0]
        except TypeError: self.errno = 0xff if errno is None else errno
        self.strerror = PN53X_ERR.get(self.errno, "Unknown error code")

    def __str__(self):
        return "[PN53x Error 0x{e.errno:02x}] {e.strerror}".format(e=self)

class Chipset(object):
    SOF = bytearray('\x00\x00\xFF')
    ACK = bytearray('\x00\x00\xFF\x00\xFF\x00')

    def __init__(self, transport):
        self.CMD = PN53X_CMD
        self.transport = transport
        
        ic, ver, rev, support = self.get_firmware_version()
        self.ic = "PN5{0:02x}".format(ic)
        self.fw = "{0}.{1}".format(ver, rev)
        log.debug("chipset is a {0} version {1}".format(self.ic, self.fw))

        if self.ic == 'PN531':
            self.set_parameters = self.pn531_set_parameters
            self.max_packet_data_size = 254
            self.pn531_sam_configuration("normal")
        elif self.ic == 'PN532':
            self.set_parameters = self.pn532_set_parameters
            self.max_packet_data_size = 264
            self.pn532_sam_configuration("normal")
        elif self.ic == 'PN533':
            self.set_parameters = self.pn533_set_parameters
            self.max_packet_data_size = 264
            
    def close(self):
        self.write_frame(Chipset.ACK)
        self.transport.close()
        self.transport = None

    def write_frame(self, frame):
        self.transport.write(frame)
        
    def read_frame(self, timeout):
        return self.transport.read(timeout)
        
    def command(self, cmd_code, cmd_data=None, timeout=100):
        """Send a chip command and return the chip response."""
        cmd_name = self.CMD.get(cmd_code, "PN53x 0x{0:02X}".format(cmd_code))
        log.debug("{0} command with timeout {1} ms".format(cmd_name, timeout))
        
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

        try:
            self.write_frame(frame)
            frame = self.read_frame(timeout=100)
        except IOError as error:
            log.error("timeout while waiting for ack")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        
        if frame[0:3] != Chipset.SOF:
            log.error("received invalid start of frame")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if frame[0:len(Chipset.ACK)] != Chipset.ACK:
            log.warning("missing ack frame from pn53x")

        while frame == Chipset.ACK:
            # transport raises IOError if timed out
            try:
                frame = self.read_frame(timeout)
            except IOError as error:
                if error.errno == errno.ETIMEDOUT:
                    self.write_frame(Chipset.ACK)
                raise error
        
        if not frame.startswith(Chipset.SOF):
            log.debug("invalid start of frame")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if frame[3] == 255 and frame[4] == 255:
            # extended information frame
            if sum(frame[5:8]) & 0xFF != 0:
                log.error("extended frame lenght checksum error")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            LEN, TFI, PD0 = frame[5]*256+frame[6], frame[8], frame[9]
        else:
            # normal information frame 
            if sum(frame[3:5]) & 0xFF != 0:
                log.error("standard frame lenght checksum error")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            LEN, TFI, PD0 = frame[3], frame[5], frame[6]

        if not TFI == 0xd5:
            if TFI == 0x7f: raise ChipsetError(0x7f)
            log.error("invalid frame identifier value")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if not PD0 == cmd_code + 1:
            log.error("response code does not match command code")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
    
        if frame[3] == 255 and frame[4] == 255:
            # extended information frame
            if sum(frame[8:8+LEN+1]) % 256 == 0:
                return frame[10:8+LEN]
        else:
            # normal information frame 
            if sum(frame[5:5+LEN+1]) % 256 == 0:
                return frame[7:5+LEN]
            
        log.error("frame payload checksum error")
        raise IOError(errno.EIO, os.strerror(errno.EIO))

    def diagnose(self, test, test_data=None):
        if test == "line":
            if test_data is None: test_data = "nfcpy"
            data = self.command(0x00, chr(0) + test_data)
            if data is None: raise ChipsetError(data)
            return data[0] == 0 and data[1:] == test_data
        raise ValueError("unknown diagnose test {0!r}".format(test))

    def get_firmware_version(self):
        data = self.command(0x02)
        if len(data) == 2:
            ic, ver, rev, support = 0x31, data[0], data[1], 0x00
        else: ic, ver, rev, support = data
        return ic, ver, rev, support

    def get_general_status(self):
        return self.command(0x04)

    def read_register(self, addr):
        if type(addr) is int: addr = [addr]
        data = ''.join([struct.pack(">H", x) for x in addr])
        data = self.command(0x06, data, timeout=250)
        if data is None or data[0] != 0:
            raise ChipsetError(data)
        return data[1:]

    def pn531_set_parameters(self, use_nad=False, use_did=False,
                             auto_atr_res=True, use_irq=False,
                             auto_rats=True):
        flags = (int(use_nad) | int(use_did)<<1 | int(auto_atr_res)<<2 |
                 int(use_irq)<<3 | int(auto_rats)<<4)
        self.command(0x12, chr(flags))
        
    def pn532_set_parameters(self, use_nad=False, use_did=False,
                             auto_atr_res=True, use_irq=False,
                             auto_rats=True, iso_14443_picc=True,
                             short_host_frame=False):
        flags = (int(use_nad) | int(use_did)<<1 | int(auto_atr_res)<<2 |
                 int(use_irq)<<3 | int(auto_rats)<<4 |
                 int(iso_14443_picc)<<5 | int(short_host_frame)<<6)
        self.command(0x12, chr(flags))
        
    def pn533_set_parameters(self, use_nad=False, use_did=False,
                             auto_atr_res=True, tda_powered=False,
                             auto_rats=True, secure=False):
        flags = (int(use_nad) | int(use_did)<<1 | int(auto_atr_res)<<2 |
                 int(tda_powered)<<3 | int(auto_rats)<<4 | int(secure)<<5)
        self.command(0x12, chr(flags))

    def pn531_sam_configuration(self, mode="normal", timeout=0):
        mode = ("normal", "virtual", "wired", "dual").index(mode) + 1
        self.command(0x14, chr(mode) + chr(timeout))

    def pn532_sam_configuration(self, mode="normal", timeout=0, irq=False):
        mode = ("normal", "virtual", "wired", "dual").index(mode) + 1
        self.command(0x14, chr(mode) + chr(timeout) + chr(int(irq)))

    def rf_configuration(self, cfg_item, cfg_data):
        self.command(0x32, bytearray([cfg_item]) + bytearray(cfg_data))

    def in_list_passive_target(self, brm, initiator_data):
        brm = ("106A", "212F", "424F", "106B", "106J").index(brm)
        data = chr(1) + chr(brm) + initiator_data
        data = self.command(0x4A, data, timeout=1000)
        return data[2:] if data and data[0] == 1 else None
            
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

        data = chr(mode) + chr(baud) + chr(next) \
            + passive_initiator_data + nfcid3 + general_bytes
        
        data = self.command(0x56, data, timeout=1000)
        if data is None or data[0] != 0:
            raise ChipsetError(data)
        return data[2:]
    
    def in_data_exchange(self, data, timeout, more=False):
        data = self.command(0x40, chr(int(more)<<6 | 0x01) + data, timeout)
        if data is None or data[0] & 0x3f != 0:
            raise ChipsetError(data[0] & 0x3f if data else None)
        return data[1:], bool(data[0] & 0x40)
    
    def in_communicate_thru(self, data, timeout):
        data = self.command(0x42, data, timeout)
        if data is None or data[0] != 0:
            raise ChipsetError(data)
        return data[1:]

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
        data = self.command(0x86, None, timeout)
        if data is None or data[0] & 0x3f != 0:
            raise ChipsetError(data[0] & 0x3f if data else None)
        return data[1:], bool(data[0] & 0x40)

    def tg_set_data(self, data, timeout):
        data = self.command(0x8E, data, timeout)
        if data is None or data[0] != 0:
            raise ChipsetError(data)

    def tg_set_meta_data(self, data, timeout):
        data = self.command(0x94, data, timeout)
        if data is None or data[0] != 0:
            raise ChipsetError(data)

class Device(nfc.dev.Device):
    def __init__(self, chipset):
        self.chipset = chipset
        
        # perform a communication line test
        if self.chipset.diagnose("line", "nfcpy") is not True:
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        
        self._vendor_name = "NXP"
        self._device_name = self.chipset.ic

        RWT_WTX = {'PN531': (14, 7), "PN532": (14, 7), "PN533": (8, 1)}
        rwt, wtx = RWT_WTX[self.chipset.ic]

        # set ATR_RES timeout: 102.4 ms, non-DEP: 51.2 ms)
        atr_res_to = 11 # T = 100 * 2^(x-1) µs
        non_dep_to = 10 # T = 100 * 2^(x-1) µs
        log.debug("ATR_RES timeout: {0:7.1f} ms".format(0.1*2**(atr_res_to-1)))
        log.debug("non-DEP timeout: {0:7.1f} ms".format(0.1*2**(non_dep_to-1)))
        atr_res_to = chr(atr_res_to); non_dep_to = chr(non_dep_to)
        self.chipset.rf_configuration(0x02, chr(11) + atr_res_to + non_dep_to)
        
        # retries for ATR_REQ, PSL_REQ, target activation
        log.debug("set retries: ATR_REQ=2 PSL_REQ=1 PassiveTarget=3")
        self.chipset.rf_configuration(0x05, "\x02\x01\x03")

    def close(self):
        try:
            self.chipset.rf_configuration(0x01, "\x00") # RF off
            self.chipset.close()
        except (ChipsetError, IOError):
            pass

    def sense(self, targets, gbi=None):
        if targets is None and gbi is not None:
            return self.sense_dep(gbi)
        
        for tg in targets:
            if type(tg) == nfc.clf.TTA:
                target = self.sense_tta()
                if (target and
                    (tg.cfg is None or target.cfg.startswith(tg.cfg)) and
                    (tg.uid is None or target.uid.startswith(tg.uid))):
                    break
            elif type(tg) == nfc.clf.TTB:
                target = self.sense_ttb()
                if target:
                    pass
            elif type(tg) == nfc.clf.TTF:
                br, sc, rc = tg.br, tg.sys, 0
                if sc is None: sc, rc = bytearray('\xFF\xFF'), 1
                target = self.sense_ttf(br, sc, rc)
                if (target and
                    (tg.sys is None or target.sys == tg.sys) and
                    (tg.idm is None or target.idm.startswith(tg.idm)) and
                    (tg.pmm is None or target.pmm.startswith(tg.pmm))):
                    break
        else:
            self.chipset.rf_configuration(0x01, "\x00") # RF-OFF
            return None

        self.exchange = self.send_cmd_recv_rsp
        return target

    def sense_tta(self):
        log.debug("polling for NFC-A technology")

        rsp = self.chipset.in_list_passive_target("106A", "")
        if rsp is not None:
            log.debug("found NFC-A target @ 106 kbps")
            cfg = rsp[1::-1] + rsp[2:3]
            uid = rsp[4:4+rsp[3]]
            ats = rsp[4+rsp[3]:]
            return nfc.clf.TTA(br=106, cfg=cfg, uid=uid, ats=ats)
        
        if self.chipset.ic != "PN531":
            rsp = self.chipset.in_list_passive_target("106J", "")
            if rsp is not None:
                log.debug("found NFC-A TT1 target @ 106 kbps")
                return nfc.clf.TTA(br=106, cfg=rsp[1::-1], uid=rsp[2:])

    def sense_ttb(self):
        return None
    
    def sense_ttf(self, br, sc, rc):
        poll_cmd = "00{sc[0]:02x}{sc[1]:02x}{rc:02x}03".format(sc=sc, rc=rc)
        log.debug("poll NFC-F {0}".format(poll_cmd))
        poll_cmd = bytearray(poll_cmd.decode("hex"))

        rsp = self.chipset.in_list_passive_target(str(br)+'F', poll_cmd)
        if rsp  and len(rsp) >= 18:
            if len(rsp) == 18: rsp += "\xff\xff"
            log.debug("found NFC-F target @ {0} kbps".format(br))
            return nfc.clf.TTF(br, rsp[2:10], rsp[10:18], rsp[18:20])
    
    def sense_dep(self, general_bytes):
        log.debug("polling for a p2p target")
        self.chipset.rf_configuration(0x01, "\x00")

        pollrq = "\x00\xFF\xFF\x00\x03"
        nfcid3 = "\x01\xfe" + os.urandom(8)

        for mode, speed in (("passive", "424"), ("active", "424")):
            try:
                rsp = self.chipset.in_jump_for_dep(
                    mode, speed, pollrq, nfcid3, general_bytes)
                log.info("activated a p2p target in {0} kbps {1} mode"
                         .format(speed, mode))
                break
            except ChipsetError as error:
                # errno 0x01/0x0A are passive/active mode timeouts
                if not error.errno in (0x01, 0x0A):
                    log.warning(error)
                    raise nfc.clf.TransmissionError(str(error))
            except IOError as error:
                log.error(error)
                raise error
        else:
            return None
        
        log.debug("ATR_RES(nfcid3={0} did={1:02x} bs={2:02x} "
                  "br={3:02x} to={4:02x} pp={5:02x} gb={6})"
                  .format(str(rsp[0:10]).encode("hex"),
                          rsp[10], rsp[11], rsp[12], rsp[13],
                          rsp[14], str(rsp[15:]).encode("hex")))
        
        self.exchange = self.send_cmd_recv_rsp
        return rsp[15:]

    def listen_dep(self, target, timeout):
        assert type(target) is nfc.clf.DEP
        
        timeout_msec = int(timeout * 1000)
        log.debug("listen_dep for {0} msec".format(timeout_msec))
        
        # nfca_params: SENS_RES + UID + SEL_RES
        # SENS_RES is set to be independent of byte order
        nfca_params = "\x01\x01" + os.urandom(3) + "\x40"
        nfca_params = bytearray(nfca_params)
        
        # nfcf_params: IDM + PMM + SYS
        nfcf_params = "\x01\xFE" + os.urandom(6) + 8 * "\x00" + "\xFF\xFF"
        nfcf_params = bytearray(nfcf_params)
        
        nfcid3t = nfcf_params[0:8] + "\x00\x00"

        try:
            self.chipset.set_parameters(auto_atr_res=True)
            data = self.chipset.tg_init_as_target(
                "DEP", nfca_params, nfcf_params, nfcid3t,
                target.gb, timeout=timeout_msec)
        except IOError as error:
            if error.errno == errno.ETIMEDOUT:
                log.debug(error)
                return None
            else:
                log.warning(error)
                raise error

        speed = (106, 212, 424)[(data[0]>>4) & 0x07]
        cmode = ("passive", "active", "passive")[data[0] & 0x03]
        log.info("activated as target in {0} kbps {1} mode"
                 .format(speed, cmode))
        
        target.br = speed
        target.gb = data[18:]

        try:
            recv_data, more = self.chipset.tg_get_data(timeout=1000)
            while more:
                data, more = self.chipset.tg_get_data(timeout_msec)
                recv_data += data
        except (ChipsetError, IOError) as error:
            log.warning(error)
            return None
        
        self.exchange = self.send_rsp_recv_cmd
        return (target, recv_data)

    def send_cmd_recv_rsp(self, send_data, timeout):
        non_dep_to, timeout = timeout_to_index(timeout)
        self.chipset.rf_configuration(0x02, bytearray([11, 11, non_dep_to]))
        self.chipset.rf_configuration(0x04, bytearray([3]))
        
        msec = min(100 + 3 * int(timeout * 1000), 2550)
        miu = self.chipset.max_packet_data_size - 2

        try:
            for offset in range(0, len(send_data), miu):
                data = send_data[offset:offset+miu]
                more = len(send_data) > offset + miu
                data, more = self.chipset.in_data_exchange(data, msec, more)
            recv_data = data
            while more:
                data, more = self.chipset.in_data_exchange('', msec)
                recv_data += data
            return recv_data
        except ChipsetError as error:
            if error.errno == 1:
                log.debug(error)
                raise nfc.clf.TimeoutError
            else:
                log.warning(error)
                raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            if error.errno == errno.ETIMEDOUT:
                log.debug(error)
                raise nfc.clf.TimeoutError("send_cmd_recv_rsp")
            else:
                log.error(error)
                raise error # Transport broken -> give up

    def send_rsp_recv_cmd(self, send_data, timeout):
        timeout_msec = int(timeout * 1000)
        miu = self.chipset.max_packet_data_size - 2
        try:
            offset = 0
            for offset in range(0, len(send_data), miu)[0:-1]:
                data = send_data[offset:offset+miu]
                self.chipset.tg_set_meta_data(data, timeout_msec)
            self.chipset.tg_set_data(send_data[offset:], timeout_msec)
            recv_data, more = self.chipset.tg_get_data(timeout_msec)
            while more:
                data, more = self.chipset.tg_get_data(timeout_msec)
                recv_data += data
            return recv_data
        except ChipsetError as error:
            if error.errno == 0x29:
                log.debug(error)
                return None # RF-OFF detected
            else:
                log.warning(error)
                raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            if error.errno == errno.ETIMEDOUT:
                log.debug(error)
                raise nfc.clf.TimeoutError("send_rsp_recv_cmd")
            else:
                log.error(error)
                raise error # Transport broken

    @property
    def capabilities(self):
        return {'ISO-DEP': True, 'NFC-DEP': True}

def init(transport):
    if transport.TYPE == "TTY":
        # send wakeup signal to quit low power battery mode (PN532 1.6)
        transport.write(bytearray([0x55, 0x55] + 14 * [0x00]))

    # write ack to perform a soft reset
    # raises IOError(EACCES) if we're second (on USB)
    transport.write(Chipset.ACK)
    
    chipset = Chipset(transport)
    device = Device(chipset)
    
    if chipset.ic == "PN533":
        # PN533 bug: usb manufacturer and product strings disappear
        # from usb configuration after first use in p2p mode. Thus
        # we'll read it directly from the EEPROM (but if no EEPROM
        # is installed we'll have to set fixed strings).
        try:
            eeprom = bytearray()
            for addr in range(0xA000, 0xA100, 16):
                eeprom += chipset.read_register(range(addr, addr+16))
            index = 0
            while index < len(eeprom) and eeprom[index] != 0xFF:
                tlv_tag, tlv_len = eeprom[index], eeprom[index+1]
                tlv_data = eeprom[index+2:index+2+tlv_len]
                if tlv_tag == 3:
                    device._device_name = tlv_data[2:].decode("utf-16")
                if tlv_tag == 4:
                    device._vendor_name = tlv_data[2:].decode("utf-16")
                index += 2 + tlv_len
        except nfc.dev.pn53x.ChipsetError:
            vendor_name = "NXP"
            device_name = "PN533"
    else:
        vendor_name = transport.manufacturer_name
        if vendor_name:
            device._vendor_name = vendor_name
        device_name = transport.product_name
        if device_name:
            device._device_name = device_name

    return device
