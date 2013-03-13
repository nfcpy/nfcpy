# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2013 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# rcs380.py - Sony RC-S380 NFC reader
#

import logging
log = logging.getLogger(__name__)

from transport import usb as usb_transport
from nfc.clf import ProtocolError, TransmissionError, TimeoutError

import struct
import time

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.debug("{func}({args})".format(func=func.__name__, args=_args))
        return func(*args, **kwargs)
    return traced_func

class Frame():
    def __init__(self, data):
        if data[0:3] == bytearray("\x00\x00\xff"):
            frame = bytearray(data)
            if frame == bytearray("\x00\x00\xff\x00\xff\x00"):
                self._type = "ack"
            elif frame == bytearray("\x00\x00\xFF\xFF\xFF"):
                self._type = "err"
            elif frame[3:5] == bytearray("\xff\xff"):
                self._type = "data"
            if self.type == "data":
                length = struct.unpack("<H", str(frame[5:7]))[0]
                self._data = frame[8:8+length]
        else:
            frame  = bytearray([0, 0, 255, 255, 255])
            frame += bytearray(struct.pack("<H", len(data)))
            frame += bytearray(struct.pack("B", (256 - sum(frame[5:7])) % 256))
            frame += bytearray(data)
            frame += bytearray([(256 - sum(frame[8:])) % 256, 0])
            self._frame = frame

    def __str__(self):
        return str(self._frame)
    
    @property
    def type(self):
        return self._type

    @property
    def data(self):
        return self._data

class CommunicationError:
    err2str = {0x00000000: "NO_ERROR",
               0x00000001: "PROTOCOL_ERROR",
               0x00000002: "PARITY_ERROR",
               0x00000004: "CRC_ERROR",
               0x00000008: "COLLISION_ERROR",
               0x00000010: "OVERFLOW_ERROR",
               0x00000040: "TEMPERATURE_ERROR",
               0x00000080: "RECEIVE_TIMEOUT_ERROR",
               0x00000100: "CRYPTO1_ERROR",
               0x00000200: "RFCA_ERROR",
               0x00000400: "RF_OFF_ERROR",
               0x00000800: "TRANSMIT_TIMEOUT_ERROR",
               0x80000000: "RECEIVE_LENGTH_ERROR"
               }
    str2err = dict([(v, k) for k, v in err2str.iteritems()])
    
    def __init__(self, status_bytes):
        self.errno = struct.unpack('<L', str(status_bytes))[0]

    def __eq__(self, strerr):
        return self.errno & CommunicationError.str2err[strerr]

    def __ne__(self, strerr):
        return not self.__eq__(strerr)

    def __str__(self):
        return CommunicationError.err2str.get(
            self.errno, "{0:08x}".format(self.errno))
    
class StatusError:
    err2str = ("SUCCESS", "PARAMETER_ERROR", "PB_ERROR", "RFCA_ERROR",
               "TEMPERATURE_ERROR", "PWD_ERROR", "RECEIVE_ERROR",
               "COMMANDTYPE_ERROR")

    def __init__(self, status):
        self.errno = status

    def __str__(self):
        try:
            return StatusError.err2str[self.errno]
        except IndexError:
            return "UNKNOWN STATUS ERROR {0:02x}".format(self.errno)
    
class Chipset():
    def __init__(self, transport):
        self.transport = transport
        self.set_command_type(1)
        self.get_firmware_version()
        self.get_pd_data_version()
        self.switch_rf("off")

    #@trace
    def send_command(self, cmd_code, cmd_data, timeout):
        data = bytearray([0xD6, cmd_code]) + bytearray(cmd_data)
        self.transport.write(str(Frame(data)))
        if Frame(self.transport.read(timeout=100)).type == "ack":
            data = Frame(self.transport.read(timeout)).data
            if data[0] == 0xD7 and data[1] == cmd_code + 1:
                return data[2:]

    @trace
    def in_set_rf(self, comm_type):
        in_comm_type = {"212F": (1, 1, 15, 1), "424F": (1, 2, 15, 2),
                        "106A": (2, 3, 15, 3), "212A": (0, 4,  0, 4),
                        "424A": (0, 5,  0, 5), "106B": (3, 7, 15, 7),
                        "212B": (0, 8,  0, 8), "424B": (0, 9,  0, 9)
                        }
        comm_type = in_comm_type[comm_type]
        rsp_data = self.send_command(0x00, comm_type, 100)
        if rsp_data[0] != 0:
            log.error("in_set_rf error {0:x}".format(rsp_data[0]))
        
    @trace
    def in_set_protocol(self, data):
        data = self.send_command(0x02, data, 100)
        if data[0] != 0:
            log.error("in_set_protocol error {0:x}".format(data[0]))
            raise StatusError(data[0])
        
    @trace
    def in_comm_rf(self, data, timeout):
        to = struct.pack("<H", timeout*10)
        data = self.send_command(0x04, to + str(data), timeout+500)
        if tuple(data[0:4]) != (0, 0, 0, 0):
            error = CommunicationError(data[0:4])
            log.debug("in_comm_rf error {0}".format(error))
            raise error
        return data[5:]
        
    @trace
    def switch_rf(self, switch):
        switch = ("off", "on").index(switch)
        data = self.send_command(0x06, [switch], 100)
        if data[0] != 0:
            log.error("switch_rf error {0:x}".format(data[0]))
        
    @trace
    def tg_set_rf(self, comm_type):
        tg_comm_type = {"106A": (8, 11), "212F": (8, 12), "424F": (8, 13),
                        "212A": (8, 14), "424A": (8, 15)}
        
        comm_type = tg_comm_type[comm_type]
        rsp_data = self.send_command(0x40, comm_type, 100)
        if rsp_data[0] != 0:
            log.error("tg_set_rf error {0:x}".format(rsp_data[0]))
        
    @trace
    def tg_set_protocol(self, data):
        rsp_data = self.send_command(0x42, data, 100)
        if rsp_data[0] != 0:
            log.error("tg_set_protocol error {0:x}".format(rsp_data[0]))
        
    @trace
    def tg_set_auto(self, data):
        rsp_data = self.send_command(0x44, data, 100)
        if rsp_data[0] != 0:
            log.error("tg_set_auto error {0:x}".format(rsp_data[0]))
        
    #@trace
    def tg_comm_rf(self, guard_time, send_timeout=0xFFFF, mdaa=False,
                   nfca_params='', nfcf_params='', mf_halted=False,
                   arae=False, recv_timeout=0xFFFF, transmit_data=''):
        """Send *transmit_data* as the RF response packet and return
        an RF command packet. The response packet is send not before
        *guard_time* and not after *send_timeout* elapsed in relation
        to the last received command packet.
        """
        data = struct.pack("<HH?6s18s??H", guard_time, send_timeout, mdaa,
                           nfca_params, nfcf_params, mf_halted, arae,
                           recv_timeout) + str(transmit_data)
        data = self.send_command(0x48, data, recv_timeout+500)
        if tuple(data[3:7]) != (0, 0, 0, 0):
            log.debug("tg_comm_rf status 0x{0}".format(
                    str(data[3:7][::-1]).encode("hex")))
        return data
        
    @trace
    def get_firmware_version(self):
        rsp_data = self.send_command(0x20, [], 100)
        log.debug("firmware version {1:x}.{0:02x}".format(*rsp_data))
        rsp_data = self.send_command(0x20, [0x80], 100)
        log.debug("boot version {1:x}.{0:02x}".format(*rsp_data))
        
    @trace
    def get_pd_data_version(self):
        rsp_data = self.send_command(0x22, [], 100)
        log.debug("package data format {1:x}.{0:02x}".format(*rsp_data))

    @trace
    def get_command_type(self):
        rsp_data = self.send_command(0x28, [], 100)
        return struct.unpack(">Q", str(rsp_data[0:8]))
    
    @trace
    def set_command_type(self, command_type):
        rsp_data = self.send_command(0x2A, [command_type], 100)
        if rsp_data[0] != 0:
            log.error("set_command_type error {0:x}".format(rsp_data[0]))
    
class Device(object):
    def __init__(self, chipset):
        self.chipset = chipset
    
    def close(self):
        self.chipset.switch_rf("off")
        pass
    
    def poll(self, p2p_activation_data=None):
        self.tech = None
        for poll in (self.nfca_poll, self._poll_nfcb, self._poll_nfcf):
            target = poll()
            if target is not None:
                if target['type'] is not "DEP":
                    return target
                if p2p_activation_data is not None:
                    return self._poll_dep(p2p_activation_data)

    def nfca_poll(self):
        log.debug("polling for NFC-A technology")
        self.technology = None
        self.chipset.in_set_rf("106A")
        p = bytearray.fromhex("0006010002000300040005010600070708000900"+
                              "0a000b000c000e040f001000110012001306")
        self.chipset.in_set_protocol(p)
        
        try:
            sens_res = self.chipset.in_comm_rf("\x26", 30)
            log.debug("SENS_RES (ATQ) = " + str(sens_res).encode("hex"))
        except CommunicationError as error:
            self.chipset.switch_rf("off")
            if error == "RECEIVE_TIMEOUT_ERROR":
                return None
            else:
                raise error

        if sens_res[0] & 0x1F == 0 and sens_res[1] & 0x0F != 0b1100:
            pass
        
        if sens_res[1] & 0x0F == 0b1100:
            if not sens_res[0] & 0x1F == 0:
                raise ProtocolError("4.6.3.3")
            
            log.debug("NFC-A TT1 target @ 106 kbps")
            # set: add tt1 crc, check tt1 crc, all bits valid, rrdd = 60µs
            self.chipset.in_set_protocol("\x01\x02\x02\x02\x07\x08\x11\x02")
            rid_cmd = "\x78\x00\x00\x00\x00\x00\x00"
            rid_res = self.chipset.in_comm_rf(rid_cmd, 30)
            if not rid_res[0] & 0xF0 == 0x10:
                raise ProtocolError("8.6.2.1")
            self.tech = "nfcj"
            return {"type": "TT1", "UID": rid_res[2:]}

        else:
            if sens_res[0] & 0x1F == 0:
                raise ProtocolError("4.6.3.3")
            log.debug("type 2 tag platform")
            
        self.chipset.in_set_protocol("\x04\x01\x07\x08")

        nfcid1 = bytearray()
        for cascade_level in range(3):
            sel_cmd = ("\x93", "\x95", "\x97")[cascade_level]
            # SDD_REQ
            self.chipset.in_set_protocol("\x01\x00\x02\x00")
            sdd_res = self.chipset.in_comm_rf(sel_cmd + "\x20", 30)
            log.debug("SDD_RES = " + str(sdd_res).encode("hex"))
            # SDD_SEL
            self.chipset.in_set_protocol("\x01\x01\x02\x01")
            sel_res = self.chipset.in_comm_rf(sel_cmd + "\x70" + sdd_res, 30)
            log.debug("SEL_RES = " + str(sel_res).encode("hex"))
            # DONE ?
            nfcid1_complete = bool(sel_res[0] & 0b00000100 == 0)
            nfcid1 += sdd_res[0:4] if nfcid1_complete else sdd_res[1:4]
            if nfcid1_complete:
                log.debug("NFCID1 = " + str(nfcid1).encode("hex"))
                break

        if nfcid1_complete:
            log.debug("NFC-A target found at 106 kbps")
            self.tech = "nfca"        
            atq = sens_res[0] * 256 + sens_res[1]
            sak = sel_res[0]
            uid = nfcid1
            platform = ("TT2", "TT4", "DEP", "DEP/TT4")[(sak >> 5) & 0b11]
            log.debug("NFC-A configured for {0}".format(platform))
            if sak == 0b00000000:
                return {"type": "TT2", "ATQ": atq, "SAK": sak, "UID": uid}
            elif sak & 0b00100000:
                ats = self.chipset.in_comm_rf("\xE0\x80", 30)
                log.debug("ATS = " + str(ats).encode("hex"))
                return {"type": "TT4", "ATQ": atq, "SAK": sak, "UID": uid,
                        "ATS": ats}
            elif sak & 0b01000000:
                return {"type": "DEP", "ATQ": atq, "SAK": sak, "UID": uid}
        else:
            # no target found, shut off rf field
            self.chipset.switch_rf("off")

    def _poll_nfcb(self):
        log.debug("polling for NFC-B technology")
        self.technology = None
        self.chipset.in_set_rf("106B")
        p = bytearray.fromhex("0014010102010300040005000600070808000901"+
                              "0a010b010c010e040f001000110012001306")
        self.chipset.in_set_protocol(p)
        try:
            rsp = self.chipset.in_comm_rf("\x05\x00\x00", 30)
            print repr(rsp)
        except CommunicationError as error:
            if not error == "RECEIVE_TIMEOUT_ERROR":
                raise error
        self.chipset.switch_rf("off")
    
    def _poll_nfcf(self):
        log.debug("polling for NFC-F technology")
        self.technology = None
        
        p = bytearray.fromhex("0018 0101 0201 0301 0400 0500 0600" +
                              "0708 0800 0900 0a00 0b00 0c00 0e04" +
                              "0f00 1000 1100 1200 1306")

        poll_ffff = "\x06\x00\xFF\xFF\x00\x00"
        poll_12fc = "\x06\x00\x12\xFC\x00\x00"

        for br in ("424F", "212F"):
            self.chipset.in_set_rf(br)
            self.chipset.in_set_protocol(p)
            try:
                rsp = self.chipset.in_comm_rf("\x06\x00\xFF\xFF\x00\x00", 100)
                if (rsp[0], rsp[1]) != (0x12, 0x01): return None
            except CommunicationError as error:
                if error == "RECEIVE_TIMEOUT_ERROR": continue
                else: raise error

            if (rsp[2], rsp[3]) == (0x01, 0xfe):
                self.tech = "nfcf"
                self.chipset.in_set_protocol(bytearray.fromhex("0300"))
                return {"type": "DEP"}

            for poll_cmd in ("\x06\x00\x12\xFC\x01\x00",
                             "\x06\x00\xFF\xFF\x01\x00"):
                try:
                    rsp = self.chipset.in_comm_rf(poll_cmd, 100)
                    if (rsp[0], rsp[1]) != (0x14, 0x01): return None
                except CommunicationError as error:
                    if error == "RECEIVE_TIMEOUT_ERROR": continue
                    raise error
                else:
                    log.debug("NFC-F target at {0} kbps".format(br[0:3]))
                    idm, pmm, sys = rsp[2:10], rsp[10:18], rsp[18:20]
                    self.tech = "nfcf"
                    self.chipset.in_set_protocol(bytearray.fromhex("0300"))
                    return {"type": "TT3", "IDm": idm, "PMm": pmm, "SYS": sys}
        else:
            # no target found, shut down rf field
            self.chipset.in_set_protocol("\x03\x00")
            self.chipset.switch_rf("off")
            
    def _poll_dep(self, gb):
        def ATR(nfcid3, bs, br, pp, gb):
            atr = "\x00\xD4\x00" + nfcid3 + bytearray([0, bs, br, pp]) + gb
            atr[0] = len(atr)
            return atr
            
        log.debug("polling for NFC-DEP protocol")
        if self.tech == "nfcf":
            rsp = self.chipset.in_comm_rf("\x06\x00\xFF\xFF\x00\x00", 100)
            if (rsp[2], rsp[3]) == (0x01, 0xfe):
                nfcid3 = rsp[2:10] + "\x00\x00"
                frame = ATR(nfcid3, bs=0, br=0, pp=0b00110010, gb=gb)
                frame = self.chipset.in_comm_rf(frame, 1300)
                if not frame or frame[0] != len(frame) or frame[0] < 18:
                    log.error("no atr_rsp or atr_rsp length error")
                    return
                if tuple(frame[1:2]) == (0xD5, 0x01):
                    log.error("not an atr_rsp pdu type")
                    return
                if frame[3:11] != nfcid3[0:8]:
                    log.warning("wrong nfcid3 in atr_rsp")
                to, pp, gb = frame[16], frame[17], frame[18:]
                wt = to & 0x0f; rwt = 4096 / 13.56E6 * pow(2, wt)
                return {"type": "DEP", "rwt": rwt, "data": str(gb)}

    def listen(self, general_bytes, timeout):
        # timeout in seconds
        self.tech = None
        pass

    def listen_nfcf(self, idm, pmm, sc, br, timeout):
        self.tech = None
        self.chipset.tg_set_rf(br+"F")
        self.chipset.tg_set_protocol([0, 1, 1, 1, 2, 7])
        
        data = self.chipset.tg_comm_rf(1000, recv_timeout=int(timeout*1E3)+1)
        if data is None or tuple(data[3:7]) != (0, 0, 0, 0):
            return None
        
        tech = ("106A", "212F", "424F", "212A", "424A")
        log.debug("activated in {0}".format(tech[data[0]-11]))
        cmd = data[7:]

        if len(cmd) < 2 or cmd[0] != len(cmd):
            log.debug("nfc-f frame length error")
            return None

        if cmd[1] == 0xD4:
            log.debug("received an nfc-dep command")
            return None

        while cmd[0] == 6 and cmd[1] == 0:
            log.debug("rcvd SENSF_REQ " + str(cmd).encode("hex"))
            if tuple(cmd[2:4]) in [(255, 255), tuple(sc)]:
                if cmd[4] == 1:
                    rsp = idm + pmm + sc
                elif cmd[4] == 2:
                    protocol_features = ("\x00\x81", "\x00\x82")[br=="424"]
                    rsp = idm + pmm + protocol_features
                else:
                    rsp = idm + pmm
                rsp = bytearray([2 + len(rsp), 0x01]) + rsp
                log.debug("send SENSF_RES " + str(rsp).encode("hex"))
                tsn = cmd[5]
                data = self.chipset.tg_comm_rf(
                    2416 + tsn * 1208, 2416 + (tsn + 1) * 1208,
                    recv_timeout=3000, transmit_data=rsp)
                if data is None or tuple(data[3:7]) != (0, 0, 0, 0):
                    return None
                cmd = data[7:]
                if len(cmd) < 2 or cmd[0] != len(cmd) or cmd[1] == 0xD4:
                    return None
            else:
                log.debug("unmatched system code in SENSF_REQ command")
                return None

        self.tech = "nfcf"
        return cmd

    def transceive(self, data, timeout, check_crc=True):
        try:
            if self.tech == "nfca":
                return self.nfca_transceive(data, timeout, check_crc)
            if self.tech == "nfcj":
                return self.nfcj_transceive(data, timeout, check_crc)
            if self.tech == "nfcf":
                return self.nfcf_transceive(data, timeout, check_crc)
        except CommunicationError as error:
            log.debug("{0} transceive {1}".format(self.tech, error))
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise TimeoutError
            if error == "CRC_ERROR":
                raise TransmissionError
            raise DigitalProtocolError
        
    @trace
    def nfca_transceive(self, data, timeout, check_crc):
        self.chipset.in_set_protocol("\x02" + chr(check_crc))
        return self.chipset.in_comm_rf(data, int(timeout*1E3)+1)

    @trace
    def nfcj_transceive(self, data, timeout, check_crc):
        return self.chipset.in_comm_rf(data, int(timeout*1E3)+1)

    @trace
    def nfcf_transceive(self, data, timeout, check_crc):
        return self.chipset.in_comm_rf(data, int(timeout*1E3)+1)

    @trace
    def send_command(self, data):
        if self.tech == "nfca":
            return self._nfca_send_command(data)
        if self.tech == "nfcf":
            return self._nfcf_send_command(data)
        raise NotImplemented

    @trace
    def recv_response(self, timeout):
        if self.tech == "nfca":
            return self._nfca_recv_response(int(timeout*1E3)+1)
        if self.tech == "nfcf":
            return self._nfcf_recv_response(int(timeout*1E3)+1)
        raise NotImplemented

    @trace
    def recv_command(self, timeout):
        if self.tech == "nfcf":
            return self._nfcf_recv_command(int(timeout*1E3)+1)
        raise NotImplemented

    @trace
    def send_response(self, data):
        if self.tech == "nfcf":
            return self._nfcf_send_response(data)
        raise NotImplemented
    
    def _nfca_send_command(self, data):
        self._nfca_cmd = data
        return True

    def _nfca_recv_response(self, timeout):
        try:
            return self.chipset.in_comm_rf(self._nfca_cmd, timeout=timeout)
        except CommunicationError as error:
            if not error == "RECEIVE_TIMEOUT_ERROR":
                log.error("nfca_recv_response error {0}".format(error))

    def _nfcf_send_command(self, data):
        try:
            self.chipset.in_comm_rf(data, timeout=0)
            return True
        except CommunicationError as error:
            log.error("nfcf_send_command error {0}".format(error))

    def _nfcf_recv_response(self, timeout):
        try:
            return self.chipset.in_comm_rf(data="", timeout=timeout)
        except CommunicationError as error:
            if not error == "RECEIVE_TIMEOUT_ERROR":
                log.error("nfcf_recv_response error {0}".format(error))

    def _nfcf_recv_command(self, timeout):
        data = self.chipset.tg_comm_rf(200, recv_timeout=timeout)
        return data[7:] if tuple(data[3:7]) == (0, 0, 0, 0) else None

    def _nfcf_send_response(self, data):
        data = self.chipset.tg_comm_rf(3624, recv_timeout=0, transmit_data=data)
        return True if tuple(data[3:7]) == (0, 0, 0, 0) else False

    def dep_get_data(self, timeout):
        pass

    def dep_set_data(self, data, timeout):
        pass

def init(device, transport):
    if transport == "usb":
        transport = usb_transport(device)
        chipset = Chipset(transport)
        product = transport.dh.getString(device.iProduct, 100)
        device = Device(chipset)
        device._vendor = "Sony"
        device._product = product
        return device

