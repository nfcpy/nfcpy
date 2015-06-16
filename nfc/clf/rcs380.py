# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import os
import time
import errno
import struct
import operator
from binascii import hexlify

import nfc.clf
from . import device

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.debug("{func}({args})".format(func=func.__name__, args=_args))
        data = func(*args, **kwargs)
        #log.debug("{0} returns {1}".format(func.__name__, repr(data)))
        return data
    return traced_func

class Frame():
    def __init__(self, data):
        self._data = None
        self._frame = None

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
        return self.__class__.__name__ + ' ' + CommunicationError.err2str.get(
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
    
class Chipset(object):
    ACK = bytearray.fromhex('0000FF00FF00')
    CMD = {
        # RF Communication
        0x00: "InSetRF",
        0x02: "InSetProtocol",
        0x04: "InCommRF",
        0x06: "SwitchRF",
        0x10: "MaintainFlash",
        0x12: "ResetDevice",
        0x20: "GetFirmwareVersion",
        0x22: "GetPDDataVersion",
        0x24: "GetProperty",
        0x26: "InGetProtocol",
        0x28: "GetCommandType",
        0x2A: "SetCommandType",
        0x30: "InSetRCT",
        0x32: "InGetRCT",
        0x34: "GetPDData",
        0x36: "ReadRegister",
        0x40: "TgSetRF",
        0x42: "TgSetProtocol",
        0x44: "TgSetAuto",
        0x46: "TgSetRFOff",
        0x48: "TgCommRF",
        0x50: "TgGetProtocol",
        0x60: "TgSetRCT",
        0x62: "TgGetRCT",
        0xF0: "Diagnose",
    }

    def __init__(self, transport, logger):
        self.transport = transport
        self.log = logger
        
        # write ack to perform a soft reset
        # raises IOError(EACCES) if we're second
        self.transport.write(Chipset.ACK)
        
        # do some basic initialization and deactivate rf
        self.set_command_type(1)
        self.get_firmware_version()
        self.get_pd_data_version()
        self.switch_rf("off")

    def close(self):
        self.switch_rf('off')
        self.transport.write(Chipset.ACK)
        self.transport.close()
        self.transport = None

    def send_command(self, cmd_code, cmd_data, timeout):
        cmd_data = bytearray(cmd_data)
        log.log(logging.DEBUG-1, self.CMD[cmd_code]+" "+hexlify(cmd_data))
        if self.transport is not None:
            cmd = bytearray([0xD6, cmd_code]) + cmd_data
            self.transport.write(str(Frame(cmd)))
            if Frame(self.transport.read(timeout=100)).type == "ack":
                rsp = Frame(self.transport.read(timeout)).data
                if rsp and rsp[0] == 0xD7 and rsp[1] == cmd_code + 1:
                    return rsp[2:]
        else: log.debug("transport closed in send_command")
                
    def in_set_rf(self, comm_type):
        in_comm_type = {"212F": (1, 1, 15, 1), "424F": (1, 2, 15, 2),
                        "106A": (2, 3, 15, 3), "212A": (4, 4, 15, 4),
                        "424A": (5, 5, 15, 5), "106B": (3, 7, 15, 7),
                        "212B": (0, 8,  0, 8), "424B": (0, 9,  0, 9)
                        }
        comm_type = in_comm_type[comm_type]
        data = self.send_command(0x00, comm_type, 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    in_set_protocol_defaults = bytearray.fromhex(
        "0018 0101 0201 0300 0400 0500 0600 0708 0800 0900"
        "0A00 0B00 0C00 0E04 0F00 1000 1100 1200 1306")

    def in_set_protocol(self, data=None, **kwargs):
        data = bytearray() if data is None else bytearray(data)
        KEYS = ("initial_guard_time", "add_crc", "check_crc", "multi_card",
                "add_parity", "check_parity", "bitwise_anticoll",
                "last_byte_bit_count", "mifare_crypto", "add_sof",
                "check_sof", "add_eof", "check_eof", "rfu", "deaf_time",
                "continuous_receive_mode", "min_len_for_crm",
                "type_1_tag_rrdd", "rfca", "guard_time")
        for key, value in kwargs.iteritems():
            data.extend(bytearray([KEYS.index(key), int(value)]))
        data = self.send_command(0x02, data, 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    def in_comm_rf(self, data, timeout):
        to = struct.pack("<H", timeout*10) if timeout <= 6553 else '\xFF\xFF'
        data = self.send_command(0x04, to + str(data), timeout+500)
        if data and tuple(data[0:4]) != (0, 0, 0, 0):
            raise CommunicationError(data[0:4])
        return data[5:] if data else None
        
    def switch_rf(self, switch):
        switch = ("off", "on").index(switch)
        data = self.send_command(0x06, [switch], 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def tg_set_rf(self, comm_type):
        tg_comm_type = {"106A": (8, 11), "212F": (8, 12), "424F": (8, 13),
                        "212A": (8, 14), "424A": (8, 15)}
        
        comm_type = tg_comm_type[comm_type]
        data = self.send_command(0x40, comm_type, 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def tg_set_protocol(self, data):
        data = self.send_command(0x42, bytearray(data), 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def tg_set_auto(self, data):
        data = self.send_command(0x44, data, 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def tg_comm_rf(self, guard_time=0, send_timeout=0xFFFF,
                   mdaa=False, nfca_params='', nfcf_params='',
                   mf_halted=False, arae=False, recv_timeout=0,
                   transmit_data=None):
        """Send a response packet and receive next command. If
        *transmit_data* is None skip sending. If *recv_timeout* is
        zero skip receiving. Data is send only between *guard_time*
        and *send_timeout*, measured from the end of the last received
        data.  If *mdaa* is True reply to Type A and Type F activation
        commands with data from *nfca_params* and *nfcf_params*.
        """
        data = struct.pack(
            "<HH?6s18s??H", guard_time, send_timeout, mdaa, nfca_params,
            nfcf_params, mf_halted, arae, recv_timeout)
        if transmit_data:
            data = data + str(transmit_data)
            
        data = self.send_command(0x48, data, recv_timeout+500)
        
        if data and tuple(data[3:7]) != (0, 0, 0, 0):
            raise CommunicationError(data[3:7])
        
        return data

    @trace
    def reset_device(self, startup_delay=0):
        self.send_command(0x12, struct.pack("<H", startup_delay), 100)
        self.transport.write(Chipset.ACK)
        time.sleep(float(startup_delay + 500)/1000)

    @trace
    def get_firmware_version(self, option=None):
        assert option in (None, 0x60, 0x61, 0x80)
        data = self.send_command(0x20, [option] if option else [], 100)
        log.debug("firmware version {1:x}.{0:02x}".format(*data))
        return data
        
    @trace
    def get_pd_data_version(self):
        data = self.send_command(0x22, [], 100)
        log.debug("package data format {1:x}.{0:02x}".format(*data))

    @trace
    def get_command_type(self):
        data = self.send_command(0x28, [], 100)
        return struct.unpack(">Q", str(data[0:8]))
    
    @trace
    def set_command_type(self, command_type):
        data = self.send_command(0x2A, [command_type], 100)
        if data and data[0] != 0:
            raise StatusError(data[0])

class Device(device.Device):
    def __init__(self, chipset, logger):
        self.chipset = chipset
        self.log = logger

        minor, major = self.chipset.get_firmware_version()
        self._chipset_name = "NFC Port-100 v{0:x}.{1:02x}".format(major, minor)
    
    def close(self):
        self.chipset.close()

    def mute(self):
        self.chipset.switch_rf("off")

    def sense_tta(self, target):
        log.debug("polling for NFC-A technology")
        
        if target.brty not in ("106A", "212A", "424A"):
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=6, add_crc=0,
                                     check_crc=0, check_parity=1,
                                     last_byte_bit_count=7)
        try:
            sens_res = self.chipset.in_comm_rf("\x26", 30)
            if len(sens_res) != 2: return None
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR": log.debug(error)
            return None
        
        log.debug("rcvd SENS_RES " + hexlify(sens_res))

        if sens_res[0] & 0x1F == 0:
            log.debug("type 1 tag target found")
            self.chipset.in_set_protocol(last_byte_bit_count=8, add_crc=2,
                                         check_crc=2, type_1_tag_rrdd=2)
            target = nfc.clf.TTA(target.bitrate, sens_res=sens_res)
            if sens_res[1] & 0x0F == 0b1100:
                rid_cmd = bytearray.fromhex("78 0000 00000000")
                log.debug("send RID_CMD " + hexlify(rid_cmd))
                try:
                    target.rid_res = self.chipset.in_comm_rf(rid_cmd, 30)
                except CommunicationError as error:
                    log.debug(error)
                    return None
            return target

        # other than type 1 tag
        try:
            self.chipset.in_set_protocol(last_byte_bit_count=8, add_parity=1)
            if target.sel_req:
                uid = target.sel_req
                if len(uid) > 4: uid = "\x88" + uid
                if len(uid) > 8: uid = uid[0:4] + "\x88" + uid[4:]
                self.chipset.in_set_protocol(add_crc=1, check_crc=1)
                for i, sel_cmd in zip(range(0,len(uid),4),"\x93\x95\x97"):
                    sel_req = sel_cmd + "\x70" + uid[i:i+4]
                    sel_req.append(reduce(operator.xor, sel_req[2:6])) # BCC
                    log.debug("send SEL_REQ " + hexlify(sel_req))
                    sel_res = self.chipset.in_comm_rf(sel_req, 30)
                    log.debug("rcvd SEL_RES " + hexlify(sel_res))
                uid = target.sel_req
            else:
                uid = bytearray()
                for sel_cmd in "\x93\x95\x97":
                    self.chipset.in_set_protocol(add_crc=0, check_crc=0)
                    sdd_req = sel_cmd + "\x20"
                    log.debug("send SDD_REQ " + hexlify(sdd_req))
                    sdd_res = self.chipset.in_comm_rf(sdd_req, 30)
                    log.debug("rcvd SDD_RES " + hexlify(sdd_res))
                    self.chipset.in_set_protocol(add_crc=1, check_crc=1)
                    sel_req = sel_cmd + "\x70" + sdd_res
                    log.debug("send SEL_REQ " + hexlify(sel_req))
                    sel_res = self.chipset.in_comm_rf(sel_req, 30)
                    log.debug("rcvd SEL_RES " + hexlify(sel_res))
                    if sel_res[0] & 0b00000100: uid = uid + sdd_res[1:4]
                    else: uid = uid + sdd_res[0:4]; break
            if sel_res[0] & 0b00000100 == 0:
                return nfc.clf.TTA(target.bitrate, sens_res=sens_res,
                                   sel_res=sel_res, sdd_res=uid)
        except CommunicationError as error:
            log.debug(error)

    def sense_ttb(self, target):
        log.debug("polling for NFC-B technology")

        if target.brty not in ("106B", "212B", "424B"):
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=20, add_sof=1,
                                     check_sof=1, add_eof=1, check_eof=1)

        sens_req = (target.sens_req if target.sens_req else
                    bytearray.fromhex("050010"))
        
        log.debug("send SENSB_REQ " + hexlify(sens_req))
        try:
            sens_res = self.chipset.in_comm_rf(sens_req, 30)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR": log.debug(error)
            return None
        
        if len(sens_res) >= 12 and sens_res[0] == 0x50:
            log.debug("rcvd SENSB_RES " + hexlify(sens_res))
            return nfc.clf.TTB(106, sens_res=sens_res)

    def sense_ttf(self, target):
        log.debug("polling for NFC-F technology")

        if target.brty not in ("212F", "424F"):
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=24)

        sens_req = (target.sens_req if target.sens_req else
                    bytearray.fromhex("00FFFF0000"))
        
        log.debug("send SENSF_REQ " + hexlify(sens_req))
        try:
            frame = chr(len(sens_req)+1) + sens_req
            frame = self.chipset.in_comm_rf(frame, 10)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR": log.debug(error)
            return None
        
        if len(frame) >= 18 and frame[0] == len(frame) and frame[1] == 1:
            log.debug("rcvd SENSF_RES " + hexlify(frame[1:]))
            return nfc.clf.TTF(target.bitrate, sens_res=frame[1:])
            
    def listen_ttf(self, target, timeout):
        assert type(target) == nfc.clf.TTF
        
        timeout_msec = int(timeout * 1000) + 1 if timeout else 0
        log.debug("listen_ttf for {0} msec".format(timeout_msec))

        if target.br is None:
            log.warning("listen bitrate not specified, set to 212")
            target.br = 212
            
        self.chipset.tg_set_rf(str(target.br) + 'F')
        self.chipset.tg_set_protocol("\x00\x01\x01\x00\x02\x07")

        data = None
        time_to_return = time.time() + timeout

        while timeout_msec > 0:
            try:
                data = self.chipset.tg_comm_rf(
                    mdaa=False, recv_timeout=timeout_msec,
                    transmit_data=data)
            except CommunicationError as error:
                if error != "RECEIVE_TIMEOUT_ERROR":
                    log.debug(error)
            else:
                tech = ('106A', '212F', '424F')[data[0]-11]
                log.info("{0} {1}".format(tech, str(data).encode("hex")))
                if data[7:].startswith("\x06\x00"):
                    data = ("\x01" + target.idm + target.pmm
                            + (target.sys if data[7+4] == 1 else ''))
                    data = chr(len(data) + 1) + data
                    timeout_msec = 100
                    continue
                elif data[9:].startswith(target.idm):
                    break
                else:
                    data = None
            timeout_msec = int(time_to_return - time.time() * 1000)
        else:
            return None

        self.chipset.tg_set_protocol("\x01\x01") # break on rf off
        self.exchange = self.send_rsp_recv_cmd
        return target, data[7:]

    def listen_dep(self, target, timeout):
        assert type(target) == nfc.clf.DEP
        
        timeout_msec = int(timeout * 1000) + 1 if timeout else 0
        log.debug("listen_dep for {0} msec".format(timeout_msec))

        nfca_cfg = bytearray((0x01, 0x00, 0x40))
        nfca_uid = bytearray(os.urandom(3))
        nfca_target = nfc.clf.TTA(None, nfca_cfg, nfca_uid)
        nfca_params = nfca_cfg[0:2] + nfca_uid + nfca_cfg[2:3]
        
        nfcf_idm = bytearray((0x01, 0xFE)) + os.urandom(6)
        nfcf_pmm = bytearray(8)
        nfcf_sys = bytearray((0xFF, 0xFF))
        nfcf_target = nfc.clf.TTF(None, nfcf_idm, nfcf_pmm, nfcf_sys)
        nfcf_params = nfcf_target.idm + nfcf_target.pmm + nfcf_target.sys
        
        if target.br is not None:
            tech = str(target.br) + {106: 'A', 212: 'F', 424: 'F'}[target.br]
            mdaa = False
        else:
            tech = "106A"
            mdaa = True

        self.chipset.tg_set_rf(tech)
        self.chipset.tg_set_protocol("\x00\x01\x01\x00\x02\x07")

        data = None
        time_to_return = time.time() + timeout

        while timeout_msec > 0:
            try:
                data = self.chipset.tg_comm_rf(
                    mdaa=mdaa, recv_timeout=timeout_msec,
                    nfca_params=str(nfca_params),
                    nfcf_params=str(nfcf_params),
                    transmit_data=data)
            except CommunicationError as error:
                if error != "RECEIVE_TIMEOUT_ERROR":
                    log.warning(error)
            else:
                tech = ('106A', '212F', '424F')[data[0]-11]
                log.debug("{0} {1}".format(tech, str(data).encode("hex")))
                if mdaa is True:
                    if data[2] & 0x03 == 3: break
                    else: data = None
                elif tech in ('212F', '424F'):
                    if data[7:].startswith("\x06\x00" + nfcf_target.sys):
                        data = ("\x01" + nfcf_target.idm + nfcf_target.pmm
                                + (nfcf_target.sys if data[7+4] == 1 else ''))
                        data = chr(len(data) + 1) + data
                        timeout_msec = 100
                        continue
                    elif data[8:].startswith('\xD4\x00' + nfcf_target.idm):
                        break
                    else: data = None
                else: data = None
            timeout_msec = int((time_to_return - time.time()) * 1000)
        else:
            return None

        self.chipset.tg_set_protocol("\x01\x01") # break on rf off
        target = nfca_target if tech[-1] == 'A' else nfcf_target
        target.br = int(tech[0:-1])
        self.exchange = self.send_rsp_recv_cmd
        return target, data[7:]

    @property
    def max_send_data_size(self):
        return 290

    @property
    def max_recv_data_size(self):
        return 290

    def send_cmd_recv_rsp(self, target, data, timeout):
        timeout_msec = int(timeout * 1000) + 1 if timeout else 0
        try:
            return self.chipset.in_comm_rf(data, timeout_msec)
        except CommunicationError as error:
            log.debug(error)
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise nfc.clf.TimeoutError
            raise nfc.clf.TransmissionError

    def send_rsp_recv_cmd(self, target, data, timeout):
        timeout_msec = int(timeout * 1000) + 1 if timeout else 0
        try:
            data = self.chipset.tg_comm_rf(
                guard_time=500, recv_timeout=timeout_msec, transmit_data=data)
            return data[7:] if data else None
        except CommunicationError as error:
            log.debug(error)
            if error == "RF_OFF_ERROR":
                return None
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise nfc.clf.TimeoutError
            raise nfc.clf.TransmissionError

def init(transport):
    chipset = Chipset(transport, logger=log)
    device = Device(chipset, logger=log)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device

