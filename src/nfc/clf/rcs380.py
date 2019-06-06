# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
"""Driver module for contactless devices based on the Sony NFC Port-100
chipset. The only product known to use this chipset is the PaSoRi
RC-S380. The RC-S380 connects to the host as a native USB device.

The RC-S380 has been the first NFC Forum certified device. It supports
reading and writing of all NFC Forum tags as well as peer-to-peer
mode. In addition, the NFC Port-100 also supports card emulation Type
A and Type F Technology. A notable restriction is that peer-to-peer
active communication mode (not required for NFC Forum certification)
is not supported.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes
sense_ttb   yes
sense_ttf   yes
sense_dep   no
listen_tta  yes      Type F responses can not be disabled
listen_ttb  no
listen_ttf  yes
listen_dep  yes      Only passive communication mode
==========  =======  ============

"""
import nfc.clf
from . import device

import time
import struct
import operator
from functools import reduce
from binascii import hexlify

import logging
log = logging.getLogger(__name__)


class Frame(object):
    def __init__(self, data):
        self._data = None
        self._type = None
        self._frame = None

        if data[0:3] == bytearray(b"\x00\x00\xff"):
            frame = bytearray(data)
            if frame == bytearray(b"\x00\x00\xff\x00\xff\x00"):
                self._type = "ack"
            elif frame == bytearray(b"\x00\x00\xFF\xFF\xFF"):
                self._type = "err"
            elif frame[3:5] == bytearray(b"\xff\xff"):
                self._type = "data"
            if self.type == "data":
                length = struct.unpack("<H", bytes(frame[5:7]))[0]
                self._data = frame[8:8+length]
        else:
            frame = bytearray([0, 0, 255, 255, 255])
            frame += bytearray(struct.pack("<H", len(data)))
            frame += bytearray(struct.pack("B", (256 - sum(frame[5:7])) % 256))
            frame += bytearray(data)
            frame += bytearray([(256 - sum(frame[8:])) % 256, 0])
            self._frame = frame

    def __str__(self):
        return str(self._frame)

    def __bytes__(self):
        return bytes(self._frame)

    @property
    def type(self):
        return self._type

    @property
    def data(self):
        return self._data


class CommunicationError(Exception):
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
    str2err = dict([(v, k) for k, v in err2str.items()])

    def __init__(self, status_bytes):
        self.errno = struct.unpack('<L', status_bytes)[0]

    def __eq__(self, strerr):
        errno = CommunicationError.str2err[strerr]
        return bool(self.errno & errno) if self.errno or errno else True

    def __ne__(self, strerr):
        return not self.__eq__(strerr)

    def __str__(self):
        return self.__class__.__name__ + ' ' + CommunicationError.err2str.get(
            self.errno, "0x{0:08X}".format(self.errno))


class StatusError(Exception):
    err2str = ("SUCCESS", "PARAMETER_ERROR", "PB_ERROR", "RFCA_ERROR",
               "TEMPERATURE_ERROR", "PWD_ERROR", "RECEIVE_ERROR",
               "COMMANDTYPE_ERROR")

    def __init__(self, status):
        self.errno = status

    def __str__(self):
        try:
            return StatusError.err2str[self.errno]
        except IndexError:
            return "UNKNOWN STATUS ERROR 0x{:02X}".format(self.errno)


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

        # Clear any response data that may be leftover from the last
        # session when it was killed.
        try:
            while True:
                data = self.transport.read(timeout=10)
                log.debug("cleared garbage %s", hexlify(data).decode())
        except IOError:
            pass

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

    def send_command(self, cmd_code, cmd_data):
        cmd_data = bytearray(cmd_data)
        log.log(logging.DEBUG-1, "{} {}".format(self.CMD[cmd_code],
                                                hexlify(cmd_data).decode()))
        if self.transport is not None:
            cmd = bytearray([0xD6, cmd_code]) + cmd_data
            self.transport.write(bytes(Frame(cmd)))
            ack = Frame(self.transport.read())
            if ack.type == 'ack':
                rsp = Frame(self.transport.read())
                if rsp.type == 'data':
                    if rsp.data[0] == 0xD7 and rsp.data[1] == cmd_code + 1:
                        return rsp.data[2:]
                    else:
                        logmsg = "expected rsp code D7{:02X} not {:02X}{:02X}"
                        log.error(logmsg.format(cmd_code+1, *rsp.data[0:2]))
                else:
                    log.error("expected data but got {}".format(rsp.type))
            else:
                log.error("expected ack but got {}".format(ack.type))
        else:
            log.debug("transport closed in send_command")

    def in_set_rf(self, brty_send, brty_recv=None):
        settings = {
            "212F": (1, 1, 15, 1), "424F": (1, 2, 15, 2),
            "106A": (2, 3, 15, 3), "212A": (4, 4, 15, 4),
            "424A": (5, 5, 15, 5), "106B": (3, 7, 15, 7),
            "212B": (3, 8, 15, 8), "424B": (3, 9, 15, 9),
        }
        if brty_recv is None:
            brty_recv = brty_send
        data = settings[brty_send][0:2] + settings[brty_recv][2:4]
        data = self.send_command(0x00, data)
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
        for key, value in sorted(kwargs.items()):
            data.extend(bytearray([KEYS.index(key), int(value)]))
        if len(data) > 0:
            data = self.send_command(0x02, data)
            if data and data[0] != 0:
                raise StatusError(data[0])

    def in_comm_rf(self, data, timeout):
        timeout = min((timeout + (1 if timeout > 0 else 0)) * 10, 0xFFFF)
        data = self.send_command(0x04,
                                 struct.pack("<H", timeout) + bytes(data))
        if data and tuple(data[0:4]) != (0, 0, 0, 0):
            raise CommunicationError(data[0:4])
        return data[5:] if data else None

    def switch_rf(self, switch):
        switch = ("off", "on").index(switch)
        data = self.send_command(0x06, [switch])
        if data and data[0] != 0:
            raise StatusError(data[0])

    def tg_set_rf(self, comm_type):
        tg_comm_type = {"106A": (8, 11), "212F": (8, 12), "424F": (8, 13),
                        "212A": (8, 14), "424A": (8, 15)}

        comm_type = tg_comm_type[comm_type]
        data = self.send_command(0x40, comm_type)
        if data and data[0] != 0:
            raise StatusError(data[0])

    tg_set_protocol_defaults = bytearray.fromhex("0001 0101 0207")

    def tg_set_protocol(self, data=None, **kwargs):
        data = bytearray() if data is None else bytearray(data)
        KEYS = ("send_timeout_time_unit", "rf_off_error",
                "continuous_receive_mode")
        for key, value in sorted(kwargs.items()):
            data.extend(bytearray([KEYS.index(key), int(value)]))
        data = self.send_command(0x42, bytearray(data))
        if data and data[0] != 0:
            raise StatusError(data[0])

    def tg_set_auto(self, data):
        data = self.send_command(0x44, data)
        if data and data[0] != 0:
            raise StatusError(data[0])

    def tg_comm_rf(self, guard_time=0, send_timeout=0xFFFF,
                   mdaa=False, nfca_params=b'', nfcf_params=b'',
                   mf_halted=False, arae=False, recv_timeout=0,
                   transmit_data=None):
        # Send a response packet and receive the next request. If
        # *transmit_data* is None skip sending. If *recv_timeout* is
        # zero skip receiving. Data is sent only between *guard_time*
        # and *send_timeout*, measured from the end of the last
        # received data. If *mdaa* is True, reply to Type A and Type F
        # activation commands with *nfca_params* (sens_res, nfcid1-3,
        # sel_res) and *nfcf_params* (idm, pmm, system_code).
        data = struct.pack("<HH?6s18s??H", guard_time, send_timeout,
                           mdaa, bytes(nfca_params), bytes(nfcf_params),
                           mf_halted, arae, recv_timeout)
        if transmit_data:
            data = data + bytes(transmit_data)

        data = self.send_command(0x48, data)

        if data and tuple(data[3:7]) != (0, 0, 0, 0):
            raise CommunicationError(data[3:7])

        return data

    def reset_device(self, startup_delay=0):
        self.send_command(0x12, struct.pack("<H", startup_delay))
        self.transport.write(Chipset.ACK)
        time.sleep(float(startup_delay + 500)/1000)

    def get_firmware_version(self, option=None):
        assert option in (None, 0x60, 0x61, 0x80)
        data = self.send_command(0x20, [option] if option else [])
        log.debug("firmware version {1:x}.{0:02x}".format(*data))
        return data

    def get_pd_data_version(self):
        data = self.send_command(0x22, [])
        log.debug("package data format {1:x}.{0:02x}".format(*data))

    def get_command_type(self):
        data = self.send_command(0x28, [])
        return struct.unpack(">Q", data[0:8])[0]

    def set_command_type(self, command_type):
        data = self.send_command(0x2A, [command_type])
        if data and data[0] != 0:
            raise StatusError(data[0])


class Device(device.Device):
    # Device driver for the Sony NFC Port-100 chipset.

    def __init__(self, chipset, logger):
        self.chipset = chipset
        self.log = logger

        minor, major = self.chipset.get_firmware_version()
        self._chipset_name = "NFC Port-100 v{0:x}.{1:02x}".format(major, minor)

    def close(self):
        self.chipset.close()
        self.chipset = None

    def mute(self):
        self.chipset.switch_rf("off")

    def sense_tta(self, target):
        """Sense for a Type A Target is supported for 106, 212 and 424
        kbps. However, there may not be any target that understands the
        activation commands in other than 106 kbps.

        """
        log.debug("polling for NFC-A technology")

        if target.brty not in ("106A", "212A", "424A"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=6, add_crc=0,
                                     check_crc=0, check_parity=1,
                                     last_byte_bit_count=7)

        sens_req = (target.sens_req if target.sens_req else
                    bytearray.fromhex("26"))

        try:
            sens_res = self.chipset.in_comm_rf(sens_req, 30)
            if len(sens_res) != 2:
                return None
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
            return None

        log.debug("rcvd SENS_RES %s", hexlify(sens_res).decode())

        if sens_res[0] & 0x1F == 0:
            log.debug("type 1 tag target found")
            self.chipset.in_set_protocol(last_byte_bit_count=8, add_crc=2,
                                         check_crc=2, type_1_tag_rrdd=2)
            target = nfc.clf.RemoteTarget(target.brty, sens_res=sens_res)
            if sens_res[1] & 0x0F == 0b1100:
                rid_cmd = bytearray.fromhex("78 0000 00000000")
                log.debug("send RID_CMD %s", hexlify(rid_cmd).decode())
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
                if len(uid) > 4:
                    uid = b"\x88" + uid
                if len(uid) > 8:
                    uid = uid[0:4] + b"\x88" + uid[4:]
                self.chipset.in_set_protocol(add_crc=1, check_crc=1)
                for i, sel_cmd in zip(range(0, len(uid), 4), b"\x93\x95\x97"):
                    sel_req = bytearray([sel_cmd, 0x70]) + uid[i:i+4]
                    sel_req.append(reduce(operator.xor, sel_req[2:6]))  # BCC
                    log.debug("send SEL_REQ %s", hexlify(sel_req).decode())
                    sel_res = self.chipset.in_comm_rf(sel_req, 30)
                    log.debug("rcvd SEL_RES %s", hexlify(sel_res).decode())
                uid = target.sel_req
            else:
                uid = bytearray()
                for sel_cmd in b"\x93\x95\x97":
                    self.chipset.in_set_protocol(add_crc=0, check_crc=0)
                    sdd_req = bytearray([sel_cmd, 0x20])
                    log.debug("send SDD_REQ %s", hexlify(sdd_req).decode())
                    sdd_res = self.chipset.in_comm_rf(sdd_req, 30)
                    log.debug("rcvd SDD_RES %s", hexlify(sdd_res).decode())
                    self.chipset.in_set_protocol(add_crc=1, check_crc=1)
                    sel_req = bytearray([sel_cmd, 0x70]) + sdd_res
                    log.debug("send SEL_REQ %s", hexlify(sel_req).decode())
                    sel_res = self.chipset.in_comm_rf(sel_req, 30)
                    log.debug("rcvd SEL_RES %s", hexlify(sel_res).decode())
                    if sel_res[0] & 0b00000100:
                        uid = uid + sdd_res[1:4]
                    else:
                        uid = uid + sdd_res[0:4]
                        break
            if sel_res[0] & 0b00000100 == 0:
                return nfc.clf.RemoteTarget(target.brty, sens_res=sens_res,
                                            sel_res=sel_res, sdd_res=uid)
        except CommunicationError as error:
            log.debug(error)

    def sense_ttb(self, target):
        """Sense for a Type B Target is supported for 106, 212 and 424
        kbps. However, there may not be any target that understands the
        activation command in other than 106 kbps.

        """
        log.debug("polling for NFC-B technology")

        if target.brty not in ("106B", "212B", "424B"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=20, add_sof=1,
                                     check_sof=1, add_eof=1, check_eof=1)

        sensb_req = (target.sensb_req if target.sensb_req else
                     bytearray.fromhex("050010"))

        log.debug("send SENSB_REQ %s", hexlify(sensb_req).decode())
        try:
            sensb_res = self.chipset.in_comm_rf(sensb_req, 30)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
            return None

        if len(sensb_res) >= 12 and sensb_res[0] == 0x50:
            log.debug("rcvd SENSB_RES %s", hexlify(sensb_res).decode())
            return nfc.clf.RemoteTarget(target.brty, sensb_res=sensb_res)

    def sense_ttf(self, target):
        """Sense for a Type F Target is supported for 212 and 424 kbps.

        """
        log.debug("polling for NFC-F technology")

        if target.brty not in ("212F", "424F"):
            message = "unsupported bitrate {0}".format(target.brty)
            raise nfc.clf.UnsupportedTargetError(message)

        self.chipset.in_set_rf(target.brty)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        self.chipset.in_set_protocol(initial_guard_time=24)

        sensf_req = (target.sensf_req if target.sensf_req else
                     bytearray.fromhex("00FFFF0100"))

        log.debug("send SENSF_REQ %s", hexlify(sensf_req).decode())
        try:
            frame = bytearray([len(sensf_req)+1]) + sensf_req
            frame = self.chipset.in_comm_rf(frame, 10)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
            return None

        if 18 <= len(frame) == frame[0] and frame[1] == 1:
            log.debug("rcvd SENSF_RES %s", hexlify(frame[1:]).decode())
            return nfc.clf.RemoteTarget(target.brty, sensf_res=frame[1:])

    def sense_dep(self, target):
        """Sense for an active DEP Target is not supported. The device only
        supports passive activation via sense_tta/sense_ttf.

        """
        message = "{device} does not support sense for active DEP Target"
        raise nfc.clf.UnsupportedTargetError(message.format(device=self))

    def listen_tta(self, target, timeout):
        """Listen as Type A Target in 106 kbps.

        Restrictions:

        * It is not possible to send short frames that are required
          for ACK and NAK responses. This means that a Type 2 Tag
          emulation can only implement a single sector memory model.

        * It can not be avoided that the chipset responds to SENSF_REQ
          commands. The driver configures the SENSF_RES response to
          all zero and ignores all Type F communication but eventually
          it depends on the remote device whether Type A Target
          activation will still be attempted.

        """
        if not target.brty == '106A':
            info = "unsupported target bitrate: %r" % target.brty
            raise nfc.clf.UnsupportedTargetError(info)

        if target.rid_res:
            info = "listening for type 1 tag activation is not supported"
            raise nfc.clf.UnsupportedTargetError(info)

        if target.sens_res is None:
            raise ValueError("sens_res is required")
        if target.sdd_res is None:
            raise ValueError("sdd_res is required")
        if target.sel_res is None:
            raise ValueError("sel_res is required")
        if len(target.sens_res) != 2:
            raise ValueError("sens_res must be 2 byte")
        if len(target.sdd_res) != 4:
            raise ValueError("sdd_res must be 4 byte")
        if len(target.sel_res) != 1:
            raise ValueError("sel_res must be 1 byte")
        if target.sdd_res[0] != 0x08:
            raise ValueError("sdd_res[0] must be 08h")

        nfca_params = target.sens_res + target.sdd_res[1:4] + target.sel_res
        log.debug("nfca_params %s", hexlify(nfca_params).decode())

        self.chipset.tg_set_rf("106A")
        self.chipset.tg_set_protocol(self.chipset.tg_set_protocol_defaults)
        self.chipset.tg_set_protocol(rf_off_error=False)

        time_to_return = time.time() + timeout
        tg_comm_rf_args = {'mdaa': True, 'nfca_params': nfca_params}
        tg_comm_rf_args['recv_timeout'] = min(int(1000 * timeout), 0xFFFF)

        def listen_tta_tt2():
            recv_timeout = tg_comm_rf_args['recv_timeout']
            while recv_timeout > 0:
                log.debug("wait %d ms for Type 2 Tag activation", recv_timeout)
                try:
                    data = self.chipset.tg_comm_rf(**tg_comm_rf_args)
                except CommunicationError as error:
                    log.debug(error)
                else:
                    brty = ('106A', '212F', '424F')[data[0]-11]
                    log.debug("%s rcvd %s",
                              brty, hexlify(memoryview(data)[7:]).decode())
                    if brty == "106A" and data[2] & 0x03 == 3:
                        self.chipset.tg_set_protocol(rf_off_error=True)
                        return nfc.clf.LocalTarget(
                            "106A", sens_res=nfca_params[0:2],
                            sdd_res=b'\x08'+nfca_params[2:5],
                            sel_res=nfca_params[5:6], tt2_cmd=data[7:])
                    else:
                        log.debug("not a 106A Type 2 Tag command")
                finally:
                    recv_timeout = int(1000 * (time_to_return - time.time()))
                    tg_comm_rf_args['recv_timeout'] = recv_timeout

        def listen_tta_tt4():
            rats_cmd = rats_res = None
            recv_timeout = tg_comm_rf_args['recv_timeout']
            while recv_timeout > 0:
                log.debug("wait %d ms for 106A TT4 command", recv_timeout)
                try:
                    data = self.chipset.tg_comm_rf(**tg_comm_rf_args)
                    tg_comm_rf_args['transmit_data'] = None
                except CommunicationError as error:
                    tg_comm_rf_args['transmit_data'] = None
                    rats_cmd = rats_res = None
                    log.debug(error)
                else:
                    brty = ('106A', '212F', '424F')[data[0]-11]
                    log.debug("%s rcvd %s", brty,
                              hexlify(memoryview(data)[7:]).decode())
                    if brty == "106A" and data[2] == 3 and data[7] == 0xE0:
                        (rats_cmd, rats_res) = (data[7:], target.rats_res)
                        log.debug("rcvd RATS_CMD %s",
                                  hexlify(rats_cmd).decode())
                        if rats_res is None:
                            rats_res = bytearray.fromhex("05 78 80 70 02")
                        log.debug("send RATS_RES %s",
                                  hexlify(rats_res).decode())
                        tg_comm_rf_args['transmit_data'] = rats_res
                    elif brty == "106A" and data[7] != 0xF0 and rats_cmd:
                        did = rats_cmd[1] & 0x0F
                        cmd = data[7:]
                        ta_tb_tc = rats_res[2:]
                        ta = ta_tb_tc.pop(0) if rats_res[1] & 0x10 else None
                        tb = ta_tb_tc.pop(0) if rats_res[1] & 0x20 else None
                        tc = ta_tb_tc.pop(0) if rats_res[1] & 0x40 else None
                        if ta is not None:
                            log.debug("TA(1) = {:08b}".format(ta))
                        if tb is not None:
                            log.debug("TB(1) = {:08b}".format(tb))
                        if tc is not None:
                            log.debug("TC(1) = {:08b}".format(tc))
                        if ta_tb_tc:
                            log.debug("T({}) = {}".format(
                                len(ta_tb_tc), hexlify(ta_tb_tc).decode()))
                        did_supported = tc is None or bool(tc & 0x02)
                        cmd_with_did = bool(cmd[0] & 0x08)
                        if (((cmd_with_did and did_supported and cmd[1] == did)
                             or (did == 0 and not cmd_with_did))):
                            if cmd[0] in (0xC2, 0xCA):
                                log.debug("rcvd S(DESELECT) %s",
                                          hexlify(cmd).decode())
                                tg_comm_rf_args['transmit_data'] = cmd
                                log.debug("send S(DESELECT) %s",
                                          hexlify(cmd).decode())
                                rats_cmd = rats_res = None
                            else:
                                log.debug("rcvd TT4_CMD %s",
                                          hexlify(cmd).decode())
                                self.chipset.tg_set_protocol(rf_off_error=True)
                                return nfc.clf.LocalTarget(
                                    "106A", sens_res=nfca_params[0:2],
                                    sdd_res=b'\x08'+nfca_params[2:5],
                                    sel_res=nfca_params[5:6], tt4_cmd=cmd,
                                    rats_cmd=rats_cmd, rats_res=rats_res)
                        else:
                            log.debug("skip TT4_CMD %s (DID)",
                                      hexlify(cmd).decode())
                    else:
                        log.debug("not a 106A TT4 command")
                finally:
                    recv_timeout = int(1000 * (time_to_return - time.time()))
                    tg_comm_rf_args['recv_timeout'] = recv_timeout

        if target.sel_res[0] & 0x60 == 0x00:
            return listen_tta_tt2()
        if target.sel_res[0] & 0x20 == 0x20:
            return listen_tta_tt4()

        reason = "sel_res does not indicate any tag target support"
        raise nfc.clf.UnsupportedTargetError(reason)

    def listen_ttb(self, target, timeout):
        """Listen as Type B Target is not supported."""
        message = "{device} does not support listen as Type A Target"
        raise nfc.clf.UnsupportedTargetError(message.format(device=self))

    def listen_ttf(self, target, timeout):
        """Listen as Type F Target is supported for either 212 or 424 kbps."""
        if target.brty not in ('212F', '424F'):
            info = "unsupported target bitrate: %r" % target.brty
            raise nfc.clf.UnsupportedTargetError(info)

        if target.sensf_res is None:
            raise ValueError("sensf_res is required")
        if len(target.sensf_res) != 19:
            raise ValueError("sensf_res must be 19 byte")

        self.chipset.tg_set_rf(target.brty)
        self.chipset.tg_set_protocol(self.chipset.tg_set_protocol_defaults)
        self.chipset.tg_set_protocol(rf_off_error=False)

        recv_timeout = min(int(1000 * timeout), 0xFFFF)
        time_to_return = time.time() + timeout
        transmit_data = sensf_req = sensf_res = None

        while recv_timeout > 0:
            if transmit_data:
                log.debug("%s send %s", target.brty,
                          hexlify(transmit_data).decode())
            log.debug("%s wait recv %d ms", target.brty, recv_timeout)
            try:
                data = self.chipset.tg_comm_rf(recv_timeout=recv_timeout,
                                               transmit_data=transmit_data)
            except CommunicationError as error:
                log.debug(error)
                continue
            finally:
                recv_timeout = int((time_to_return - time.time()) * 1E3)
                transmit_data = None

            assert target.brty == ('106A', '212F', '424F')[data[0]-11]
            log.debug("%s rcvd %s", target.brty,
                      hexlify(memoryview(data)[7:]).decode())

            if len(data) > 7 and len(data)-7 == data[7]:
                if sensf_req and data[9:17] == target.sensf_res[1:9]:
                    self.chipset.tg_set_protocol(rf_off_error=True)
                    target = nfc.clf.LocalTarget(target.brty)
                    target.sensf_req = sensf_req
                    target.sensf_res = sensf_res
                    target.tt3_cmd = data[8:]
                    return target

            if len(data) == 13 and data[7] == 6 and data[8] == 0:
                (sensf_req, sensf_res) = (data[8:], target.sensf_res[:])
                if (((sensf_req[1] == 255 or sensf_req[1] == sensf_res[17]) and
                     (sensf_req[2] == 255 or sensf_req[2] == sensf_res[18]))):
                    transmit_data = sensf_res[0:17]
                    if sensf_req[3] == 1:
                        transmit_data += sensf_res[17:19]
                    if sensf_req[3] == 2:
                        transmit_data += b"\x00"
                        transmit_data += bytearray(
                                [1 << (target.brty == "424F")])
                    transmit_data = bytearray([len(transmit_data)+1]) \
                        + transmit_data

    def listen_dep(self, target, timeout):
        log.debug("listen_dep for {0:.3f} sec".format(timeout))

        if not target.sens_res or len(target.sens_res) != 2:
            raise ValueError("sens_res is required and must be 2 byte")
        if not target.sel_res or len(target.sel_res) != 1:
            raise ValueError("sel_res is required and must be 1 byte")
        if not target.sdd_res or len(target.sdd_res) != 4:
            raise ValueError("sdd_res is required and must be 4 byte")
        if not target.sensf_res or len(target.sensf_res) < 19:
            raise ValueError("sensf_res is required and must be 19 byte")
        if not target.atr_res or len(target.atr_res) < 17:
            raise ValueError("atr_res is required and must be >= 17 byte")

        nfca_params = target.sens_res + target.sdd_res[1:4] + target.sel_res
        nfcf_params = target.sensf_res[1:19]
        log.debug("nfca_params %s", hexlify(nfca_params).decode())
        log.debug("nfcf_params %s", hexlify(nfcf_params).decode())

        self.chipset.tg_set_rf("106A")
        self.chipset.tg_set_protocol(self.chipset.tg_set_protocol_defaults)
        self.chipset.tg_set_protocol(rf_off_error=False)

        tg_comm_rf_args = {'mdaa': True}
        tg_comm_rf_args['nfca_params'] = nfca_params
        tg_comm_rf_args['nfcf_params'] = nfcf_params

        recv_timeout = min(int(1000 * timeout), 0xFFFF)
        time_to_return = time.time() + timeout

        while recv_timeout > 0:
            tg_comm_rf_args['recv_timeout'] = recv_timeout
            log.debug("wait %d ms for activation", recv_timeout)
            try:
                data = self.chipset.tg_comm_rf(**tg_comm_rf_args)
            except CommunicationError as error:
                if error != "RECEIVE_TIMEOUT_ERROR":
                    log.warning(error)
            else:
                brty = ('106A', '212F', '424F')[data[0]-11]
                log.debug("%s %s", brty, hexlify(data).decode())
                if data[2] & 0x03 == 3:
                    data = data[7:]
                    break
                else:
                    log.debug("not a passive mode activation")
            recv_timeout = int(1000 * (time_to_return - time.time()))
        else:
            return None

        # further tg_comm_rf commands return RF_OFF_ERROR when field is gone
        self.chipset.tg_set_protocol(rf_off_error=True)

        if brty == "106A" and len(data) > 1 and data[0] != 0xF0:
            # We received a Type A card activation, probably because
            # sel_res has indicated Type 2 or Type 4A Tag support.
            target = nfc.clf.LocalTarget("106A", tt2_cmd=data[:])
            target.sens_res = nfca_params[0:2]
            target.sdd_res = b'\x08' + nfca_params[2:5]
            target.sel_res = nfca_params[5:6]
            return target

        def verify_frame(brty, data, cmd_set):
            offset = 1 if brty == "106A" else 0
            try:
                if brty == "106A" and data[0] != 0xF0:
                    log.warning("rcvd frame has invalid start byte")
                elif data[offset] != len(data) - offset:
                    log.warning("rcvd frame has incorrect length byte")
                elif data[offset+1] != 0xD4:
                    log.warning("rcvd frame command byte 1 is not D4h")
                elif data[offset+2] not in cmd_set:
                    log.warning(
                            "rcvd frame command byte 2 not in %r" % cmd_set)
                else:
                    return data[offset+1:]
            except (IndexError):
                log.warning("rcvd frame with less than header size")

        def send_res_recv_req(brty, data, timeout):
            if data:
                data = (b"", b"\xF0")[brty == "106A"] + \
                       bytes([len(data)+1]) + data
            args = {'transmit_data': data, 'recv_timeout': timeout}
            data = self.chipset.tg_comm_rf(**args)[7:]
            if timeout > 0:
                return verify_frame(brty, data, cmd_set=[0, 4, 6, 8, 10])

        activation_params = nfca_params if brty == '106A' else nfcf_params
        data = verify_frame(brty, data, cmd_set=[0])

        while data and data[1] == 0:
            try:
                (atr_req, atr_res) = (data[:], target.atr_res)
                log.debug("%s rcvd ATR_REQ %s",
                          brty, hexlify(atr_req).decode())
                if 16 <= len(atr_req) <= 64:
                    log.debug("%s send ATR_RES %s", brty,
                              hexlify(atr_res).decode())
                    data = send_res_recv_req(brty, atr_res, 1000)
                else:
                    log.warning("ATR_REQ must be 16 to 64 byte")
                    data = None
            except (CommunicationError) as error:
                log.warning(str(error))
                data = None

        def send_dsl_res(brty, data):
            dsl_res = b"\xD5\x09" + data[2:3]
            log.debug("%s send DSL_RES %s", brty, hexlify(dsl_res).decode())
            send_res_recv_req(brty, dsl_res, 0)

        def send_rls_res(brty, data):
            rls_res = b"\xD5\x0B" + data[2:3]
            log.debug("%s send RLS_RES %s", brty, hexlify(rls_res).decode())
            send_res_recv_req(brty, rls_res, 0)

        def send_psl_res(brty, data):
            (dsi, dri) = (data[3] >> 3 & 7, data[3] & 7)
            if dsi != dri:
                log.error("PSL_REQ DSI != DRI is not supported")
                raise CommunicationError(b'\0\0\0\0')
            (psl_req, psl_res) = (data[:], b"\xD5\x05" + data[2:3])
            log.debug("%s send PSL_RES %s", brty, hexlify(psl_res).decode())
            send_res_recv_req(brty, psl_res, 0)
            brty = ('106A', '212F', '424F')[dsi]
            self.chipset.tg_set_rf(brty)
            return brty, psl_req, psl_res

        psl_req = None
        while data and data[1] in (4, 6, 8, 10):
            did = atr_req[12] if atr_req[12] > 0 else None
            cmd = {4: "PSL", 6: "DEP", 8: "DSL", 10: "RLS"}.get(data[1], '???')
            log.debug("%s rcvd %s_REQ %s", brty, cmd, hexlify(data).decode())
            try:
                if cmd == "DEP":
                    if did == (data[3] if data[2] >> 2 & 1 else None):
                        target = nfc.clf.LocalTarget(brty, dep_req=data)
                        target.atr_req = atr_req
                        if psl_req:
                            target.psl_req = psl_req
                        if activation_params == nfca_params:
                            target.sens_res = nfca_params[0:2]
                            target.sdd_res = b'\x08' + nfca_params[2:5]
                            target.sel_res = nfca_params[5:6]
                        else:
                            target.sensf_res = b"\x01" + nfcf_params
                        return target

                elif cmd == "DSL":
                    if did == (data[2] if len(data) > 2 else None):
                        return send_dsl_res(brty, data)

                elif cmd == "RLS":
                    if did == (data[2] if len(data) > 2 else None):
                        return send_rls_res(brty, data)

                elif cmd == "PSL":  # pragma: no branch
                    if did == (data[2] if data[2] > 0 else None):
                        brty, psl_req, psl_res = send_psl_res(brty, data)

                log.debug("%s wait recv 1000 ms", brty)
                data = send_res_recv_req(brty, None, 1000)

            except (CommunicationError) as error:
                log.warning(str(error))
                return None

    def get_max_send_data_size(self, target):
        return 290

    def get_max_recv_data_size(self, target):
        return 290

    def send_cmd_recv_rsp(self, target, data, timeout):
        if timeout:
            timeout_msec = max(min(int(timeout * 1000), 0xFFFF), 1)
        else:
            timeout_msec = 0
        self.chipset.in_set_rf(target.brty_send, target.brty_recv)
        self.chipset.in_set_protocol(self.chipset.in_set_protocol_defaults)
        in_set_protocol_settings = {}
        if target.brty_send.endswith('A'):
            in_set_protocol_settings['add_parity'] = 1
            in_set_protocol_settings['check_parity'] = 1
        if target.brty_send.endswith('B'):
            in_set_protocol_settings['initial_guard_time'] = 20
            in_set_protocol_settings['add_sof'] = 1
            in_set_protocol_settings['check_sof'] = 1
            in_set_protocol_settings['add_eof'] = 1
            in_set_protocol_settings['check_eof'] = 1
        try:
            if ((target.brty == '106A' and target.sel_res and
                 target.sel_res[0] & 0x60 == 0x00)):
                # Driver must check TT2 CRC to get ACK/NAK
                in_set_protocol_settings['check_crc'] = 0
                self.chipset.in_set_protocol(**in_set_protocol_settings)
                return self._tt2_send_cmd_recv_rsp(data, timeout_msec)
            else:
                self.chipset.in_set_protocol(**in_set_protocol_settings)
                return self.chipset.in_comm_rf(data, timeout_msec)
        except CommunicationError as error:
            log.debug(error)
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise nfc.clf.TimeoutError
            raise nfc.clf.TransmissionError

    def _tt2_send_cmd_recv_rsp(self, data, timeout_msec):
        # The Type2Tag implementation needs to receive the Mifare
        # ACK/NAK responses but the chipset reports them as crc error
        # (indistinguishable from a real crc error). We thus had to
        # switch off the crc check and do it here.
        data = self.chipset.in_comm_rf(data, timeout_msec)
        if len(data) > 2 and self.check_crc_a(data) is False:
            raise nfc.clf.TransmissionError("crc_a check error")
        return data[:-2] if len(data) > 2 else data

    def send_rsp_recv_cmd(self, target, data, timeout):
        assert timeout is None or timeout >= 0
        kwargs = {
            'guard_time': 500,
            'transmit_data': data,
            'recv_timeout': 0xFFFF if timeout is None else int(timeout*1E3),
        }
        try:
            data = self.chipset.tg_comm_rf(**kwargs)
            return data[7:] if data else None
        except CommunicationError as error:
            log.debug(error)
            if error == "RF_OFF_ERROR":
                raise nfc.clf.BrokenLinkError(str(error))
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise nfc.clf.TimeoutError(str(error))
            raise nfc.clf.TransmissionError(str(error))


def init(transport):
    chipset = Chipset(transport, logger=log)
    device = Device(chipset, logger=log)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device
