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

import nfc.dev
import nfc.clf

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
    
class Chipset():
    ACK = bytearray('\x00\x00\xFF\x00\xFF\x00')
    
    def __init__(self, transport):
        self.transport = transport
        
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
        if self.transport is not None:
            cmd = bytearray([0xD6, cmd_code]) + bytearray(cmd_data)
            self.transport.write(str(Frame(cmd)))
            if Frame(self.transport.read(timeout=100)).type == "ack":
                rsp = Frame(self.transport.read(timeout)).data
                if rsp and rsp[0] == 0xD7 and rsp[1] == cmd_code + 1:
                    return rsp[2:]
        else: log.debug("transport closed in send_command")
                
    @trace
    def in_set_rf(self, comm_type):
        in_comm_type = {"212F": (1, 1, 15, 1), "424F": (1, 2, 15, 2),
                        "106A": (2, 3, 15, 3), "212A": (0, 4,  0, 4),
                        "424A": (0, 5,  0, 5), "106B": (3, 7, 15, 7),
                        "212B": (0, 8,  0, 8), "424B": (0, 9,  0, 9)
                        }
        comm_type = in_comm_type[comm_type]
        data = self.send_command(0x00, comm_type, 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def in_set_protocol(self, data):
        data = self.send_command(0x02, bytearray(data), 100)
        if data and data[0] != 0:
            raise StatusError(data[0])
        
    @trace
    def in_comm_rf(self, data, timeout):
        to = struct.pack("<H", timeout*10) if timeout <= 6553 else '\xFF\xFF'
        data = self.send_command(0x04, to + str(data), timeout+500)
        if data and tuple(data[0:4]) != (0, 0, 0, 0):
            raise CommunicationError(data[0:4])
        return data[5:] if data else None
        
    @trace
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
    def get_firmware_version(self):
        data = self.send_command(0x20, [], 100)
        log.debug("firmware version {1:x}.{0:02x}".format(*data))
        data = self.send_command(0x20, [0x80], 100)
        log.debug("boot version {1:x}.{0:02x}".format(*data))
        
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

class Device(nfc.dev.Device):
    def __init__(self, transport):
        self.chipset = Chipset(transport)
    
    def close(self):
        self.chipset.close()
    
    @property
    def capabilities(self):
        return {}

    def sense(self, targets):
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
            return None
        
        self.exchange = self.send_cmd_recv_rsp
        return target

    def sense_tta(self):
        target = None
        try:
            target = self._sense_tta()
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target

    def _sense_tta(self):
        log.debug("polling for NFC-A technology")
        self.chipset.switch_rf("off")
        
        self.chipset.in_set_rf("106A")
        self.chipset.in_set_protocol(
            "\x00\x06" "\x01\x00" "\x02\x00" "\x03\x00" "\x04\x00"
            "\x05\x01" "\x06\x00" "\x07\x07" "\x08\x00" "\x09\x00"
            "\x0A\x00" "\x0B\x00" "\x0C\x00" "\x0E\x04" "\x0F\x00"
            "\x10\x00" "\x11\x00" "\x12\x00" "\x13\x06")
        
        sens_res = self.chipset.in_comm_rf("\x26", 30)
        if sens_res is None or len(sens_res) != 2: return
        log.debug("SENS_RES (ATQ) = " + str(sens_res).encode("hex"))

        if sens_res[0] & 0x1F == 0 and sens_res[1] & 0x0F == 0b1100:
            #
            # type 1 tag platform
            #
            log.debug("NFC-A TT1 target @ 106 kbps")
            
            # set: add tt1 crc, check tt1 crc, all bits valid, rrdd = 60µs
            self.chipset.in_set_protocol("\x01\x02\x02\x02\x07\x08\x11\x02")
            
            rid_cmd = bytearray("\x78\x00\x00\x00\x00\x00\x00")
            rid_res = self.chipset.in_comm_rf(rid_cmd, 30)
            if not rid_res[0] & 0xF0 == 0x10:
                self.chipset.switch_rf("off")
                raise nfc.clf.ProtocolError("8.6.2.1")
            
            return nfc.clf.TTA(br=106, cfg=sens_res, uid=rid_res[2:])

        elif sens_res[0] & 0x1F == 0 or sens_res[1] & 0x0F == 0b1100:
            self.chipset.switch_rf("off")
            raise nfc.clf.ProtocolError("4.6.3.3")
        
        #
        # other than type 1 tag platform
        #
        self.chipset.in_set_protocol("\x04\x01\x07\x08") # odd parity, all bits
        uid = bytearray()
        for cascade_level in range(3):
            sel_cmd = ("\x93", "\x95", "\x97")[cascade_level]
            self.chipset.in_set_protocol("\x01\x00\x02\x00") # no crc add/check
            sdd_res = self.chipset.in_comm_rf(sel_cmd + "\x20", 30)
            log.debug("SDD_RES = " + str(sdd_res).encode("hex"))
            self.chipset.in_set_protocol("\x01\x01\x02\x01") # do crc add/check
            sel_res = self.chipset.in_comm_rf(sel_cmd + "\x70" + sdd_res, 30)
            log.debug("SEL_RES = " + str(sel_res).encode("hex"))
            if bool(sel_res[0] & 0b00000100):
                uid = uid + sdd_res[1:4]
            else:
                uid = uid + sdd_res[0:4]
                return nfc.clf.TTA(br=106, cfg=sens_res+sel_res, uid=uid)

    def sense_ttb(self):
        target = None
        try:
            target = self._sense_ttb()
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target

    def _sense_ttb(self):
        log.debug("polling for NFC-B technology")

        self.chipset.in_set_rf("106B")
        self.chipset.in_set_protocol(
            "\x00\x14" "\x01\x01" "\x02\x01" "\x03\x00" "\x04\x00"
            "\x05\x00" "\x06\x00" "\x07\x08" "\x08\x00" "\x09\x01"
            "\x0A\x01" "\x0B\x01" "\x0C\x01" "\x0E\x04" "\x0F\x00"
            "\x10\x00" "\x11\x00" "\x12\x00" "\x13\x06")

        rsp = self.chipset.in_comm_rf("\x05\x00\x00", 30)

    def sense_ttf(self, br, sc, rc):
        target = None
        try:
            target = self._sense_ttf(br, sc, rc)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target
    
    def _sense_ttf(self, br, sc, rc):
        # poll felica (bit rate 'br', system code 'sc', request code 'rc')
        poll_cmd = "0600{sc[0]:02x}{sc[1]:02x}{rc:02x}03".format(sc=sc, rc=rc)
        log.debug("poll NFC-F {0}".format(poll_cmd))

        self.chipset.in_set_rf(str(br) + "F")
        self.chipset.in_set_protocol(
            "\x00\x18" "\x01\x01" "\x02\x01" "\x03\x00" "\x04\x00"
            "\x05\x00" "\x06\x00" "\x07\x08" "\x08\x00" "\x09\x00"
            "\x0A\x00" "\x0B\x00" "\x0C\x00" "\x0E\x04" "\x0F\x00"
            "\x10\x00" "\x11\x00" "\x12\x00" "\x13\x06")
        
        rsp = self.chipset.in_comm_rf(bytearray(poll_cmd.decode("hex")), 10)
        if rsp and len(rsp) >= 18 and rsp[0] == len(rsp) and rsp[1] == 1:
            if len(rsp) == 18: rsp += "\xff\xff"
            idm, pmm, sys = rsp[2:10], rsp[10:18], rsp[18:20]
            return nfc.clf.TTF(br=br, idm=idm, pmm=pmm, sys=sys)
            
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

    def send_cmd_recv_rsp(self, data, timeout):
        timeout_msec = int(timeout * 1000) + 1 if timeout else 0
        try:
            return self.chipset.in_comm_rf(data, timeout_msec)
        except CommunicationError as error:
            log.debug(error)
            if error == "RECEIVE_TIMEOUT_ERROR":
                raise nfc.clf.TimeoutError
            raise nfc.clf.TransmissionError

    def send_rsp_recv_cmd(self, data, timeout):
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

    def set_communication_mode(self, brm, **kwargs):
        if self.exchange == self.send_rsp_recv_cmd:
            self._tg_set_communication_mode(brm, **kwargs)
        if self.exchange == self.send_cmd_recv_rsp:
            self._in_set_communication_mode(brm, **kwargs)

    def _tg_set_communication_mode(self, brm, **args):
        if brm: self.chipset.tg_set_rf(brm)

    def _in_set_communication_mode(self, brm, **kwargs):
        # brm is a 'bitrate' + 'technology' string, e.g. '106A'
        # technology letters: 'A', 'B', 'F', 'J' (Jewel/Topaz), 'P' (Picopass)
        if brm: self.chipset.in_set_rf(brm)
        settings = list()
        if 'add_crc' in kwargs:
            mapping = {'OFF': 0, 'ISO': 1, 'TT1': 2, 'PICO-2': 3, 'PICO-3': 4}
            settings.extend([0x01, mapping.get(kwargs.get('add_crc'))])
        if 'check_crc' in kwargs:
            mapping = {'OFF': 0, 'ISO': 1, 'TT1': 2, 'PICO': 3}
            settings.extend([0x02, mapping.get(kwargs.get('check_crc'))])
        if settings:
            self.chipset.in_set_protocol(settings)

def init(transport):
    device = Device(transport)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device

