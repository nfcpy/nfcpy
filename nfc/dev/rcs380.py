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

from transport import usb as usb_transport
from nfc.clf import ProtocolError, TransmissionError, TimeoutError
from nfc.clf import TTA, TTB, TTF
import nfc.dev

from collections import namedtuple
from struct import pack, unpack
from time import time
from os import urandom

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.debug("{func}({args})".format(func=func.__name__, args=_args))
        data = func(*args, **kwargs)
        log.debug("{0} returns {1}".format(func.__name__, repr(data)))
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
                length = unpack("<H", str(frame[5:7]))[0]
                self._data = frame[8:8+length]
        else:
            frame  = bytearray([0, 0, 255, 255, 255])
            frame += bytearray(pack("<H", len(data)))
            frame += bytearray(pack("B", (256 - sum(frame[5:7])) % 256))
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
        self.errno = unpack('<L', str(status_bytes))[0]

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
    def __init__(self, transport):
        self.transport = transport
        self.set_command_type(1)
        self.get_firmware_version()
        self.get_pd_data_version()
        self.switch_rf("off")

    #@trace
    def send_command(self, cmd_code, cmd_data, timeout):
        cmd = bytearray([0xD6, cmd_code]) + bytearray(cmd_data)
        self.transport.write(str(Frame(cmd)))
        if Frame(self.transport.read(timeout=100)).type == "ack":
            rsp_frame = self.transport.read(timeout)
            if rsp_frame is None:
                raise IOError("no answer from reader within %d ms" % timeout)
            rsp = Frame(rsp_frame).data
            if rsp[0] == 0xD7 and rsp[1] == cmd_code + 1:
                return rsp[2:]
                
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
        try: data = bytearray.fromhex(data)
        except (TypeError, ValueError): pass
        data = self.send_command(0x02, data, 100)
        if data[0] != 0:
            log.error("in_set_protocol error {0:x}".format(data[0]))
            raise StatusError(data[0])
        
    @trace
    def in_comm_rf(self, data, timeout):
        to = pack("<H", timeout*10)
        data = self.send_command(0x04, to + str(data), timeout+500)
        if tuple(data[0:4]) != (0, 0, 0, 0):
            error = CommunicationError(data[0:4])
            log.debug("in_comm_rf {0}".format(error))
            raise error
        return data[5:]
        
    @trace
    def switch_rf(self, switch):
        switch = ("off", "on").index(switch)
        data = self.send_command(0x06, [switch], 100)
        if data[0] != 0:
            log.error("switch_rf {0:x}".format(data[0]))
        
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
        try: data = bytearray.fromhex(data)
        except (TypeError, ValueError): pass
        rsp_data = self.send_command(0x42, data, 100)
        if rsp_data[0] != 0:
            log.error("tg_set_protocol error {0:x}".format(rsp_data[0]))
        
    @trace
    def tg_set_auto(self, data):
        rsp_data = self.send_command(0x44, data, 100)
        if rsp_data[0] != 0:
            log.error("tg_set_auto error {0:x}".format(rsp_data[0]))
        
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
        data = pack(
            "<HH?6s18s??H", guard_time, send_timeout, mdaa, nfca_params,
            nfcf_params, mf_halted, arae, recv_timeout)
        if transmit_data:
            data = data + str(transmit_data)
            
        data = self.send_command(0x48, data, recv_timeout+500)
        
        if tuple(data[3:7]) != (0, 0, 0, 0):
            raise CommunicationError(data[3:7])
        
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
        return unpack(">Q", str(rsp_data[0:8]))
    
    @trace
    def set_command_type(self, command_type):
        rsp_data = self.send_command(0x2A, [command_type], 100)
        if rsp_data[0] != 0:
            log.error("set_command_type error {0:x}".format(rsp_data[0]))

class Device(nfc.dev.Device):
    def __init__(self, chipset):
        self.chipset = chipset
    
    def close(self):
        self.chipset.switch_rf("off")
        pass
    
    @trace
    def sense(self, targets):
        for tg in targets:
            if type(tg) == TTA:
                target = self.sense_a()
                if (target and
                    (tg.cfg is None or target.cfg.startswith(tg.cfg)) and
                    (tg.uid is None or target.uid.startswith(tg.uid))):
                    break
            elif type(tg) == TTB:
                target = self.sense_b()
                if target:
                    pass
            elif type(tg) == TTF:
                br, sc, rc = tg.br, tg.sys, 0
                if sc is None: sc, rc = bytearray('\xFF\xFF'), 1
                target = self.sense_f(br, sc, rc)
                if (target and
                    (tg.sys is None or target.sys == tg.sys) and
                    (tg.idm is None or target.idm.startswith(tg.idm)) and
                    (tg.pmm is None or target.pmm.startswith(tg.pmm))):
                    break
        else:
            return None
        
        self.exchange = self.send_cmd_recv_rsp
        return target

    def sense_a(self):
        target = None
        try:
            target = self._sense_a()
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target

    def _sense_a(self):
        log.debug("polling for NFC-A technology")
        self.technology = None
        self.chipset.switch_rf("off")
        
        self.chipset.in_set_rf("106A")
        self.chipset.in_set_protocol(
            "0006 0100 0200 0300 0400 0501 0600 0707 0800 0900"
            "0a00 0b00 0c00 0e04 0f00 1000 1100 1200 1306")
        
        sens_res = self.chipset.in_comm_rf("\x26", 30)
        log.debug("SENS_RES (ATQ) = " + str(sens_res).encode("hex"))

        if sens_res[0] & 0x1F == 0 and sens_res[1] & 0x0F == 0b1100:
            #
            # type 1 tag platform
            #
            log.debug("NFC-A TT1 target @ 106 kbps")
            
            # set: add tt1 crc, check tt1 crc, all bits valid, rrdd = 60µs
            self.chipset.in_set_protocol("0102 0202 0708 1102")
            
            rid_cmd = bytearray.fromhex("78 00 00 00 00 00 00")
            rid_res = self.chipset.in_comm_rf(rid_cmd, 30)
            if not rid_res[0] & 0xF0 == 0x10:
                self.chipset.switch_rf("off")
                raise ProtocolError("8.6.2.1")
            
            return TTA(br=106, cfg=sens_res, uid=rid_res[2:])

        elif sens_res[0] & 0x1F == 0 or sens_res[1] & 0x0F == 0b1100:
            self.chipset.switch_rf("off")
            raise ProtocolError("4.6.3.3")
        
        #
        # other than type 1 tag platform
        #
        self.chipset.in_set_protocol("0401 0708") # odd parity, all bits
        uid = bytearray()
        for cascade_level in range(3):
            sel_cmd = ("\x93", "\x95", "\x97")[cascade_level]
            self.chipset.in_set_protocol("0100 0200") # no crc add/check
            sdd_res = self.chipset.in_comm_rf(sel_cmd + "\x20", 30)
            log.debug("SDD_RES = " + str(sdd_res).encode("hex"))
            self.chipset.in_set_protocol("0101 0201") # do crc add/check
            sel_res = self.chipset.in_comm_rf(sel_cmd + "\x70" + sdd_res, 30)
            log.debug("SEL_RES = " + str(sel_res).encode("hex"))
            if bool(sel_res[0] & 0b00000100):
                uid = uid + sdd_res[1:4]
            else:
                uid = uid + sdd_res[0:4]
                return TTA(br=106, cfg=sens_res+sel_res, uid=uid)

    def sense_b(self):
        target = None
        try:
            target = self._sense_b()
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target

    def _sense_b(self):
        log.debug("polling for NFC-B technology")
        self.chipset.in_set_rf("106B")
        p = bytearray.fromhex("0014010102010300040005000600070808000901"+
                              "0a010b010c010e040f001000110012001306")
        self.chipset.in_set_protocol(p)        
        rsp = self.chipset.in_comm_rf("\x05\x00\x00", 30)

    def sense_f(self, br, sc, rc):
        target = None
        try:
            target = self._sense_f(br, sc, rc)
        except CommunicationError as error:
            if error != "RECEIVE_TIMEOUT_ERROR":
                log.debug(error)
        if target is None:
            self.chipset.switch_rf("off")
        return target
    
    def _sense_f(self, br, sc, rc):
        # poll felica (bit rate 'br', system code 'sc', request code 'rc')
        poll_cmd = "0600{sc[0]:02x}{sc[1]:02x}{rc:02x}03".format(sc=sc, rc=rc)
        log.debug("poll NFC-F {0}".format(poll_cmd))

        self.chipset.in_set_rf(str(br) + "F")
        self.chipset.in_set_protocol(
            "0018 0101 0201 0300 0400 0500 0600 0708 0800 0900"
            "0a00 0b00 0c00 0e04 0f00 1000 1100 1200 1306")
        
        rsp = self.chipset.in_comm_rf(bytearray.fromhex(poll_cmd), 10)
        if len(rsp) >= 18 and rsp[0] == len(rsp) and rsp[1] == 1:
            if len(rsp) == 18: rsp += "\xff\xff"
            idm, pmm, sys = rsp[2:10], rsp[10:18], rsp[18:20]
            return TTF(br=br, idm=idm, pmm=pmm, sys=sys)
            
    @trace
    def listen(self, targets, timeout):
        """Listen for multiple targets. This hardware supports
        listening for Type A and Type F activation."""
        
        if not targets:
            return None

        timeout_msec = int(timeout * 1000)
        log.debug("listen for {0} msec".format(timeout_msec))

        nfca_params = bytearray.fromhex("FFFF000000FF")
        nfcf_params = bytearray(18) # all zero
        nfca_target = None
        nfcf_target = None
        
        for target in targets:
            if type(target) == TTA:
                nfca_params = target.cfg[0:2] + target.uid[1:] + target.cfg[2:]
                nfca_target = target
            if type(target) == TTF:
                nfcf_params = target.idm + target.pmm + target.sys
                nfcf_target = target
            
        assert len(nfca_params) == 6
        assert len(nfcf_params) == 18
        
        self.chipset.tg_set_rf("212F")
        self.chipset.tg_set_protocol("0001 0100 0207")

        start_time = time()
        while timeout > 0:
            try:
                data = self.chipset.tg_comm_rf(
                    mdaa=True, recv_timeout=timeout_msec,
                    nfca_params=str(nfca_params),
                    nfcf_params=str(nfcf_params),
                    mf_halted=bool(nfca_target))
                tech = ('106A', '212F', '424F')[data[0]-11]
                log.info("{0} {1}".format(tech, str(data).encode("hex")))
                if data[2] & 0x03 == 3:
                    break
            except CommunicationError as error:
                if error != "RECEIVE_TIMEOUT_ERROR":
                    log.debug(error)
            timeout -= time() - start_time
        else:
            return None

        self.chipset.tg_set_protocol("0101") # break on rf off
        if tech == "106A": target = TTA(106, *nfca_target[1:])
        if tech == "212F": target = TTF(212, *nfcf_target[1:])
        if tech == "424F": target = TTF(424, *nfcf_target[1:])
        self.exchange = self.send_rsp_recv_cmd
        return target, data[7:]

    @trace
    def send_cmd_recv_rsp(self, data, timeout):
        timeout_msec = int(timeout * 1000)
        try:
            return self.chipset.in_comm_rf(data, timeout_msec)
        except CommunicationError as error:
            log.debug(error)
            if error == "RECEIVE_TIMEOUT_ERROR": raise TimeoutError
            else: raise TransmissionError

    @trace
    def send_rsp_recv_cmd(self, data, timeout):
        timeout_msec = int(timeout * 1000)
        try:
            data = self.chipset.tg_comm_rf(
                guard_time=500, recv_timeout=timeout_msec, transmit_data=data)
            return data[7:]
        except CommunicationError as error:
            log.debug(error)
            if error in ("RECEIVE_TIMEOUT_ERROR", "RF_OFF_ERROR"):
                raise TimeoutError
            else: raise TransmissionError

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

def init(device, transport):
    if transport == "usb":
        transport = usb_transport(device)
        chipset = Chipset(transport)
        product = transport.dh.getString(device.iProduct, 100)
        device = Device(chipset)
        device._vendor = "Sony"
        device._product = product
        return device

