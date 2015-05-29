# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""This module implements common functionality for the PN53x family of
contactless interface chips, namely the NXP PN531, PN532, PN533 and
the Sony RC-S956. All of these are built upon a PN512 Contactless
Interface Unit (CIU) that is coupled with a 80C51 microprocessor and a
host communication interface. The implementation is split into a
:class:`Chipset` and a :class:`Device` class. The :class:`Chipset`
class provides methods for many of the chipset commands and handles
the host controller communication protocol. The :class:`Device` class
implements the :class:`device.Device` interface for the common
functionality across the chipset family.

"""
import os
import sys
import time
import errno
import logging
from binascii import hexlify

if sys.hexversion >= 0x020704F0:
    from struct import pack, unpack
else: # for Debian Wheezy (and thus Raspbian)
    from struct import pack, unpack as _unpack
    unpack = lambda fmt, string: _unpack(fmt, buffer(string))

import nfc.clf
from . import device

class Chipset(object):
    """Chipset"""
    SOF = bytearray.fromhex('0000FF')
    ACK = bytearray.fromhex('0000FF00FF00')
    REG = {
        0x6331: "CIU_Command",
        0x6332: "CIU_CommIEn",
        0x6333: "CIU_DivIEn",
        0x6334: "CIU_CommIRq",
        0x6335: "CIU_DivIRq",
        0x6336: "CIU_Error",
        0x6337: "CIU_Status1",
        0x6338: "CIU_Status2",
        0x6339: "CIU_FIFOData",
        0x633A: "CIU_FIFOLevel",
        0x633B: "CIU_WaterLevel",
        0x633C: "CIU_Control",
        0x633D: "CIU_BitFraming",
        0x633E: "CIU_Coll",
        0x6301: "CIU_Mode",
        0x6302: "CIU_TxMode",
        0x6303: "CIU_RxMode",
        0x6304: "CIU_TxControl",
        0x6305: "CIU_TxAuto",
        0x6306: "CIU_TxSel",
        0x6307: "CIU_RxSel",
        0x6308: "CIU_RxThreshold",
        0x6309: "CIU_Demod",
        0x630A: "CIU_FelNFC1",
        0x630B: "CIU_FelNFC2",
        0x630C: "CIU_MifNFC",
        0x630D: "CIU_ManualRCV",
        0x630E: "CIU_TypeB",
        0x630F: "CIU_SerialSpeed",
        0x6311: "CIU_CRCResultMSB",
        0x6312: "CIU_CRCResultLSB",
        0x6313: "CIU_GsNOff",
        0x6314: "CIU_ModWidth",
        0x6315: "CIU_TxBitPhase",
        0x6316: "CIU_RFCfg",
        0x6317: "CIU_GsNOn",
        0x6318: "CIU_CWGsP",
        0x6319: "CIU_ModGsP",
        0x631A: "CIU_TMode",
        0x631B: "CIU_TPrescaler",
        0x631C: "CIU_TReloadHi",
        0x631D: "CIU_TReloadLo",
        0x631E: "CIU_TCounterHi",
        0x631F: "CIU_TCounterLo",
        0x6321: "CIU_TestSel1",
        0x6322: "CIU_TestSel2",
        0x6323: "CIU_TestPinEn",
        0x6324: "CIU_TestPinValue",
        0x6325: "CIU_TestBus",
        0x6326: "CIU_AutoTest",
        0x6327: "CIU_Version",
        0x6328: "CIU_AnalogTest",
        0x6329: "CIU_TestDAC1",
        0x632A: "CIU_TestDAC2",
        0x632B: "CIU_TestADC",
        0x632C: "CIU_RFT1",
        0x632D: "CIU_RFT2",
        0x632E: "CIU_RFT3",
        0x632F: "CIU_RFT4",
    }
    REGBYNAME = {v: k for k, v in REG.iteritems()}

    class Error(Exception):
        """Chipset.Error"""
        def __init__(self, errno, strerr):
            self.errno, self.strerr = errno, strerr

        def __str__(self):
            return "Error 0x{0:02X}: {1}".format(self.errno, self.strerr)

    def chipset_error(self, cause):
        if cause is None:
            errno = 0xff
        elif type(cause) is int:
            errno = cause
        else:
            errno = cause[0]

        strerr = self.ERR.get(errno, "Unknown error code")
        raise Chipset.Error(errno, strerr)

    def __init__(self, transport, logger):
        self.transport = transport
        self.log = logger

    def command(self, cmd_code, cmd_data, timeout):
        """Send a host command and return the chip response. The chip command
        is selected by the 8-bit integer *cmd_code*. The command
        parameters, if any, are supplied with *cmd_data* as a
        bytearray or byte string. The fully constructed command frame
        is sent with :meth:`write_frame` and the chip acknowledgement
        and response is received with :meth:`read_frame`, those
        methods are used by some drivers for additional framing. The
        implementation waits 100 ms for the command acknowledgement
        and then polls every 100 ms for a response frame until
        *timeout* seconds have elapsed. If the response frame is
        correct and the response code matches *cmd_code* the data
        bytes that follow the response code are returned as a
        bytearray (without the trailing checksum and postamble).

        **Exceptions**

        * :exc:`~exceptions.IOError` :const:`errno.ETIMEDOUT` if no
          response frame was received before *timeout* seconds.

        * :exc:`~exceptions.IOError` :const:`errno.EIO` if response
          frame errors were detected.

        * :exc:`Chipset.Error` if an error response frame or status
          error was received.

        """
        assert len(cmd_data) <= self.host_command_frame_max_size - 2
        self.log.log(logging.DEBUG-1, self.CMD[cmd_code]+" "+hexlify(cmd_data))
        
        if len(cmd_data) < 254:
            head = self.SOF + chr(len(cmd_data)+2) + chr(254-len(cmd_data))
        else:
            head = self.SOF + "\xFF\xFF" + pack(">H", len(cmd_data)+2)
            head.append((256 - sum(head[-2:])) & 0xFF)
        data = bytearray([0xD4, cmd_code]) + cmd_data
        tail = bytearray([(256 - sum(data)) & 0xFF, 0])
        frame = head + data + tail
        
        try:
            self.write_frame(frame)
            frame = self.read_frame(timeout=100)
        except IOError as error:
            self.log.error("input/output error while waiting for ack")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        
        if not frame.startswith(self.SOF):
            self.log.error("invalid frame start sequence")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        
        if frame[0:len(self.ACK)] != self.ACK:
            self.log.warning("missing ack frame")
        else:
            endtime = time.time() + timeout
            while time.time() < endtime:
                try:
                    frame = self.read_frame(timeout=100); break
                except IOError as error:
                    if error.errno != errno.ETIMEDOUT:
                        raise error
            else:
                self.write_frame(self.ACK) # cancel command
                raise IOError(errno.ETIMEDOUT, os.strerror(errno.ETIMEDOUT))
        
        if frame.startswith(self.SOF + "\xFF\xFF"):
            # extended frame
            if sum(frame[5:8]) & 0xFF != 0:
                self.log.error("frame lenght checksum error")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            if unpack(">H", buffer(frame[5:7]))[0] != len(frame) - 10:
                self.log.error("frame lenght value mismatch")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            del frame[0:8]
        elif frame.startswith(self.SOF):
            # normal frame
            if sum(frame[3:5]) & 0xFF != 0:
                self.log.error("frame lenght checksum error")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            if frame[3] != len(frame) - 7:
                self.log.error("frame lenght value mismatch")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            del frame[0:5]
        else:
            self.log.debug("invalid frame start sequence")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if not sum(frame[0:-1]) & 0xFF == 0:
            self.log.error("frame data checksum error")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if frame[0] == 0x7F: # error frame
            self.chipset_error(0x7F)

        if not frame[0] == 0xD5:
            self.log.error("invalid frame identifier")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if not frame[1] == cmd_code + 1:
            self.log.error("unexpected response code")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        return frame[2:-2]

    def write_frame(self, frame):
        """Write a command *frame* to the chipset via the transport write
        method.

        """
        self.transport.write(frame)
        
    def read_frame(self, timeout):
        """Read a response frame from the chipset via the transport read
        method. The *timeout* value is in milliseconds.

        """
        return self.transport.read(timeout)
        
    def diagnose(self, test, test_data=None):
        """Send a Diagnose command. The *test* argument selects the diagnose
        function either by number or the string ``line``, ``rom``, or
        ``ram``. For a ``line`` test the implementation sends the
        longest possible command frame and verifies that the response
        data is identical. For a ``ram`` or ``rom`` test the
        implementation verfies the response status. For a *test*
        number the implementation appends the byte string *test_data*
        and returns the response data bytes.

        """
        if test == "line":
            size = self.host_command_frame_max_size - 3
            data = "\x00" + bytearray([x&0xFF for x in range(size)])
            return self.command(0x00, data, timeout=1.0) == data
        if test == "rom":
            data = self.command(0x00, '\x01', timeout=1.0)
            return data and data[0] == 0
        if test == "ram":
            data = self.command(0x00, '\x02', timeout=1.0)
            return data and data[0] == 0
        return self.command(0x00, chr(test), test_data, timeout=1.0)

    def get_firmware_version(self):
        """Send a GetFirmwareVersion command and return the response data
        bytes.

        """
        return self.command(0x02, '', timeout=0.1)

    def get_general_status(self):
        """Send a GetGeneralStatus command and return the response data
        bytes.

        """
        data = self.command(0x04, '', timeout=0.1)
        if data is None or len(data) < 3:
            raise self.chipset_error(None)
        return data

    def read_register(self, *args):
        """Send a ReadRegister command for the positional register address or
        name arguments. The register values are returned as a list for
        multiple arguments or an integer for a single argument.

        >>> Chipset.read_register(0x6301) == Chipset.read_register("CIU_Mode")
        True
        >>> Chipset.read_register(0x6301, "CIU_TxMode", "CIU_RxMode")
        [0, 0, 0]

        """
        addr = lambda r: self.REGBYNAME[r] if type(r) is str else r
        args = [addr(reg) for reg in args]
        data = ''.join([pack(">H", reg) for reg in args])
        data = self._read_register(data)
        return list(data) if len(data) > 1 else data[0]

    def _read_register(self, data):
        message = "_read_register() must be implemented in subclass"
        raise NotImplementedError(message)

    def write_register(self, *args):
        """Send a WriteRegister command. Each positional argument must be an
        (address, value) tuple except if exactly two arguments are
        supplied as register address and value. A register can also be
        selected by name. There is no return value.

        >>> Chipset.write_register(0x6301, 0x00)
        >>> Chipset.write_register("CIU_Mode", 0x00)
        >>> Chipset.write_register((0x6301, 0x00), ("CIU_TxMode", 0x00))

        """
        assert type(args) in (tuple, list)
        if len(args) == 2 and type(args[1]) == int: args = [args]
        addr = lambda r: self.REGBYNAME[r] if type(r) is str else r
        args = [(addr(reg), val) for reg, val in args]
        data = ''.join([pack(">HB", reg, val) for reg, val in args])
        self._write_register(data)

    def _write_register(self, data):
        message = "_write_register() must be implemented in subclass"
        raise NotImplementedError(message)

    def set_parameters(self, flags):
        """Send a SetParameters command with the 8-bit *flags* integer."""
        self.command(0x12, chr(flags), timeout=0.1)
        
    def rf_configuration(self, cfg_item, cfg_data):
        """Send an RFConfiguration command."""
        self.command(0x32, chr(cfg_item) + bytearray(cfg_data), timeout=0.1)

    def in_jump_for_dep(self, act_pass, br, passive_data, nfcid3, gi):
        """Send an InJumpForDEP command.

        """
        assert act_pass in (False, True)
        assert br in (106, 212, 424)
        assert len(passive_data) in (0, 4, 5)
        assert len(nfcid3) in (0, 10)
        assert len(gi) <= 48
        cm = int(bool(act_pass))
        br = (106, 212, 424).index(br)
        nf = (bool(passive_data) | bool(nfcid3) << 1 | bool(gi) << 2)
        data = chr(cm) + chr(br) + chr(nf) + passive_data + nfcid3 + gi
        data = self.command(0x56, bytearray(data), timeout=3.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[2:]

    def in_jump_for_psl(self, act_pass, br, passive_data, nfcid3, gi):
        """Send an InJumpForPSL command.

        """
        assert act_pass in (False, True)
        assert br in (106, 212, 424)
        assert len(passive_data) in (0, 4, 5)
        assert len(nfcid3) in (0, 10)
        assert len(gi) <= 48
        cm = int(bool(act_pass))
        br = (106, 212, 424).index(br)
        nf = (bool(passive_data) | bool(nfcid3) << 1 | bool(gi) << 2)
        data = chr(cm) + chr(br) + chr(nf) + passive_data + nfcid3 + gi
        data = self.command(0x46, bytearray(data), timeout=3.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[2:]

    def in_list_passive_target(self, max_tg, brty, initiator_data):
        assert max_tg <= self.in_list_passive_target_max_target
        assert brty in self.in_list_passive_target_brty_range
        data = chr(1) + chr(brty) + initiator_data
        data = self.command(0x4A, data, timeout=1.0)
        return data[2:] if data and data[0] > 0 else None

    def in_atr(self, nfcid3i='', gi=''):
        flag = int(bool(nfcid3i)) | (int(bool(gi)) << 1)
        data = chr(1) + chr(flag) + nfcid3i + gi
        data = self.command(0x50, data, timeout=1.5)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[1:]

    def in_psl(self, br_it, br_ti):
        data = bytearray([1, br_it, br_ti])
        data = self.command(0x4E, data, timeout=1.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def in_data_exchange(self, data, timeout, more=False):
        data = self.command(0x40, chr(int(more)<<6 | 0x01) + data, timeout)
        if data is None or data[0] & 0x3f != 0:
            self.chipset_error(data[0] & 0x3f if data else None)
        return data[1:], bool(data[0] & 0x40)

    def in_communicate_thru(self, data, timeout):
        data = self.command(0x42, data, timeout)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[1:]

    def tg_set_general_bytes(self, gb):
        data = self.command(0x92, gb, timeout=0.1)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_get_data(self, timeout):
        data = self.command(0x86, '', timeout)
        if data is None or data[0] & 0x3f != 0:
            self.chipset_error(data[0] & 0x3f if data else None)
        return data[1:], bool(data[0] & 0x40)

    def tg_set_data(self, data, timeout):
        data = self.command(0x8E, data, timeout)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_set_meta_data(self, data, timeout):
        data = self.command(0x94, data, timeout)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_get_initiator_command(self, timeout):
        data = self.command(0x88, '', timeout)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[1:]

    def tg_response_to_initiator(self, data):
        data = self.command(0x90, data, timeout=1.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_get_target_status(self):
        data = self.command(0x8A, '', timeout=0.1)
        if data[0] == 0x01:
            br_tx = (106, 212, 424)[data[1] >> 4 & 7]
            br_rx = (106, 212, 424)[data[1] & 7]
        else:
            br_tx, br_rx = (0, 0)
        return data[0], br_tx, br_rx

class Device(device.Device):
    """Base class for devices with an NXP PN531, PN532, PN533 or Sony
    RC-S956 contactless interface chip. This class implements the
    functionality that is identical or needed by most of the drivers
    that inherit from pn53x.

    """
    def __init__(self, chipset, logger):
        self.chipset = chipset
        self.log = logger
        
        try:
            chipset_communication = self.chipset.diagnose('line')
        except Chipset.Error:
            chipset_communication = False

        if chipset_communication is False:
            self.log.error("chipset communication test failed")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        self.eeprom = bytearray()
        try:
            self.chipset.read_register(0xA000) # check access
            for addr in range(0xA000, 0xA100, 64):
                data = self.chipset.read_register(*range(addr, addr+64))
                self.eeprom.extend(data)
        except Chipset.Error:
            self.log.debug("no eeprom attached")

        if self.eeprom:
            head = "EEPROM  " + ' '.join(["%2X" % i for i in range(16)])
            self.log.debug(head)
            for i in range(0, len(self.eeprom), 16):
                data = ' '.join(["%02X" % x for x in self.eeprom[i:i+16]])
                self.log.debug(('0x%04X: %s' % (0xA000+i, data)))

        for page in range(4):
            self.log.debug("CIU PN512 register page {0}".format(page))
            for line in self._print_ciu_register_page(page):
                self.log.debug(line)

    def mute(self):
        self.chipset.rf_configuration(0x01, chr(0b00000010))

    def sense_tta(self, target):
        brty = {"106A": 0}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        if not target.sdd_req:
            uid = bytearray()
        else:
            if len(target.sdd_req) == 4:
                uid = target.sdd_req
            elif len(target.sdd_req) == 7:
                uid = "\x88" + target.sdd_req
            elif len(target.sdd_req) == 10:
                uid = "\x88" + target.sdd_req[:3] + "\x88" + target.sdd_req[3:]
            else:
                message = "sdd_req must be 4, 7, or 10 bytes"
                self.log.warning(message.format(target.brty))
                raise ValueError(message)

        rsp = self.chipset.in_list_passive_target(1, 0, uid)
        if rsp is not None:
            sens, sel, sdd = rsp[1::-1], rsp[2:3], rsp[4:]
            if sel[0] & 0x60 == 0x00:
                self.log.debug("disable crc check for type 2 tag")
                rxmode = self.chipset.read_register("CIU_RxMode")
                self.chipset.write_register("CIU_RxMode", rxmode & 0x7F)
            return nfc.clf.TTA(106, sens_res=sens, sel_res=sel, sdd_res=sdd)

        if self.chipset.read_register("CIU_FIFOData") == 0x26:
            # If we still see the SENS_REQ command in the CIU FIFO
            # then there was no SENS_RES, thus no tag present.
            return None

        self.log.debug("sens_res but no sdd_res, try as type 1 tag")

        if 4 not in self.chipset.in_list_passive_target_brty_range:
            self.log.warning("The {0} can not read Type 1 Tags.".format(self))
            return None

        rsp = self.chipset.in_list_passive_target(1, 4, "")
        if rsp is not None:
            rid_cmd = bytearray.fromhex("78 0000 00000000")
            try:
                rid_res = self.chipset.in_data_exchange(rid_cmd, 0.01)[0]
                return nfc.clf.TTA(106, sens_res=rsp[1::-1], rid_res=rid_res)
            except Chipset.Error:
                pass

    def sense_ttb(self, target, did=None):
        brty = {"106B": 3, "212B": 6, "424B": 7, "848B": 8}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        afi = target.sens_req[0:1] if target.sens_req else "\x00"
        rsp = self.chipset.in_list_passive_target(1, brty, afi)
        if rsp and rsp[10] & 0b00001001 == 0b00000001:
            # This is an ISO tag and the chipset has now activated it
            # with 64-byte max frame size and maybe a DID. Because we
            # implement ISO-DEP in software and can do without DID and
            # use a full 256 byte response frame size, we'll send a
            # DESELECT and WUPB to allow ATTRIB from the activation
            # code in tags/tt4.py.
            try:
                deselect_command = ("\xCA" + did) if did else "\xC2"
                self.chipset.in_communicate_thru(deselect_command, 0.5)
                rsp = self.chipset.in_communicate_thru("\x05"+afi+"\x08", 0.5)
                if rsp is not None:
                    return nfc.clf.TTB(target.bitrate, sens_res=rsp)
            except (Chipset.Error, IOError) as error:
                self.log.debug(error)

    def sense_ttf(self, target):
        brty = {"212F": 1, "424F": 2}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message); raise ValueError(message)

        if not self.chipset.read_register("CIU_TxControl") & 0b00000011:
            # Some FeliCa cards need more time from power up to
            # polling. If the field was not already activated, do this
            # now and wait about 5 ms.
            self.chipset.rf_configuration(0x01, "\x01"); time.sleep(0.005)
        default_sens_req = bytearray.fromhex("00FFFF0000")
        sens_req = target.sens_req if target.sens_req else default_sens_req
        brty = target.bitrate // 212
        rsp = self.chipset.in_list_passive_target(1, brty, sens_req)
        if rsp is not None:
            return nfc.clf.TTF(target.bitrate, sens_res=rsp[1:])
    
    def sense_dep(self, target, passive_target):
        if passive_target:
            (mode, br) = ("passive", passive_target.bitrate)
            if passive_target.bitrate == 106:
                # set the detect-sync bit for 106 kbps
                self.chipset.write_register("CIU_Mode", 0b01111011)
            data = chr(len(target.atr_req)+1) + target.atr_req
            try:
                data = self.chipset.in_communicate_thru(data, timeout=0.1)
                atr_res = data[1:]
            except Chipset.Error as error:
                self.log.error(error)
                return None
        else:
            (mode, br) = ("active", target.bitrate)
            nfcid3 = target.atr_req[2:12]
            gbytes = target.atr_req[16:]
            try:
                data = self.chipset.in_jump_for_psl(1, br, '', nfcid3, gbytes)
                atr_res = '\xD5\x01' + data
            except Chipset.Error as error:
                if error.errno not in (0x01, 0x0A): self.log.error(error)
                return None

        if target.psl_req and len(target.psl_req) == 5:
            self.log.debug("started DEP in {0} kbps {1} mode".format(br, mode))
            try:
                data = chr(len(target.psl_req)+1) + target.psl_req
                data = self.chipset.in_communicate_thru(data, timeout=0.1)
                psl_res = data[1:]
            except Chipset.Error as error:
                self.log.error(error)
                return None
            
            dsi = target.psl_req[3] >> 3 & 0b111 
            dri = target.psl_req[3] & 0b111
            assert dsi == dri, "send/recv bitrate can not be different"
            br = 106 << dsi
            if passive_target:
                tx_mode = 0b10000000 | (dsi << 4) | ((0b00,0b10)[dsi>0])
                rx_mode = 0b10000000 | (dri << 4) | ((0b00,0b10)[dri>0])
            else:
                tx_mode = 0b10000001 | (dsi << 4)
                rx_mode = 0b10000001 | (dri << 4)
            regs = [("CIU_TxMode", tx_mode), ("CIU_RxMode", rx_mode)]
            # set the detect-sync bit for 106 kbps
            regs.append(("CIU_Mode", 0b01111011 if br==106 else 0b00111011))
            self.chipset.write_register(*regs)

        self.log.debug("running DEP in {0} kbps {1} mode".format(br, mode))
        return nfc.clf.DEP(br, atr_res=atr_res)
        
    @property
    def max_send_data_size(self):
        return self.chipset.host_command_frame_max_size - 2

    @property
    def max_recv_data_size(self):
        return self.chipset.host_command_frame_max_size - 3

    def send_cmd_recv_rsp(self, target, data, timeout):
        timeout_microsec = int(timeout * 1E6)
        try: index = [i+1 for i in range(16) if timeout_microsec>>i <= 100][0]
        except IndexError: index = 16
        timeout_microsec = 100 << (index-1)
        timeout = (100 << (index-1)) / 1E6
        self.log.debug("set response timeout {0:.6f} ms".format(timeout))
        self.chipset.rf_configuration(0x02, bytearray([10, 11, index]))
        try:
            if type(target) is nfc.clf.TTA:
                if target.rid_res is not None: # TT1
                    return self._tt1_send_cmd_recv_rsp(data, timeout+0.1)
                if target.sel_res[0] & 0x60 == 0x00: # TT2
                    return self._tt2_send_cmd_recv_rsp(data, timeout+0.1)
            if type(target) is nfc.clf.DEP and target.bitrate == 106:
                # The 106A start byte is handled by the PN512.
                data = self.chipset.in_communicate_thru(data[1:], timeout+0.1)
                return "\xF0" + data
            return self.chipset.in_communicate_thru(data, timeout+0.1)
        except Chipset.Error as error:
            self.log.debug(error)
            if error.errno == 1: raise nfc.clf.TimeoutError
            else: raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            self.log.debug(error)
            if not error.errno == errno.ETIMEDOUT: raise error
            else: raise nfc.clf.TimeoutError("send_cmd_recv_rsp")

    def _tt1_send_cmd_recv_rsp(self, data, timeout):
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        fname = "._tt1_send_cmd_recv_rsp()"
        raise NotImplementedError("must implement " + cname + fname)

    def _tt2_send_cmd_recv_rsp(self, data, timeout):
        # The Type2Tag implementation needs to receive the Mifare
        # ACK/NAK responses but the chipset reports them as crc error
        # (indistinguishable from a real crc error). We thus have to
        # switch off the crc check and do it here.
        data = self.chipset.in_communicate_thru(data, timeout)
        if len(data) > 2 and self.check_crc_a(data) is False:
            raise nfc.clf.TransmissionError("crc_a check error")
        return data[:-2] if len(data) > 2 else data

    def listen_tta(self, target, timeout):
        if target.bitrate != 106:
            raise ValueError("bitrate can only be 106 kbps")
        for attr in (("sens_res", 2), ("sdd_res", 4), ("sel_res", 1)):
            if eval("target.{0} is None".format(attr[0])):
                raise ValueError("{0} attribute is required".format(attr[0]))
            if eval("len(target.{0}) != {1}".format(*attr)):
                raise ValueError("{0} must be {1} byte".format(*attr))

        tta_params = target.sens_res + target.sdd_res[1:4] + target.sel_res
        regs = [("CIU_FIFOLevel", 0b10000000)] # clear fifo
        regs.extend(zip(25*["CIU_FIFOData"], tta_params+bytearray(18)+"\0"))
        regs.extend([
            ("CIU_Command", 0b00000001), # write the configure command
            ("CIU_Mode",    0b00111111), # b2 - disable mode detector
            ("CIU_FelNFC2", 0b10000000), # b7 - wait until selected
            ("CIU_TxMode",  0b10000000), # 106 kbps Type A framing
            ("CIU_RxMode",  0b10000000), # 106 kbps Type A framing
            ("CIU_Command", 0b00001101), # AutoColl
        ])
        self.chipset.write_register(*regs)
        endtime = time.time() + timeout
        while time.time() < endtime:
            if self.chipset.read_register("CIU_CommIRq") & 0b00100000:
                self.chipset.write_register("CIU_CommIRq", 0b00100000)
                fifo_size = self.chipset.read_register("CIU_FIFOLevel")
                fifo_read = fifo_size * ["CIU_FIFOData"]
                target.cmd = bytearray(self.chipset.read_register(*fifo_read))
                return target

    def listen_ttf(self, target, timeout):
        if target.bitrate not in (212, 424):
            raise ValueError("bitrate can only be 212 or 424 kbps")
        if target.sens_res is None:
            raise ValueError("sens_res attribute is required")
        if len(target.sens_res) not in (17, 19):
            raise ValueError("sens_res must be 16 or 18 bytes")

        ttf_params = bytearray(target.sens_res[1:])
        if len(ttf_params) == 16: ttf_params += "\xFF\xFF"
        regs = [("CIU_FIFOLevel", 0b10000000)] # clear fifo
        regs.extend(zip(25*["CIU_FIFOData"], bytearray(6)+ttf_params+"\0"))
        regs.extend([
            ("CIU_Command", 0b00000001), # write the configure command
            ("CIU_Mode",    0b00111111), # b2 - disable mode detector
            ("CIU_FelNFC2", 0b10000000), # b7 - wait until selected
            ("CIU_TxMode",  0b10000010 | (target.bitrate//212)<<4),
            ("CIU_RxMode",  0b10000010 | (target.bitrate//212)<<4),
            ("CIU_Command", 0b00001101), # AutoColl
        ])
        self.chipset.write_register(*regs)
        endtime = time.time() + timeout
        while time.time() < endtime:
            if self.chipset.read_register("CIU_CommIRq") & 0b00100000:
                self.chipset.write_register("CIU_CommIRq", 0b00100000)
                fifo_size = self.chipset.read_register("CIU_FIFOLevel")
                fifo_read = fifo_size * ["CIU_FIFOData"]
                target.cmd = bytearray(self.chipset.read_register(*fifo_read))
                return target

    def listen_dep(self, target, timeout):
        ttap = target.tta.sens_res+target.tta.sdd_res[1:]+target.tta.sel_res
        ttfp = target.ttf.sens_res[1:]
        mode = 0b00000010 if target.atr_res else 0b00000011

        endtime = time.time() + timeout
        while time.time() < endtime:
            try:
                wait = max(endtime - time.time(), 0.5)
                data = self._init_as_target(mode, ttap, ttfp, wait)
            except IOError as error:
                if error.errno != errno.ETIMEDOUT: raise error
            else:
                if not (data[1]==len(data)-1 and data[2:4]=="\xD4\x00"):
                    info = "expected ATR_REQ but got %s"
                    self.log.debug(info, hexlify(buffer(data, 1)))
                else: break
        else: return

        target.bitrate = 106 << (data[0]>>4)
        target.atr_req = data[2:]
        mode = ("passive", "active")[data[0] & 1]
        if mode == "active":
            del target.tta, target.ttf
        elif target.bitrate == 106:
            target.tta.bitrate = target.bitrate
            target.atr_res = target.tta.atr_res
            del target.ttf, target.tta.atr_res
        else:
            target.ttf.bitrate = target.bitrate
            target.atr_res = target.ttf.atr_res
            del target.tta, target.ttf.atr_res

        info = "activated as DEP target in {0} {1} communication mode"
        self.log.debug(info.format(target.brty, mode))

        try:
            data = self._send_atr_response(target, timeout=0.5)
        except Chipset.Error as error:
            self.log.error(error); return
        except IOError as error:
            if error.errno != errno.ETIMEDOUT: raise
            self.log.debug(error); return
        
        if data and data.startswith("\x06\xD4\x04"): # PSL_REQ
            target.psl_req = data[1:]
            target.psl_res = "\xD5\x05" + target.psl_req[2:3]
            try:
                data = self._send_psl_response(target, timeout=0.5)
            except Chipset.Error as error:
                self.log.error(error); return
            except IOError as error:
                if error.errno != errno.ETIMEDOUT: raise
                self.log.debug(error); return
        
        if data and data[0] == len(data) and data[1:3] == "\xD4\x06":
            target.cmd = ('\xF0','')[target.bitrate>106] + data
            return target

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        classname = self.__class__.__module__ + '.' + self.__class__.__name__
        missing = classname + '._init_as_target()'
        raise NotImplementedError("must implement " + missing)

    def _send_atr_response(self, target, timeout):
        target.atr_res[12] = target.atr_req[12] # copy DID
        self.log.debug("send ATR_RES " + hexlify(target.atr_res))
        data = chr(len(target.atr_res)+1) + target.atr_res
        self.chipset.tg_response_to_initiator(data)
        return self.chipset.tg_get_initiator_command(timeout)

    def _send_psl_response(self, target, timeout):
        dsi = target.psl_req[3] >> 3 & 0b111
        dri = target.psl_req[3] & 0b111
        rx_mode = self.chipset.read_register("CIU_RxMode")
        rx_mode = (rx_mode & 0b10001111) | (dsi << 4)
        if rx_mode & 0b00000011 != 1: # if not active mode
            rx_mode = (rx_mode & 0b11111100) | ((0,2)[dsi>0])
        self.log.debug("set CIU_RxMode to {:08b}".format(rx_mode))
        self.chipset.write_register(("CIU_RxMode", rx_mode))
        self.log.debug("send PSL_RES " + hexlify(target.psl_res))
        data = chr(len(target.psl_res)+1) + target.psl_res
        self.chipset.tg_response_to_initiator(data)
        data = self.chipset.tg_get_initiator_command(timeout)
        tx_mode = self.chipset.read_register("CIU_TxMode")
        tx_mode = (tx_mode & 0b10001111) | (dri << 4)
        if tx_mode & 0b00000011 != 1: # if not active mode
            tx_mode = (tx_mode & 0b11111100) | ((0,2)[dri>0])
        self.log.debug("set CIU_TxMode to {:08b}".format(tx_mode))
        self.chipset.write_register(("CIU_TxMode", tx_mode))
        target.bitrate = (106, 212, 424)[dri]
        return data

    def send_rsp_recv_cmd(self, target, data, timeout):
        try:
            if data: self.chipset.tg_response_to_initiator(data)
            return self.chipset.tg_get_initiator_command(timeout)
        except Chipset.Error as error:
            if error.errno in (0x29, 0x31):
                self.log.debug(error)
                return None # RF-OFF
            else:
                self.log.warning(error)
                raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            if error.errno == errno.ETIMEDOUT:
                self.log.debug(error)
                raise nfc.clf.TimeoutError
            else:
                self.log.error(error)
                raise error # transport broken

    def _print_ciu_register_page(self, *pages):
        lines = list()
        for page in pages:
            base = (0x6331, 0x6301, 0x6311, 0x6321)[page]
            regs = set(self.chipset.REG)
            regs = sorted(regs.intersection(range(base, base+16)))
            vals = self.chipset.read_register(*regs)
            regs = [self.chipset.REG[r] for r in regs]
            for r, v in zip(regs, vals):
                lines.append("{0:16s} {1:08b}b {2:02X}h".format(r, v, v))
        return lines
