# -*- coding: latin-1 -*-

# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""This is not really a device driver but a base module that
implements common functionality for the PN53x family of contactless
interface chips, namely the NXP PN531, PN532, PN533 and the Sony
RC-S956.

"""
import nfc.clf
from . import device

import os
import time
import errno
from binascii import hexlify
from struct import pack, unpack

import logging
log = logging.getLogger(__name__)


class Chipset(object):
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
    REGBYNAME = {v: k for k, v in REG.items()}

    class Error(Exception):
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

    def close(self):
        self.transport.close()
        self.transport = None

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
        if cmd_data is not None:
            assert len(cmd_data) <= self.host_command_frame_max_size - 2
            self.log.log(logging.DEBUG-1, "{} {} {:.3f}".format(
                    self.CMD[cmd_code], hexlify(cmd_data).decode(), timeout))

            if len(cmd_data) < 254:
                head = self.SOF + bytearray([len(cmd_data)+2]) \
                       + bytearray([254-len(cmd_data)])
            else:
                head = self.SOF + b'\xFF\xFF' + pack(">H", len(cmd_data)+2)
                head.append((256 - sum(head[-2:])) & 0xFF)

            data = bytearray([0xD4, cmd_code]) + cmd_data
            tail = bytearray([(256 - sum(data)) & 0xFF, 0])

            try:
                self.write_frame(head + data + tail)
                frame = self.read_frame(timeout=100)
            except IOError:
                self.log.error("input/output error while waiting for ack")
                raise IOError(errno.EIO, os.strerror(errno.EIO))

            if not frame.startswith(self.SOF):
                self.log.error("invalid frame start sequence")
                raise IOError(errno.EIO, os.strerror(errno.EIO))

            if frame[0:len(self.ACK)] != self.ACK:
                self.log.warning("missing ack frame")
        else:
            frame = self.ACK

        if timeout is not None and timeout <= 0:
            return

        while frame == self.ACK:
            try:
                frame = self.read_frame(int(1000 * timeout))
            except IOError as error:
                if error.errno == errno.ETIMEDOUT:
                    self.write_frame(self.ACK)  # cancel command
                    time.sleep(0.001)
                raise error

        if frame.startswith(self.SOF + b'\xFF\xFF'):
            # extended frame
            if sum(frame[5:8]) & 0xFF != 0:
                self.log.error("frame lenght checksum error")
                raise IOError(errno.EIO, os.strerror(errno.EIO))
            if unpack(">H", memoryview(frame[5:7]))[0] != len(frame) - 10:
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

        if not sum(frame) & 0xFF == 0:
            self.log.error("frame data checksum error")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if frame[0] == 0x7F:  # error frame
            self.chipset_error(0x7F)

        if not frame[0] == 0xD5:
            self.log.error("invalid frame identifier")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        if not frame[1] == cmd_code + 1:
            self.log.error("unexpected response code")
            raise IOError(errno.EIO, os.strerror(errno.EIO))

        return frame[2:-2]

    def write_frame(self, frame):
        """Write a command *frame* to the chipset."""
        self.transport.write(frame)

    def read_frame(self, timeout):
        """Wait *timeout* milliseconds to return a chip response frame."""
        return self.transport.read(timeout)

    def send_ack(self):
        # Send an ACK frame, usually to terminate most recent command.
        self.transport.write(Chipset.ACK)

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
            data = b'\x00' + bytearray([x & 0xFF for x in range(size)])
            return self.command(0x00, data, timeout=1.0) == data
        if test == "rom":
            data = self.command(0x00, b'\x01', timeout=1.0)
            return data and data[0] == 0
        if test == "ram":
            data = self.command(0x00, b'\x02', timeout=1.0)
            return data and data[0] == 0
        return self.command(0x00, pack('B', test) + test_data, timeout=1.0)

    def get_firmware_version(self):
        """Send a GetFirmwareVersion command and return the response data
        bytes.

        """
        return self.command(0x02, b'', timeout=0.1)

    def get_general_status(self):
        """Send a GetGeneralStatus command and return the response data
        bytes.

        """
        data = self.command(0x04, b'', timeout=0.1)
        if data is None or len(data) < 3:
            raise self.chipset_error(None)
        return data

    def read_register(self, *args):
        """Send a ReadRegister command for the positional register address or
        name arguments. The register values are returned as a list for
        multiple arguments or an integer for a single argument. ::

          tx_mode = Chipset.read_register(0x6302)
          rx_mode = Chipset.read_register("CIU_RxMode")
          tx_mode, rx_mode = Chipset.read_register("CIU_TxMode", "CIU_RxMode")

        """
        def addr(r):
            return self.REGBYNAME[r] if type(r) is str else r

        args = [addr(reg) for reg in args]
        data = b''.join([pack(">H", reg) for reg in args])
        data = self._read_register(data)
        return list(data) if len(data) > 1 else data[0]

    def _read_register(self, data):
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError(cname + "._read_register")

    def write_register(self, *args):
        """Send a WriteRegister command. Each positional argument must be an
        (address, value) tuple except if exactly two arguments are
        supplied as register address and value. A register can also be
        selected by name. There is no return value. ::

          Chipset.write_register(0x6301, 0x00)
          Chipset.write_register("CIU_Mode", 0x00)
          Chipset.write_register((0x6301, 0x00), ("CIU_TxMode", 0x00))

        """
        def addr(r):
            return self.REGBYNAME[r] if type(r) is str else r

        assert type(args) in (tuple, list)
        if len(args) == 2 and type(args[1]) == int:
            args = [args]
        args = [(addr(reg), val) for reg, val in args]
        data = b''.join([pack(">HB", reg, val) for reg, val in args])
        self._write_register(data)

    def _write_register(self, data):
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError(cname + "._write_register")

    def set_parameters(self, flags):
        """Send a SetParameters command with the 8-bit *flags* integer."""
        self.command(0x12, bytearray([flags]), timeout=0.1)

    def rf_configuration(self, cfg_item, cfg_data):
        """Send an RFConfiguration command."""
        self.command(0x32, bytearray([cfg_item]) + bytearray(cfg_data),
                     timeout=0.1)

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
        data = bytearray([cm, br, nf]) + passive_data + nfcid3 + gi
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
        data = bytearray([cm, br, nf]) + passive_data + nfcid3 + gi
        data = self.command(0x46, data, timeout=3.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)
        return data[2:]

    def in_list_passive_target(self, max_tg, brty, initiator_data):
        assert max_tg <= self.in_list_passive_target_max_target
        assert brty in self.in_list_passive_target_brty_range
        data = bytearray([1, brty]) + initiator_data
        data = self.command(0x4A, data, timeout=1.0)
        return data[2:] if data and data[0] > 0 else None

    def in_atr(self, nfcid3i=b'', gi=b''):
        flag = int(bool(nfcid3i)) | (int(bool(gi)) << 1)
        data = bytearray([1, flag]) + nfcid3i + gi
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
        data = self.command(0x40, bytearray([int(more) << 6 | 0x01]) + data,
                            timeout)
        if data is None or data[0] & 0x3f != 0:
            self.chipset_error(data[0] & 0x3f if data else None)
        return data[1:], bool(data[0] & 0x40)

    def in_communicate_thru(self, data, timeout):
        data = self.command(0x42, data, timeout)
        if timeout > 0:
            if data and data[0] == 0:
                return data[1:]
            else:
                self.chipset_error(data)

    def tg_set_general_bytes(self, gb):
        data = self.command(0x92, gb, timeout=0.1)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_get_data(self, timeout):
        data = self.command(0x86, b'', timeout)
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
        data = self.command(0x88, b'', timeout)
        if timeout > 0:
            if data and data[0] == 0:
                return data[1:]
            else:
                self.chipset_error(data)

    def tg_response_to_initiator(self, data):
        data = self.command(0x90, data, timeout=1.0)
        if data is None or data[0] != 0:
            self.chipset_error(data)

    def tg_get_target_status(self):
        data = self.command(0x8A, b'', timeout=0.1)
        if data[0] == 0x01:
            br_tx = (106, 212, 424)[data[1] >> 4 & 7]
            br_rx = (106, 212, 424)[data[1] & 7]
        else:
            br_tx, br_rx = (0, 0)
        return data[0], br_tx, br_rx


class Device(device.Device):
    # Base class for devices with an NXP PN531, PN532, PN533 or Sony
    # RC-S956 contactless interface chip. This class implements the
    # functionality that is identical or needed by most of the drivers
    # that inherit from pn53x.

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

        # for line in self._print_ciu_register_page(0, 1, 2, 3):
        #     self.log.debug(line)

        # for addr in range(0, 0x03FF, 16):
        #     xram = self.chipset.read_register(*range(addr, addr+16))
        #     xram = ' '.join(["%02X" % x for x in xram])
        #     self.log.debug("0x%04X: %s", addr, xram)

    def close(self):
        self.chipset.close()
        self.chipset = None

    def mute(self):
        self.chipset.rf_configuration(0x01, bytearray([0b00000010]))

    def sense_tta(self, target):
        brty = {"106A": 0}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message)
            raise ValueError(message)

        uid = target.sel_req if target.sel_req else bytearray()
        if len(uid) > 4:
            uid = b'\x88' + uid
        if len(uid) > 8:
            uid = uid[0:4] + b'\x88' + uid[4:]

        rsp = self.chipset.in_list_passive_target(1, 0, uid)
        if rsp is not None:
            sens_res, sel_res, sdd_res = rsp[1::-1], rsp[2:3], rsp[4:]
            if sel_res[0] & 0x60 == 0x00:
                self.log.debug("disable crc check for type 2 tag")
                rxmode = self.chipset.read_register("CIU_RxMode")
                self.chipset.write_register("CIU_RxMode", rxmode & 0x7F)
            return nfc.clf.RemoteTarget(
                "106A", sens_res=sens_res, sel_res=sel_res, sdd_res=sdd_res)

        if self.chipset.read_register("CIU_FIFOData") == 0x26:
            # If we still see the SENS_REQ command in the CIU FIFO
            # then there was no SENS_RES, thus no tag present.
            return None

        self.log.debug("sens_res but no sdd_res, try as type 1 tag")

        if 4 not in self.chipset.in_list_passive_target_brty_range:
            self.log.warning("The {0} can not read Type 1 Tags.".format(self))
            return None

        rsp = self.chipset.in_list_passive_target(1, 4, b"")
        if rsp is not None:
            rid_cmd = bytearray.fromhex("78 0000 00000000")
            try:
                rid_res = self.chipset.in_data_exchange(rid_cmd, 0.01)[0]
                return nfc.clf.RemoteTarget(
                    "106A", sens_res=rsp[1::-1], rid_res=rid_res)
            except Chipset.Error:
                pass

    def sense_ttb(self, target, did=None):
        brty = {"106B": 3, "212B": 6, "424B": 7, "848B": 8}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message)
            raise ValueError(message)

        afi = target.sensb_req[0:1] if target.sensb_req else b'\x00'
        rsp = self.chipset.in_list_passive_target(1, brty, afi)
        if rsp and rsp[10] & 0b00001001 == 0b00000001:
            # This is an ISO tag and the chipset has now activated it
            # with 64-byte max frame size and maybe a DID. Because we
            # implement ISO-DEP in software and can do without DID and
            # use a full 256 byte response frame size, we'll send a
            # DESELECT and WUPB to allow ATTRIB from the activation
            # code in tags/tt4.py.
            try:
                deselect_command = (b'\xCA' + did) if did else b'\xC2'
                wupb_command = b'\x05' + afi + b'\x08'
                self.chipset.in_communicate_thru(deselect_command, 0.5)
                rsp = self.chipset.in_communicate_thru(wupb_command, 0.5)
                return nfc.clf.RemoteTarget(target.brty, sensb_res=rsp)
            except (Chipset.Error, IOError) as error:
                self.log.debug(error)

    def sense_ttf(self, target):
        brty = {"212F": 1, "424F": 2}.get(target.brty)
        if brty not in self.chipset.in_list_passive_target_brty_range:
            message = "unsupported bitrate {0}".format(target.brty)
            self.log.warning(message)
            raise ValueError(message)

        if not self.chipset.read_register("CIU_TxControl") & 0b00000011:
            # Some FeliCa cards need more time from power up to
            # polling. If the field was not already activated, do this
            # now and wait about 5 ms.
            self.chipset.rf_configuration(0x01, b'\x01')
            time.sleep(0.005)

        default_sensf_req = bytearray.fromhex("00FFFF0100")
        sensf_req = target.sensf_req if target.sensf_req else default_sensf_req
        rsp = self.chipset.in_list_passive_target(1, brty, sensf_req)
        if rsp is not None:
            return nfc.clf.RemoteTarget(target.brty, sensf_res=rsp[1:])

    def sense_dep(self, target):
        # Attempt active communication mode target activation.
        assert target.atr_req, "the target.atr_req attribute is required"
        assert len(target.atr_req) >= 16, "minimum lenght of atr_req is 16"
        assert len(target.atr_req) <= 64, "maximum lenght of atr_req is 64"

        # bitrate and modulation type for send/recv must be set and equal
        assert target.brty_send and target.brty_recv
        assert target.brty_send == target.brty_recv

        br = int(target.brty[0:-1])
        nfcid3 = target.atr_req[2:12]
        gbytes = target.atr_req[16:]
        try:
            data = self.chipset.in_jump_for_psl(1, br, b'', nfcid3, gbytes)
            atr_res = b'\xD5\x01' + data
        except Chipset.Error as error:
            if error.errno not in (0x01, 0x0A):
                self.log.error(error)
            return None
        finally:
            # unset the detect-sync bit, 106A sync byte is handled in dep.py
            self.chipset.write_register("CIU_Mode", 0b00111011)

        self.log.debug("running DEP in {0} kbps active mode".format(br))
        return nfc.clf.RemoteTarget(target.brty, atr_res=atr_res,
                                    atr_req=target.atr_req)

    def get_max_send_data_size(self, target):
        return self.chipset.host_command_frame_max_size - 2

    def get_max_recv_data_size(self, target):
        return self.chipset.host_command_frame_max_size - 3

    def send_cmd_recv_rsp(self, target, data, timeout):
        def bitrate(brty):
            return [106 << i for i in range(6)].index(int(brty[:-1]))

        def framing(brty):
            return {'A': 0b00, 'B': 0b11, 'F': 0b10}[brty[-1:]]

        # Set bitrate and modulation type for send and receive.
        acm = target.atr_res and not (target.sens_res or target.sensf_res)
        reg = ("CIU_TxMode", "CIU_RxMode", "CIU_TxAuto")
        txm, rxm, txa = self.chipset.read_register(*reg)
        txm = (txm & 0b10001111) | (bitrate(target.brty_send) << 4)
        rxm = (rxm & 0b10001111) | (bitrate(target.brty_recv) << 4)
        txm = (txm & 0b11111100) | (0b01 if acm else framing(target.brty_send))
        rxm = (rxm & 0b11111100) | (0b01 if acm else framing(target.brty_recv))
        txa = (txa & 0b10111111) | (target.brty_send.endswith("A") << 6)
        reg = (("CIU_TxMode", txm), ("CIU_RxMode", rxm), ("CIU_TxAuto", txa))
        self.chipset.write_register(*reg)

        # Calculate the timeout index for InCommunicateThru. The
        # effective timeout is T(us) = 100 * 2**(n-1) for 1 <= n <= 16
        # and "no timeout" for n = 0. For a given timeout we calculate
        # the index as the first effective timeout that is longer.
        timeout_microsec = int(timeout * 1E6)
        try:
            index = [i+1 for i in range(16) if timeout_microsec >> i <= 100][0]
        except IndexError:
            index = 16
        timeout_microsec = 100 << (index-1)
        timeout = (100 << (index-1)) / 1E6
        self.log.log(logging.DEBUG-1, "set response timeout %.6f sec", timeout)
        self.chipset.rf_configuration(0x02, bytearray([10, 11, index]))

        # Send the command data and return the response. All cases
        # where a response is not received raise either an IOError
        # or one of the nfc.clf.CommunicationError specializations.
        data = bytearray(data) if not isinstance(data, bytearray) else data
        try:
            if target.sens_res and not target.atr_res:
                if target.rid_res:  # TT1
                    return self._tt1_send_cmd_recv_rsp(data, timeout+0.1)
                if target.sel_res[0] & 0x60 == 0x00:  # TT2
                    return self._tt2_send_cmd_recv_rsp(data, timeout+0.1)
            return self.chipset.in_communicate_thru(data, timeout+0.1)
        except Chipset.Error as error:
            self.log.debug(error)
            if error.errno == 1:
                raise nfc.clf.TimeoutError
            else:
                raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            self.log.debug(error)
            if not error.errno == errno.ETIMEDOUT:
                raise error
            else:
                raise nfc.clf.TimeoutError("send_cmd_recv_rsp")

    def _tt1_send_cmd_recv_rsp(self, data, timeout):
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError(cname + "._tt1_send_cmd_recv_rsp()")

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
        if target.brty != "106A":
            info = "unsupported bitrate/type: %r" % target.brty
            raise nfc.clf.UnsupportedTargetError(info)
        if target.rid_res:
            info = "listening for type 1 tag activation is not supported"
            raise nfc.clf.UnsupportedTargetError(info)
        try:
            assert target.sens_res is not None, "sens_res is required"
            assert target.sdd_res is not None, "sdd_res is required"
            assert target.sel_res is not None, "sel_res is required"
            assert len(target.sens_res) == 2, "sens_res must be 2 byte"
            assert len(target.sdd_res) == 4, "sdd_res must be 4 byte"
            assert len(target.sel_res) == 1, "sel_res must be 1 byte"
            assert target.sdd_res[0] == 0x08, "sdd_res[0] must be 08h"
        except AssertionError as error:
            raise ValueError(str(error))

        nfcf_params = bytearray(range(18))
        nfca_params = target.sens_res + target.sdd_res[1:4] + target.sel_res
        self.log.debug("nfca_params %s", hexlify(nfca_params).decode())

        # We can use TgInitAsTarget to exclusively answer Type A
        # activation when the CIU automatic mode detector is disabled
        # (the firmware does not unset or even check this bit). When
        # TgInitAsTarget prepares for AutoColl, the firmware also sets
        # the CIU_TxMode and CIU_RXMode to 106A.
        self.chipset.write_register("CIU_Mode", 0b00111111)

        time_to_return = time.time() + timeout
        while time.time() < time_to_return:
            try:
                wait = max(time_to_return - time.time(), 0.5)
                args = (1, nfca_params, nfcf_params, wait)
                data = self._init_as_target(*args)
            except IOError as error:
                if error.errno != errno.ETIMEDOUT:
                    raise error
                else:
                    return None

            brty = ("106A", "212F", "424F")[(data[0] & 0x70) >> 4]
            self.log.debug("%s rcvd %s",
                           brty, hexlify(memoryview(data)[1:]).decode())
            if brty != target.brty or len(data) < 2:
                log.debug("received bitrate does not match %s", target.brty)
                continue

            if target.sel_res[0] & 0x60 == 0x00:
                self.log.debug("rcvd TT2_CMD %s",
                               hexlify(memoryview(data)[1:]).decode())
                target = nfc.clf.LocalTarget(brty, tt2_cmd=data[1:])
                target.sens_res = nfca_params[0:2]
                target.sdd_res = b'\x08' + nfca_params[2:5]
                target.sel_res = nfca_params[5:6]
                return target

            elif target.sel_res[0] & 0x20 == 0x20 and data[1] == 0xE0:
                default_rats_res = bytearray.fromhex("05 78 80 70 02")
                (rats_cmd, rats_res) = (data[1:], target.rats_res)
                if not rats_res:
                    rats_res = default_rats_res
                self.log.debug("rcvd RATS_CMD %s", hexlify(rats_cmd).decode())
                self.log.debug("send RATS_RES %s", hexlify(rats_res).decode())
                try:
                    self.chipset.tg_response_to_initiator(rats_res)
                    data = self.chipset.tg_get_initiator_command(1.0)
                except (Chipset.Error, IOError) as error:
                    self.log.error(error)
                    return
                if data and data[0] & 0xF0 == 0xC0:  # S(DESELECT)
                    self.log.debug("rcvd S(DESELECT) %s",
                                   hexlify(data).decode())
                    self.log.debug("send S(DESELECT) %s",
                                   hexlify(data).decode())
                    self.chipset.tg_response_to_initiator(data)
                elif data:
                    self.log.debug("rcvd TT4_CMD %s",
                                   hexlify(data).decode())
                    target = nfc.clf.LocalTarget(brty, tt4_cmd=data)
                    target.sens_res = nfca_params[0:2]
                    target.sdd_res = b'\x08' + nfca_params[2:5]
                    target.sel_res = nfca_params[5:6]
                    return target

            elif (target.sel_res[0] & 0x40 and data[1] == 0xF0
                  and len(data) >= 19 and data[2] == len(data)-2
                  and data[3:5] == b'\xD4\x00'):
                self.log.debug("rcvd ATR_REQ %s",
                               hexlify(memoryview(data)[3:]).decode())
                target = nfc.clf.LocalTarget(brty, atr_req=data[3:])
                target.sens_res = nfca_params[0:2]
                target.sdd_res = b'\x08' + nfca_params[2:5]
                target.sel_res = nfca_params[5:6]
                return target

    def listen_ttf(self, target, timeout):
        # For NFC-F listen we can not use TgInitAsTarget because it
        # always sets CIU_TxMode and CIU_RxMode to 106A. Best we can
        # do is to program the CIU AutoColl command and then work with
        # the CIU to receive tag commands in _tt3_send_rsp_recv_cmd
        # (InCommunicateThru does not work probably because the
        # firmware is not in target state). With the 64-bit only CIU
        # FIFO it means that a tag can only allow two blocks for read
        # and write.
        if target.brty not in ("212F", "424F"):
            info = "unsupported bitrate/type: %r" % target.brty
            raise nfc.clf.UnsupportedTargetError(info)
        try:
            assert target.sensf_res is not None, "sensf_res is required"
            assert len(target.sensf_res) == 19, "sensf_res must be 19 byte"
        except AssertionError as error:
            raise ValueError(str(error))

        nfca_params = bytearray(6)
        nfcf_params = bytearray(target.sensf_res[1:])
        self.log.debug("nfcf_params %s", hexlify(nfcf_params).decode())

        regs = [
            ("CIU_Command",   0b00000000),  # Idle command
            ("CIU_FIFOLevel", 0b10000000),  # clear fifo
        ]
        regs.extend(zip(25*["CIU_FIFOData"],
                        nfca_params + nfcf_params + b"\0"))
        regs.append(("CIU_Command", 0b00000001))  # Configure command
        self.chipset.write_register(*regs)
        regs = [
            ("CIU_Control",   0b00000000),  # act as target (b4=0)
            ("CIU_Mode",      0b00111111),  # disable mode detector (b2=1)
            ("CIU_FelNFC2",   0b10000000),  # wait until selected (b7=1)
            ("CIU_TxMode",    0b10000010 | (int(target.brty[:-1])//212) << 4),
            ("CIU_RxMode",    0b10001010 | (int(target.brty[:-1])//212) << 4),
            ("CIU_TxControl", 0b10000000),  # disable output on TX1/TX2
            ("CIU_TxAuto",    0b00100000),  # wake up when rf level detected
            ("CIU_Demod",     0b01100001),  # use Q channel, freeze PLL in recv
            ("CIU_CommIRq",   0b01111111),  # clear interrupt request bits
            ("CIU_DivIRq",    0b01111111),  # clear interrupt request bits
            ("CIU_Command",   0b00001101),  # AutoColl command
        ]
        self.chipset.write_register(*regs)

        regs = ("CIU_Status1", "CIU_Status2", "CIU_CommIRq", "CIU_DivIRq")
        time_to_return = time.time() + timeout
        while time.time() < time_to_return:
            time.sleep(0.01)
            status1, status2, commirq, divirq \
                = self.chipset.read_register(*regs)
            if commirq & 0b00110000 == 0b00110000:
                self.chipset.write_register("CIU_CommIRq", 0b00110000)
                fifo_size = self.chipset.read_register("CIU_FIFOLevel")
                fifo_read = fifo_size * ["CIU_FIFOData"]
                fifo_data = bytearray(self.chipset.read_register(*fifo_read))
                if fifo_data and len(fifo_data) == fifo_data[0]:
                    self.log.debug("%s rcvd %s", target.brty,
                                   hexlify(fifo_data).decode())
                    if fifo_data[2:10] == nfcf_params[0:8]:
                        target = nfc.clf.LocalTarget(target.brty)
                        target.sensf_res = b'\x01' + nfcf_params
                        target.tt3_cmd = fifo_data[1:]
                        return target
                # Restart the AutoColl command.
                self.chipset.write_register("CIU_Command", 0b00001101)
        self.chipset.write_register("CIU_Command", 0)  # Idle command

    def listen_dep(self, target, timeout):
        assert target.sensf_res is not None
        assert target.sens_res is not None
        assert target.sdd_res is not None
        assert target.sel_res is not None
        assert target.atr_res is not None

        nfca_params = target.sens_res + target.sdd_res[1:4] + target.sel_res
        nfcf_params = target.sensf_res[1:19]
        self.log.debug("nfca_params %s", hexlify(nfca_params).decode())
        self.log.debug("nfcf_params %s", hexlify(nfcf_params).decode())
        assert len(nfca_params) == 6
        assert len(nfcf_params) == 18

        # enable the automatic mode detector (b2 <= 0)
        self.chipset.write_register(
            ("CIU_Mode",    0b01111011),  # b2 - enable mode detector
            ("CIU_TxMode",  0b10110000),  # 848 kbps Type A framing
            ("CIU_RxMode",  0b10110000))  # 848 kbps Type A framing

        time_to_return = time.time() + timeout
        while time.time() < time_to_return:
            try:
                wait = max(time_to_return - time.time(), 0.5)
                data = self._init_as_target(2, nfca_params, nfcf_params, wait)
            except IOError as error:
                if error.errno != errno.ETIMEDOUT:
                    raise error
            else:
                if not (data[1] == len(data)-1 and data[2:4] == b'\xD4\x00'):
                    self.log.debug("expected ATR_REQ but got %s",
                                   hexlify(memoryview(data)[1:]).decode())
                else:
                    break
        else:
            return

        brty = ("106A", "212F", "424F")[(data[0] & 0b01110000) >> 4]
        mode = ("passive", "active")[data[0] & 1]
        self.log.debug("activated in %s %s communication mode", brty, mode)

        atr_req = data[2:]
        atr_res = target.atr_res[:]
        atr_res[12] = atr_req[12]  # copy DID
        activation_params = ((nfca_params if brty == "106A" else nfcf_params)
                             if mode == "passive" else None)

        try:
            self.log.debug("%s send ATR_RES %s", brty,
                           hexlify(atr_res).decode())
            data = self._send_atr_response(atr_res, timeout=1.0)
        except Chipset.Error as error:
            self.log.error(error)
            return
        except IOError as error:
            if error.errno != errno.ETIMEDOUT:
                raise
            self.log.debug(error)
            return

        psl_req = psl_res = None
        if data and data.startswith(b'\x06\xD4\x04'):
            self.log.debug("%s rcvd PSL_REQ %s", brty,
                           hexlify(memoryview(data)[1:]).decode())
            try:
                psl_req = data[1:]
                assert len(psl_req) == 5, "psl_req length mismatch"
                assert psl_req[2] == atr_req[12], "psl_req has wrong did"
            except AssertionError as error:
                log.debug(str(error))
                return None
            try:
                psl_res = b'\xD5\x05' + psl_req[2:3]
                self.log.debug("%s send PSL_RES %s", brty,
                               hexlify(psl_res).decode())
                brty = self._send_psl_response(psl_req, psl_res, timeout=0.5)
                data = self.chipset.tg_get_initiator_command(timeout)
            except Chipset.Error as error:
                self.log.error(error)
                return
            except IOError as error:
                if error.errno != errno.ETIMEDOUT:
                    raise
                self.log.debug(error)
                return

        if data and data[0] == len(data) and data[1:3] == b'\xD4\x06':
            # set detect-sync bit to 0, the 106A sync byte is handled by dep.py
            self.chipset.write_register("CIU_Mode", 0b00111011)
            # prepare the target description to return, exact content
            # depends on how we were activated (A or F with or w/o PSL)
            target = nfc.clf.LocalTarget(brty, dep_req=data[1:])
            target.atr_req, target.atr_res = atr_req, atr_res
            if psl_req:
                target.psl_req = psl_req
            if psl_res:
                target.psl_res = psl_res
            if activation_params == nfca_params:
                target.sens_res = nfca_params[0:2]
                target.sdd_res = b'\x08' + nfca_params[2:5]
                target.sel_res = nfca_params[5:6]
            if activation_params == nfcf_params:
                target.sensf_res = b'\x01' + nfcf_params
            return target

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError(cname + '._init_as_target()')

    def _send_atr_response(self, atr_res, timeout):
        self.chipset.tg_response_to_initiator(
                bytearray([len(atr_res)+1]) + atr_res)
        return self.chipset.tg_get_initiator_command(timeout)

    def _send_psl_response(self, psl_req, psl_res, timeout):
        dsi = psl_req[3] >> 3 & 0b111
        dri = psl_req[3] & 0b111
        rx_mode = self.chipset.read_register("CIU_RxMode")
        rx_mode = (rx_mode & 0b10001111) | (dsi << 4)
        if rx_mode & 0b00000011 != 1:  # if not active mode
            rx_mode = (rx_mode & 0b11111100) | ((0, 2)[dsi > 0])
        self.log.debug("set CIU_RxMode to {:08b}".format(rx_mode))
        self.chipset.write_register(("CIU_RxMode", rx_mode))
        self.log.debug("send PSL_RES %s", hexlify(psl_res).decode())
        data = bytearray([len(psl_res)+1]) + psl_res
        self.chipset.tg_response_to_initiator(data)
        tx_mode = self.chipset.read_register("CIU_TxMode")
        tx_mode = (tx_mode & 0b10001111) | (dri << 4)
        if tx_mode & 0b00000011 != 1:  # if not active mode
            tx_mode = (tx_mode & 0b11111100) | ((0, 2)[dri > 0])
        self.log.debug("set CIU_TxMode to {:08b}".format(tx_mode))
        self.chipset.write_register(("CIU_TxMode", tx_mode))
        return ("106A", "212F", "424F")[dri]

    def _tt3_send_rsp_recv_cmd(self, target, data, timeout):
        regs = [
            ("CIU_FIFOLevel", 0b10000000),  # clear fifo read/write pointer
            ("CIU_CommIRq",   0b01111111),  # clear interrupt request bits
            ("CIU_DivIRq",    0b01111111),  # clear interrupt request bits
        ]
        if data is not None:
            regs.extend(zip(len(data)*["CIU_FIFOData"], data))
            regs.append(("CIU_BitFraming", 0b10000000))  # StartSend (b7=1)
        self.chipset.write_register(*regs)

        irq_regs = ("CIU_CommIRq", "CIU_DivIRq")
        time_to_return = time.time() + (timeout if timeout else 0)
        while timeout is None or time.time() < time_to_return:
            time.sleep(0.01)
            commirq, divirq = self.chipset.read_register(*irq_regs)
            if divirq & 0b00000001:
                raise nfc.clf.BrokenLinkError("external field switched off")
            if commirq & 0b00100000:
                self.chipset.write_register("CIU_CommIRq", 0b00100000)
                fifo_size = self.chipset.read_register("CIU_FIFOLevel")
                fifo_read = fifo_size * ["CIU_FIFOData"]
                fifo_data = bytearray(self.chipset.read_register(*fifo_read))
                if fifo_data[0] != len(fifo_data):
                    raise nfc.clf.TransmissionError("frame length byte error")
                return fifo_data
        if timeout > 0:
            info = "no data received within %.3f s" % timeout
            self.log.debug(info)
            raise nfc.clf.TimeoutError(info)

    def send_rsp_recv_cmd(self, target, data, timeout):
        # print("\n".join(self._print_ciu_register_page(0, 1)))
        if target.tt3_cmd:
            return self._tt3_send_rsp_recv_cmd(target, data, timeout)
        try:
            if data:
                self.chipset.tg_response_to_initiator(data)
            return self.chipset.tg_get_initiator_command(timeout)
        except Chipset.Error as error:
            if error.errno in (0x0A, 0x29, 0x31):
                self.log.debug("Error: %s", error)
                raise nfc.clf.BrokenLinkError(str(error))
            else:
                self.log.warning(error)
                raise nfc.clf.TransmissionError(str(error))
        except IOError as error:
            if error.errno == errno.ETIMEDOUT:
                info = "no data received within %.3f s" % timeout
                self.log.debug(info)
                raise nfc.clf.TimeoutError(info)
            else:
                # host-controller communication broken
                self.log.error(error)
                raise error

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


def init(transport):
    log.warning("pn53x is not a driver module, use pn531, pn532, or pn533")
    raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
