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
"""Driver module for contactless devices based on the NXP PN533
chipset. The PN533 is pretty similar to the PN532 except that it also
has a USB host interface option and, probably due to the resources
needed for USB, does not support two simultaneous targets. Anything
else said about PN532 also applies to PN533.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes
sense_ttb   yes
sense_ttf   yes
sense_dep   yes
listen_tta  yes
listen_ttb  no
listen_ttf  yes      Maximimum frame size is 64 byte
listen_dep  yes
==========  =======  ============

"""
import nfc.clf
from . import pn53x

import time

import logging
log = logging.getLogger(__name__)


class Chipset(pn53x.Chipset):
    CMD = {
        # Miscellaneous
        0x00: "Diagnose",
        0x02: "GetFirmwareVersion",
        0x04: "GetGeneralStatus",
        0x06: "ReadRegister",
        0x08: "WriteRegister",
        0x0C: "ReadGPIO",
        0x0E: "WriteGPIO",
        0x12: "SetParameters",
        0x18: "AlparCommandForTDA",
        # RF Communication
        0x32: "RFConfiguration",
        0x58: "RFRegulationTest",
        # Initiator
        0x56: "InJumpForDEP",
        0x46: "InJumpForPSL",
        0x4A: "InListPassiveTarget",
        0x50: "InATR",
        0x4E: "InPSL",
        0x40: "InDataExchange",
        0x42: "InCommunicateThru",
        0x38: "InQuartetByteExchange",
        0x44: "InDeselect",
        0x52: "InRelease",
        0x54: "InSelect",
        0x48: "InActivateDeactivatePaypass",
        # Target
        0x8C: "TgInitAsTarget",
        0x92: "TgSetGeneralBytes",
        0x86: "TgGetData",
        0x8E: "TgSetData",
        0x96: "TgSetDataSecure",
        0x94: "TgSetMetaData",
        0x98: "TgSetMetaDataSecure",
        0x88: "TgGetInitiatorCommand",
        0x90: "TgResponseToInitiator",
        0x8A: "TgGetTargetStatus",
    }
    ERR = {
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
        0x18: "Target or Initiator does not support NFC Secure",
        0x19: "I2C bus line is busy, a TDA transaction is ongoing",
        0x23: "ISO/IEC14443-3 UID check byte is wrong",
        0x25: "Command invalid in current DEP state",
        0x26: "Operation not allowed in this configuration",
        0x27: "Command is not acceptable due to the current context",
        0x29: "Released by Initiator while operating as Target",
        0x2A: "ISO/IEC14443-3B, the ID of the card does not match",
        0x2B: "ISO/IEC14443-3B, card previously activated has disappeared",
        0x2C: "NFCID3i and NFCID3t mismatch in DEP 212/424 kbps passive",
        0x2D: "An over-current event has been detected",
        0x2E: "NAD missing in DEP frame",
        0x7f: "Invalid command syntax - received error frame",
        0xff: "Insufficient data received from executing chip command",
    }

    host_command_frame_max_size = 265
    in_list_passive_target_max_target = 1
    in_list_passive_target_brty_range = (0, 1, 2, 3, 4, 6, 7, 8)

    def get_general_status(self):
        data = super(Chipset, self).get_general_status()
        err = self.ERR.get(data[0], "error code 0x%02X" % data[0])
        field = ("", "external field detected")[data[1]]
        if data[2] == 1:
            br_rx = (106, 212, 424, 848)[data[4]]
            br_tx = (106, 212, 424, 848)[data[5]]
            mtype = {0: "A/B", 1: "Active", 2: "Jewel", 16: "FeliCa"}[data[6]]
            return err, field, (data[3], br_rx, br_tx, mtype)
        else:
            return err, field, None

    def _read_register(self, data):
        data = self.command(0x06, data, timeout=0.25)
        if data[0] != 0:
            self.chipset_error(data)
        return data[1:]

    def _write_register(self, data):
        data = self.command(0x08, data, timeout=0.25)
        if data[0] != 0:
            self.chipset_error(data)

    def tg_init_as_target(self, mode, mifare_params, felica_params,
                          nfcid3t, gt, tk, timeout):
        assert type(mode) is int and mode & 0b11111100 == 0
        assert len(mifare_params) == 6
        assert len(felica_params) == 18
        assert len(nfcid3t) == 10

        data = (bytearray([mode]) + mifare_params + felica_params + nfcid3t +
                bytearray([len(gt)]) + gt + bytearray([len(tk)]) + tk)
        return self.command(0x8c, data, timeout)


class Device(pn53x.Device):
    # Device driver for PN533 based contactless frontends.

    def __init__(self, chipset, logger):
        assert isinstance(chipset, Chipset)
        super(Device, self).__init__(chipset, logger)

        ic, ver, rev, support = self.chipset.get_firmware_version()
        self._chipset_name = "PN5{0:02x}v{1}.{2}".format(ic, ver, rev)
        self.log.debug("chipset is a {0}".format(self._chipset_name))

        self.mute()
        self.chipset.rf_configuration(0x02, b"\x00\x0B\x0A")
        self.chipset.rf_configuration(0x04, b"\x00")
        self.chipset.rf_configuration(0x05, b"\x01\x00\x01")
        self.chipset.set_parameters(0b00000000)

        self.eeprom = bytearray()
        try:
            self.chipset.read_register(0xA000)  # check access
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
        else:
            self.log.debug("no eeprom attached")

        self.log.debug("write analog settings for Type A 106 kbps")
        data = bytearray.fromhex("5A F4 3F 11 4D 85 61 6F 26 62 87")
        self.chipset.rf_configuration(0x0A, data)

        self.log.debug("write analog settings for Type F 212/424 kbps")
        data = bytearray.fromhex("6A FF 3F 10 41 85 61 6F")
        self.chipset.rf_configuration(0x0B, data)

        self.log.debug("write analog settings for Type B 106 kbps")
        data = bytearray.fromhex("FF 04 85")
        self.chipset.rf_configuration(0x0C, data)

        self.log.debug("write analog settings for 14443-4 212/424/848 kbps")
        data = bytearray.fromhex("85 15 8A 85 0A B2 85 04 DA")
        self.chipset.rf_configuration(0x0D, data)

    def close(self):
        self.mute()
        super(Device, self).close()

    def sense_tta(self, target):
        """Activate the RF field and probe for a Type A Target.

        The PN533 can discover all kinds of Type A Targets (Type 1
        Tag, Type 2 Tag, and Type 4A Tag) at 106 kbps.

        """
        return super(Device, self).sense_tta(target)

    def sense_ttb(self, target):
        """Activate the RF field and probe for a Type B Target.

        The PN533 can discover Type B Targets (Type 4B Tag) at 106,
        212, 424, and 848 kbps. The PN533 automatically sends an
        ATTRIB command that configures a 64 byte maximum frame
        size. The driver reverts this configuration with a DESELECT
        and WUPB command to return the target prepared for activation.

        """
        return super(Device, self).sense_ttb(target)

    def sense_ttf(self, target):
        """Activate the RF field and probe for a Type F Target.

        The PN533 can discover Type F Targets (Type 3 Tag) at 212 and
        424 kbps.

        """
        return super(Device, self).sense_ttf(target)

    def sense_dep(self, target):
        """Search for a DEP Target in active communication mode."""
        return super(Device, self).sense_dep(target)

    def send_cmd_recv_rsp(self, target, data, timeout):
        """Send command *data* to the remote *target* and return the response
        data if received within *timeout* seconds.

        """
        return super(Device, self).send_cmd_recv_rsp(target, data, timeout)

    def _tt1_send_cmd_recv_rsp(self, data, timeout):
        # Special handling for Tag Type 1 (Jewel/Topaz) card commands.

        if data[0] in (0x00, 0x01, 0x1A, 0x53, 0x72):
            # RALL, READ, WRITE-NE, WRITE-E, RID are properly
            # implemented by the PN533 firmware.
            return self.chipset.in_data_exchange(data, timeout)[0]

        if data[0] == 0x10:
            # RSEG implementation does not accept any segment other
            # than 0. Unfortunately we can not directly issue this
            # command to the CIU because the response is 128 byte and
            # we're not fast enough to read it from the 64 byte FIFO.
            rsp = data[1:2]
            for block in range((data[1] >> 4) * 16, (data[1] >> 4) * 16 + 16):
                cmd = bytearray([0x02, block]) + data[2:]
                rsp += self._tt1_send_cmd_recv_rsp(cmd, timeout)[1:9]
            return rsp

        # Remaining commands READ8, WRITE-E8, WRITE-NE8 are not
        # implemented by the chipset. Fortunately we can directly
        # program the CIU through register read/write. Each TT1
        # command byte must be send as a separate Type A frame, the
        # first is a short frame with only 7 data bits and the others
        # are normal frames. Reading is also a bit complicated because
        # for sending we have to disable the parity generator which
        # means that we will also receive the parity bits, thus 9 bits
        # received per 8 data bits. And because they are already
        # reversed in the FIFO we must swap before parity removal and
        # afterwards (maybe this could be a bit more optimized).
        data = self.add_crc_b(data)
        self.chipset.write_register(
            ("CIU_FIFOData", data[0]),  # CMD_CODE
            ("CIU_ManualRCV",  0x10),   # ParityDisable
            ("CIU_BitFraming", 0x07),   # 7 bits
            ("CIU_Command",    0x04),   # Transmit
        )
        for i in range(1, len(data)-1):
            self.chipset.write_register(
                ("CIU_FIFOData", data[i]),  # CMD_DATA
                ("CIU_BitFraming", 0x00),   # 8 bits
                ("CIU_Command",    0x04),   # Transmit
            )
        self.chipset.write_register(
            ("CIU_FIFOData", data[-1]),  # CMD_DATA
            ("CIU_Command",    0x0C),    # Transceive
            ("CIU_BitFraming", 0x80),    # 8 bits, start send
        )
        if data[0] == 0x54:  # WRITE-E8
            time.sleep(0.006)  # assuming same response time as WRITE-E
        if data[0] == 0x1B:  # WRITE-NE8
            time.sleep(0.003)  # assuming same response time as WRITE-NE
        self.chipset.write_register(("CIU_ManualRCV", 0x00))  # enable parity
        fifo_level = self.chipset.read_register("CIU_FIFOLevel")
        if fifo_level == 0:
            raise nfc.clf.TimeoutError
        data = self.chipset.read_register(*(fifo_level * ["CIU_FIFOData"]))
        data = ''.join(["{:08b}".format(octet)[::-1] for octet in data])
        data = [int(data[i:i+8][::-1], 2) for i in range(0, len(data)-8, 9)]
        if self.check_crc_b(data) is False:
            raise nfc.clf.TransmissionError("crc_b check error")
        return bytearray(data[:-2])

    def listen_tta(self, target, timeout):
        """Listen *timeout* seconds for a Type A activation at 106 kbps. The
        ``sens_res``, ``sdd_res``, and ``sel_res`` response data must
        be provided and ``sdd_res`` must be a 4 byte UID that starts
        with ``08h``. Depending on ``sel_res`` an activation may
        return a target with a ``tt2_cmd``, ``tt4_cmd`` or ``atr_req``
        attribute. The default RATS response sent for a Type 4 Tag
        activation can be replaced with a ``rats_res`` attribute.

        """
        return super(Device, self).listen_tta(target, timeout)

    def listen_ttb(self, target, timeout):
        """Listen as Type B Target is not supported."""
        info = "{device} does not support listen as Type B Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_ttf(self, target, timeout):
        """Listen *timeout* seconds for a Type F card activation. The target
        ``brty`` must be set to either 212F or 424F and ``sensf_res``
        provide 19 byte response data (response code + 8 byte IDm + 8
        byte PMm + 2 byte system code). Note that the maximum command
        an response frame length is 64 bytes only (including the frame
        length byte), because the driver must directly program the
        contactless interface unit within the PN533.

        """
        return super(Device, self).listen_ttf(target, timeout)

    def listen_dep(self, target, timeout):
        """Listen *timeout* seconds to become initialized as a DEP Target.

        The PN533 can be set to listen as a DEP Target for passive and
        active communication mode.

        """
        return super(Device, self).listen_dep(target, timeout)

    def send_rsp_recv_cmd(self, target, data, timeout):
        """While operating as *target* send response *data* to the remote
        device and return new command data if received within
        *timeout* seconds.

        """
        return super(Device, self).send_rsp_recv_cmd(target, data, timeout)

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        nfcid3t = ttf_params[0:8] + b"\x00\x00"
        args = (mode, tta_params, ttf_params, nfcid3t, b'', b'', timeout)
        return self.chipset.tg_init_as_target(*args)


def init(transport):
    # write ack to perform a soft reset, raises IOError(EACCES) if
    # someone else has already claimed the USB device.
    transport.write(Chipset.ACK)

    chipset = Chipset(transport, logger=log)
    device = Device(chipset, logger=log)

    # PN533 bug: Manufacturer and product strings are no longer
    # accessible from USB device description after first use with
    # slightly larger command frames. Better read it from EEPROM.
    if device.eeprom:
        index = 0
        while index < len(device.eeprom) and device.eeprom[index] != 0xFF:
            tlv_tag, tlv_len = device.eeprom[index], device.eeprom[index+1]
            tlv_data = device.eeprom[index+2:index+2+tlv_len]
            if tlv_tag == 3:
                device._device_name = tlv_data[2:].decode("utf-16-le")
            if tlv_tag == 4:
                device._vendor_name = tlv_data[2:].decode("utf-16-le")
            index += 2 + tlv_len
    else:
        device._vendor_name = "SensorID"
        device._device_name = "StickID"

    return device
