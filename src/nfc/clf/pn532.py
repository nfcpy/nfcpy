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
"""Driver module for contactless devices based on the NXP PN532
chipset. This successor of the PN531 can additionally handle Type B
Technology (type 4B Tags) and Type 1 Tag communication. It also
supports an extended frame syntax for host communication that allows
larger packets to be transferred. The chip has selectable UART, I2C or
SPI host interfaces. A speciality of the PN532 is that it can manage
two targets (cards) simultanously, although this is not used by
*nfcpy*.

The internal chipset architecture comprises a small 8-bit MCU and a
Contactless Interface Unit CIU that is basically a PN512. The CIU
implements the analog and digital part of communication (modulation
and framing) while the MCU handles the protocol parts and host
communication. Almost all PN532 firmware limitations (or bugs) can be
avoided by directly programming the CIU. Type F Target mode for card
emulation is completely implemented with the CIU and limited to 64
byte frame exchanges by the CIU's FIFO size. Type B Target mode is not
possible.

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

import os
import sys
import time
import errno

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
        0x10: "SetSerialBaudrate",
        0x12: "SetParameters",
        0x14: "SAMConfiguration",
        0x16: "PowerDown",
        # RF communication
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
        0x44: "InDeselect",
        0x52: "InRelease",
        0x54: "InSelect",
        0x60: "InAutoPoll",
        # Target
        0x8C: "TgInitAsTarget",
        0x92: "TgSetGeneralBytes",
        0x86: "TgGetData",
        0x8E: "TgSetData",
        0x94: "TgSetMetaData",
        0x88: "TgGetInitiatorCommand",
        0x90: "TgResponseToInitiator",
        0x8A: "TgGetTargetStatus",
    }
    ERR = {
        0x01: "Time out, the Target has not answered",
        0x02: "Checksum error during RF communication",
        0x03: "Parity error during RF communication",
        0x04: "Erroneous bit count in anticollision",
        0x05: "Framing error during Mifare operation",
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
        0x23: "ISO/IEC14443-3 UID check byte is wrong",
        0x25: "Command invalid in current DEP state",
        0x26: "Operation not allowed in this configuration",
        0x27: "Command is not acceptable in the current context",
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
    in_list_passive_target_max_target = 2
    in_list_passive_target_brty_range = (0, 1, 2, 3, 4)

    def _read_register(self, data):
        return self.command(0x06, data, timeout=0.25)

    def _write_register(self, data):
        self.command(0x08, data, timeout=0.25)

    def set_serial_baudrate(self, baudrate):
        br = (9600, 19200, 38400, 57600, 115200,
              230400, 460800, 921600, 1288000)
        self.command(0x10, bytearray([br.index(baudrate)]), timeout=0.1)
        self.write_frame(self.ACK)
        time.sleep(0.001)

    def sam_configuration(self, mode, timeout=0, irq=False):
        mode = ("normal", "virtual", "wired", "dual").index(mode) + 1
        self.command(0x14, bytearray([mode, timeout, int(irq)]), timeout=0.1)

    power_down_wakeup_src = ("INT0", "INT1", "rfu", "RF",
                             "HSU", "SPI", "GPIO", "I2C")

    def power_down(self, wakeup_enable, generate_irq=False):
        wakeup_set = 0
        for i, src in enumerate(self.power_down_wakeup_src):
            if src in wakeup_enable:
                wakeup_set |= 1 << i
        cmd_data = bytearray([wakeup_set, int(generate_irq)])
        data = self.command(0x16, cmd_data, timeout=0.1)
        if data[0] != 0:
            self.chipset_error(data)

    def tg_init_as_target(self, mode, mifare_params, felica_params, nfcid3t,
                          general_bytes=b'', historical_bytes=b'',
                          timeout=None):
        assert type(mode) is int and mode & 0b11111000 == 0
        assert len(mifare_params) == 6
        assert len(felica_params) == 18
        assert len(nfcid3t) == 10

        data = (bytearray([mode]) + mifare_params + felica_params + nfcid3t +
                bytearray([len(general_bytes)]) + general_bytes +
                bytearray([len(historical_bytes)]) + historical_bytes)
        return self.command(0x8c, data, timeout)


class Device(pn53x.Device):
    # Device driver for PN532 based contactless frontends.

    def __init__(self, chipset, logger):
        assert isinstance(chipset, Chipset)
        super(Device, self).__init__(chipset, logger)

        ic, ver, rev, support = self.chipset.get_firmware_version()
        self._chipset_name = "PN5{0:02x}v{1}.{2}".format(ic, ver, rev)
        self.log.debug("chipset is a {0}".format(self._chipset_name))

        self.chipset.set_parameters(0b00000000)
        self.chipset.rf_configuration(0x02, b"\x00\x0B\x0A")
        self.chipset.rf_configuration(0x04, b"\x00")
        self.chipset.rf_configuration(0x05, b"\x01\x00\x01")

        self.log.debug("write analog settings for Type A 106 kbps")
        data = bytearray.fromhex("59 F4 3F 11 4D 85 61 6F 26 62 87")
        self.chipset.rf_configuration(0x0A, data)

        self.log.debug("write analog settings for Type F 212/424 kbps")
        data = bytearray.fromhex("69 FF 3F 11 41 85 61 6F")
        self.chipset.rf_configuration(0x0B, data)

        self.log.debug("write analog settings for Type B 106 kbps")
        data = bytearray.fromhex("FF 04 85")
        self.chipset.rf_configuration(0x0C, data)

        self.log.debug("write analog settings for 14443-4 212/424/848 kbps")
        data = bytearray.fromhex("85 15 8A 85 08 B2 85 01 DA")
        self.chipset.rf_configuration(0x0D, data)

        self.mute()

    def close(self):
        # Cancel most recent command in case we've been interrupted
        # before the response, give the chip 10 ms to think about it.
        self.chipset.send_ack()
        time.sleep(0.01)

        # When using the high speed uart we must set the baud rate
        # back to 115.2 kbps, otherwise we can't talk next time.
        if self.chipset.transport.TYPE == "TTY":
            self.chipset.set_serial_baudrate(115200)
            self.chipset.transport.baudrate = 115200

        # Set the chip to sleep mode with some wakeup sources.
        self.chipset.power_down(wakeup_enable=("I2C", "SPI", "HSU"))
        super(Device, self).close()

    def sense_tta(self, target):
        """Search for a Type A Target.

        The PN532 can discover all kinds of Type A Targets (Type 1
        Tag, Type 2 Tag, and Type 4A Tag) at 106 kbps.

        """
        return super(Device, self).sense_tta(target)

    def sense_ttb(self, target):
        """Search for a Type B Target.

        The PN532 can discover Type B Targets (Type 4B Tag) at 106
        kbps. For a Type 4B Tag the firmware automatically sends an
        ATTRIB command that configures the use of DID and 64 byte
        maximum frame size. The driver reverts this configuration with
        a DESELECT and WUPB command to return the target prepared for
        activation (which nfcpy does in the tag activation code).

        """
        return super(Device, self).sense_ttb(target, did=b'\x01')

    def sense_ttf(self, target):
        """Search for a Type F Target.

        The PN532 can discover Type F Targets (Type 3 Tag) at 212 and
        424 kbps. The driver uses the default polling command
        ``06FFFF0000`` if no ``target.sens_req`` is supplied.

        """
        return super(Device, self).sense_ttf(target)

    def sense_dep(self, target):
        """Search for a DEP Target in active communication mode."""
        return super(Device, self).sense_dep(target)

    def _tt1_send_cmd_recv_rsp(self, data, timeout):
        # Special handling for Tag Type 1 (Jewel/Topaz) card commands.

        if data[0] in (0x00, 0x01, 0x1A, 0x53, 0x72):
            # These commands are implemented by the chipset.
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
        # first as a short frame with only 7 data bits and the others
        # as normal frames. Reading is also a bit complicated because
        # for sending we have to disable the parity generator which
        # means that we will also receive the parity bits, thus 9 bits
        # received per 8 data bits. And because they are already
        # reversed in the FIFO we must swap before parity removal and
        # afterwards (maybe this could be optimized a bit)
        data = self.add_crc_b(data)
        register_write = []
        register_write.append(("CIU_FIFOData",   data[0]))  # CMD_CODE
        register_write.append(("CIU_BitFraming",    0x07))  # 7 bits
        register_write.append(("CIU_Command",       0x04))  # Transmit
        register_write.append(("CIU_BitFraming",    0x00))  # 8 bits
        register_write.append(("CIU_ManualRCV",     0x30))  # ParityDisable
        for i in range(1, len(data)):
            register_write.append(("CIU_FIFOData", data[i]))  # CMD_DATA
            register_write.append(("CIU_Command",     0x04))  # Transmit
            register_write.append(("CIU_Command",     0x07))  # NoCmdChange
        register_write.append(("CIU_Command",       0x08))    # Receive
        self.chipset.write_register(*register_write)
        if data[0] == 0x54:  # WRITE-E8
            time.sleep(0.006)  # assuming same response time as WRITE-E
        if data[0] == 0x1B:  # WRITE-NE8
            time.sleep(0.003)  # assuming same response time as WRITE-NE
        self.chipset.write_register(("CIU_ManualRCV", 0x20))  # enable parity
        fifo_level = self.chipset.read_register("CIU_FIFOLevel")
        if fifo_level == 0:
            raise nfc.clf.TimeoutError
        data = self.chipset.read_register(*(fifo_level * ["CIU_FIFOData"]))
        data = ''.join(["{:08b}".format(octet)[::-1] for octet in data])
        data = [int(data[i:i+8][::-1], 2) for i in range(0, len(data)-8, 9)]
        if self.check_crc_b(data) is False:
            raise nfc.clf.TransmissionError("crc_b check error")
        return bytearray(data[0:-2])

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

        The PN532 can be set to listen as a DEP Target for passive and
        active communication mode.

        """
        return super(Device, self).listen_dep(target, timeout)

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        nfcid3t = ttf_params[0:8] + b"\x00\x00"
        args = (mode, tta_params, ttf_params, nfcid3t, b'', b'', timeout)
        return self.chipset.tg_init_as_target(*args)


def init(transport):
    if transport.TYPE == "TTY":
        baudrate = 115200  # PN532 initial baudrate
        transport.open(transport.port, baudrate)
        long_preamble = bytearray(10)

        # The PN532 chip should send an ack within 15 ms after a
        # command. We'll give it a bit more and wait 100 ms, unless
        # we're on a Raspberry Pi detected by the Broadcom SOC. The
        # USB on BCM270x has a nasty bug (may be SW or HW) that
        # introduces additional up to ~1000 ms delay for the first
        # data from a ttyUSB. Tested with two serial converters
        # (PL2303 and FT232R) in loopback and it's reproducable adding
        # up to 1000 ms if a serial open is done 1 sec after serial
        # close. Waiting longer decreases that time until after 2 sec
        # wait between close and open it all goes fine until the wait
        # time reaches 3 seconds, and so on.
        initial_timeout = 100   # milliseconds
        change_baudrate = True  # try higher speeds
        if sys.platform.startswith('linux'):
            board = b""  # Raspi board will identify through device tree
            try:
                board = open('/proc/device-tree/model', "rb").read().strip(
                        b'\x00')
            except IOError:
                pass
            if board.startswith(b"Raspberry Pi"):
                log.debug("running on {}".format(board))
                if transport.port.startswith("/dev/ttyUSB"):
                    log.debug("ttyUSB requires more time for first ack")
                    initial_timeout = 1500  # milliseconds
                elif transport.port == "/dev/ttyS0":
                    log.debug("ttyS0 can only do 115.2 kbps")
                    change_baudrate = False  # RPi 'mini uart'

        get_version_cmd = bytearray.fromhex("0000ff02fed4022a00")
        get_version_rsp = bytearray.fromhex("0000ff06fad50332")
        transport.write(long_preamble + get_version_cmd)
        log.debug("wait %d ms for data on %s", initial_timeout, transport.port)
        if not transport.read(timeout=initial_timeout) == Chipset.ACK:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        if not transport.read(timeout=100).startswith(get_version_rsp):
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        sam_configuration_cmd = bytearray.fromhex("0000ff05fbd4140100001700")
        sam_configuration_rsp = bytearray.fromhex("0000ff02fed5151600")
        transport.write(long_preamble + sam_configuration_cmd)
        if not transport.read(timeout=100) == Chipset.ACK:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        if not transport.read(timeout=100) == sam_configuration_rsp:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        if sys.platform.startswith("linux") and change_baudrate is True:
            stty = 'stty -F %s %%d 2> /dev/null' % transport.port
            for baudrate in (921600, 460800, 230400, 115200):
                log.debug("trying to set %d baud", baudrate)
                if os.system(stty % baudrate) == 0:
                    os.system(stty % 115200)
                    break

        if baudrate > 115200:
            set_baudrate_cmd = bytearray.fromhex("0000ff03fdd410000000")
            set_baudrate_rsp = bytearray.fromhex("0000ff02fed5111a00")
            set_baudrate_cmd[7] = 5 + (230400, 460800, 921600).index(baudrate)
            set_baudrate_cmd[8] = 256 - sum(set_baudrate_cmd[5:8])
            transport.write(long_preamble + set_baudrate_cmd)
            if not transport.read(timeout=100) == Chipset.ACK:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
            if not transport.read(timeout=100) == set_baudrate_rsp:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            transport.write(Chipset.ACK)
            transport.open(transport.port, baudrate)
            log.debug("changed uart speed to %d baud", baudrate)
            time.sleep(0.001)

        chipset = Chipset(transport, logger=log)
        return Device(chipset, logger=log)

    raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
