# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
"""Device driver for the Arygon ACR122U contactless reader.

The Arygon ACR122U is a PC/SC compliant contactless reader that
connects via USB and uses the USB CCID profile. It is normally
intented to be used with a PC/SC stack but this driver interfaces
directly with the inbuilt PN532 chipset by tunneling commands through
the PC/SC Escape command. The driver is limited in functionality
because the embedded microprocessor (that implements the PC/SC stack)
also operates the PN532; it does not allow all commands to pass as
desired and reacts on chip responses with its own (legitimate)
interpretation of state.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes      Type 1 (Topaz) Tags are not supported
sense_ttb   yes      ATTRIB by firmware voided with S(DESELECT)
sense_ttf   yes
sense_dep   yes
listen_tta  no
listen_ttb  no
listen_ttf  no
listen_dep  no
==========  =======  ============

"""
import nfc.clf
from . import pn532

import os
import errno
import struct
from binascii import hexlify

import logging
log = logging.getLogger(__name__)


def init(transport):
    device = Device(Chipset(transport))
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name.split()[0]
    return device


class Device(pn532.Device):
    # Device driver class for the ACR122U.

    def __init__(self, chipset):
        super(Device, self).__init__(chipset, logger=log)

    def sense_tta(self, target):
        """Activate the RF field and probe for a Type A Target at 106
        kbps. Other bitrates are not supported. Type 1 Tags are not
        supported because the device does not allow to send the
        correct RID command (even though the PN532 does).

        """
        return super(Device, self).sense_tta(target)

    def sense_ttb(self, target):
        """Activate the RF field and probe for a Type B Target.

        The RC-S956 can discover Type B Targets (Type 4B Tag) at 106
        kbps. For a Type 4B Tag the firmware automatically sends an
        ATTRIB command that configures the use of DID and 64 byte
        maximum frame size. The driver reverts this configuration with
        a DESELECT and WUPB command to return the target prepared for
        activation (which nfcpy does in the tag activation code).

        """
        return super(Device, self).sense_ttb(target)

    def sense_ttf(self, target):
        """Activate the RF field and probe for a Type F Target. Bitrates 212
        and 424 kpbs are supported.

        """
        return super(Device, self).sense_ttf(target)

    def sense_dep(self, target):
        """Search for a DEP Target. Both passive and passive communication
        mode are supported.

        """
        return super(Device, self).sense_dep(target)

    def listen_tta(self, target, timeout):
        """Listen as Type A Target is not supported."""
        info = "{device} does not support listen as Type A Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_ttb(self, target, timeout):
        """Listen as Type B Target is not supported."""
        info = "{device} does not support listen as Type B Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_ttf(self, target, timeout):
        """Listen as Type F Target is not supported."""
        info = "{device} does not support listen as Type F Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_dep(self, target, timeout):
        """Listen as DEP Target is not supported."""
        info = "{device} does not support listen as DEP Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def turn_on_led_and_buzzer(self):
        """Buzz and turn red."""
        self.chipset.set_buzzer_and_led_to_active()

    def turn_off_led_and_buzzer(self):
        """Back to green."""
        self.chipset.set_buzzer_and_led_to_default()


class Chipset(pn532.Chipset):
    # Maximum size of a host command frame to the contactless chip.
    host_command_frame_max_size = 254

    # Supported BrTy (baud rate / modulation type) values for the
    # InListPassiveTarget command. Corresponds to 106 kbps Type A, 212
    # kbps Type F, 424 kbps Type F, and 106 kbps Type B. The value for
    # 106 kbps Innovision Jewel Tag (although supported by PN532) is
    # removed because the RID command can not be send.
    in_list_passive_target_brty_range = (0, 1, 2, 3)

    def __init__(self, transport):
        self.transport = transport

        # read ACR122U firmware version string
        reader_version = self.ccid_xfr_block(bytearray.fromhex("FF00480000"))
        if not reader_version.startswith(b"ACR122U"):
            log.error("failed to retrieve ACR122U version string")
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        if int(chr(reader_version[7])) < 2:
            log.error("{0} not supported, need 2.x".format(reader_version[7:]))
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        log.debug("initialize " + reader_version.decode())

        # set icc power on
        log.debug("CCID ICC-POWER-ON")
        frame = bytearray.fromhex("62000000000000000000")
        transport.write(frame)
        transport.read(100)

        # disable autodetection
        log.debug("Set PICC Operating Parameters")
        self.ccid_xfr_block(bytearray.fromhex("FF00517F00"))

        # switch red/green led off/on
        log.debug("Configure Buzzer and LED")
        self.set_buzzer_and_led_to_default()

        super(Chipset, self).__init__(transport, logger=log)

    def close(self):
        self.ccid_xfr_block(bytearray.fromhex("FF00400C0400000000"))
        self.transport.close()
        self.transport = None

    def set_buzzer_and_led_to_default(self):
        """Turn off buzzer and set LED to default (green only). """
        self.ccid_xfr_block(bytearray.fromhex("FF00400E0400000000"))

    def set_buzzer_and_led_to_active(self, duration_in_ms=300):
        """Turn on buzzer and set LED to red only. The timeout here must exceed
         the total buzzer/flash duration defined in bytes 5-8. """
        duration_in_tenths_of_second = int(min(duration_in_ms / 100, 255))
        timeout_in_seconds = (duration_in_tenths_of_second + 1) / 10.0
        data = "FF00400D04{:02X}000101".format(duration_in_tenths_of_second)
        self.ccid_xfr_block(bytearray.fromhex(data),
                            timeout=timeout_in_seconds)

    def send_ack(self):
        # Send an ACK frame, usually to terminate most recent command.
        self.ccid_xfr_block(Chipset.ACK)

    def ccid_xfr_block(self, data, timeout=0.1):
        """Encapsulate host command *data* into an PC/SC Escape command to
        send to the device and extract the chip response if received
        within *timeout* seconds.

        """
        frame = struct.pack("<BI5B", 0x6F, len(data), 0, 0, 0, 0, 0) + data
        self.transport.write(bytearray(frame))
        frame = self.transport.read(int(timeout * 1000))
        if not frame or len(frame) < 10:
            log.error("insufficient data for decoding ccid response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if frame[0] != 0x80:
            log.error("expected a RDR_to_PC_DataBlock")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if len(frame) != 10 + struct.unpack("<I", memoryview(frame)[1:5])[0]:
            log.error("RDR_to_PC_DataBlock length mismatch")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        return frame[10:]

    def command(self, cmd_code, cmd_data, timeout):
        """Send a host command and return the chip response.

        """
        log.log(logging.DEBUG-1, "{} {}".format(self.CMD[cmd_code],
                                                hexlify(cmd_data).decode()))

        frame = bytearray([0xD4, cmd_code]) + bytearray(cmd_data)
        frame = bytearray([0xFF, 0x00, 0x00, 0x00, len(frame)]) + frame

        frame = self.ccid_xfr_block(frame, timeout)
        if not frame or len(frame) < 4:
            log.error("insufficient data for decoding chip response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if not (frame[0] == 0xD5 and frame[1] == cmd_code + 1):
            log.error("received invalid chip response")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        if not (frame[-2] == 0x90 and frame[-1] == 0x00):
            log.error("received pseudo apdu with error status")
            raise IOError(errno.EIO, os.strerror(errno.EIO))
        return frame[2:-2]
