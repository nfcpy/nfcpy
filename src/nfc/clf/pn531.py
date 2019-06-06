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
"""Driver module for contactless devices based on the NXP PN531
chipset. This was once a (sort of) joint development between Philips
and Sony to supply hardware capable of running the ISO/IEC 18092 Data
Exchange Protocol. The chip has selectable UART, I2C, SPI, or USB host
interfaces, For USB the vendor and product ID can be switched by a
hardware pin to either Philips or Sony.

The internal chipset architecture comprises a small 8-bit MCU and a
Contactless Interface Unit CIU that is basically a PN511. The CIU
implements the analog and digital part of communication (modulation
and framing) while the MCU handles the protocol parts and host
communication. The PN511 and hence the PN531 does not support Type B
Technology and can not handle the specific Jewel/Topaz (Type 1 Tag)
communication. Compared to PN532/PN533 the host frame structure does
not allow maximum size ISO/IEC 18092 packets to be transferred. The
driver handles this restriction by modifying the initialization
commands (ATR, PSL) when needed.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes      Type 1 Tag is not supported
sense_ttb   no
sense_ttf   yes
sense_dep   yes      Reduced transport data byte length (max 192)
listen_tta  yes
listen_ttb  no
listen_ttf  yes      Maximimum frame size is 64 byte
listen_dep  yes
==========  =======  ============

"""
import nfc.clf
from . import pn53x

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
        0x12: "SetTAMAParameters",
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
        # Target
        0x8C: "TgInitTAMATarget",
        0x92: "TgSetGeneralBytes",
        0x86: "TgGetDEPData",
        0x8E: "TgSetDEPData",
        0x94: "TgSetMetaDEPData",
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
        0x7f: "Invalid command syntax - received error frame",
        0xff: "Insufficient data received from executing chip command",
    }

    host_command_frame_max_size = 254
    """Maximum host command frame size."""

    in_list_passive_target_max_target = 2
    """Maximum number of targets for the InListPassiveTarget command."""

    in_list_passive_target_brty_range = (0, 1, 2)
    """Possible values for the brty parameter to InListPassiveTarget."""

    def _read_register(self, data):
        return self.command(0x06, data, timeout=0.25)

    def _write_register(self, data):
        self.command(0x08, data, timeout=0.25)

    sam_configuration_modes = ("normal", "virtual", "wired", "dual")
    """Possible SAM configuration modes."""

    def sam_configuration(self, mode, timeout=0):
        """Send the SAMConfiguration command to configure the Security Access
        Module. The *mode* argument must be one of the string values
        in :data:`sam_configuration_modes`. The *timeout* argument is
        only relevant for the virtual card configuration mode.

        """
        mode = self.sam_configuration_modes.index(mode) + 1
        self.command(0x14, bytearray([mode, timeout]), timeout=0.1)

    power_down_wakeup_sources = ("INT0", "INT1", "USB", "RF", "HSU", "SPI")
    """Possible wake up sources for the :meth:`power_down` method."""

    def power_down(self, wakeup_enable):
        """Send the PowerDown command to put the PN531 (including the
        contactless analog front end) into power down mode in order to
        save power consumption. The *wakeup_enable* argument must be a
        list of wake up sources with values from the
        :data:`power_down_wakeup_sources`.

        """
        wakeup_set = 0
        for i, src in enumerate(self.power_down_wakeup_sources):
            if src in wakeup_enable:
                wakeup_set |= 1 << i
        data = self.command(0x16, bytearray([wakeup_set]), timeout=0.1)
        if data[0] != 0:
            self.chipset_error(data)

    def tg_init_tama_target(self, mode, mifare_params, felica_params,
                            nfcid3t, gt, timeout):
        """Send the TgInitTAMATarget command."""
        assert type(mode) is int and mode & 0b11111100 == 0
        assert len(mifare_params) == 6
        assert len(felica_params) == 18
        assert len(nfcid3t) == 10

        data = bytearray([mode]) + mifare_params + felica_params + nfcid3t + gt
        return self.command(0x8c, data, timeout)


class Device(pn53x.Device):
    # Device driver for PN531 based contactless frontends.

    def __init__(self, chipset, logger):
        assert isinstance(chipset, Chipset)
        super(Device, self).__init__(chipset, logger)

        ver, rev = self.chipset.get_firmware_version()
        self._chipset_name = "PN531v{0}.{1}".format(ver, rev)
        self.log.debug("chipset is a {0}".format(self._chipset_name))

        self.chipset.sam_configuration("normal")
        self.chipset.set_parameters(0b00000000)
        self.chipset.rf_configuration(0x02, b"\x00\x0B\x0A")
        self.chipset.rf_configuration(0x04, b"\x00")
        self.chipset.rf_configuration(0x05, b"\x01\x00\x01")
        self.mute()

    def close(self):
        self.mute()
        super(Device, self).close()

    def sense_tta(self, target):
        """Activate the RF field and probe for a Type A Target.

        The PN531 can discover some Type A Targets (Type 2 Tag and
        Type 4A Tag) at 106 kbps. Type 1 Tags (Jewel/Topaz) are
        completely unsupported. Because the firmware does not evaluate
        the SENS_RES before sending SDD_REQ, it may be that a warning
        message about missing Type 1 Tag support is logged even if a
        Type 2 or 4A Tag was present. This typically happens when the
        SDD_RES or SEL_RES are lost due to communication errors
        (normally when the tag is moved away).

        """
        target = super(Device, self).sense_tta(target)
        if target and target.sdd_res and len(target.sdd_res) > 4:
            # Remove the cascade tag(s) from SDD_RES, only the PN531
            # has them included and we've set the policy that cascade
            # tags are not part of the sel_req/sdd_res parameters.
            if len(target.sdd_res) == 8:
                target.sdd_res = target.sdd_res[1:]
            elif len(target.sdd_res) == 12:
                target.sdd_res = target.sdd_res[1:4] + target.sdd_res[5:]
            # Also the SENS_RES bytes are reversed compared to PN532/533
            target.sens_res = bytearray(reversed(target.sens_res))
        return target

    def sense_ttb(self, target):
        """Sense for a Type B Target is not supported."""
        info = "{device} does not support sense for Type B Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def sense_ttf(self, target):
        """Activate the RF field and probe for a Type F Target.

        """
        return super(Device, self).sense_ttf(target)

    def sense_dep(self, target):
        """Search for a DEP Target in active communication mode.

        Because the PN531 does not implement the extended frame syntax
        for host controller communication, it can not support the
        maximum payload size of 254 byte. The driver handles this by
        modifying the length-reduction values in atr_req and atr_res.

        """
        if target.atr_req[15] & 0x30 == 0x30:
            self.log.warning("must reduce the max payload size in atr_req")
            target.atr_req[15] = (target.atr_req[15] & 0xCF) | 0x20

        target = super(Device, self).sense_dep(target)
        if target is None:
            return

        if target.atr_res[16] & 0x30 == 0x30:
            self.log.warning("must reduce the max payload size in atr_res")
            atr_res = bytearray(target.atr_res)
            atr_res[16] = (target.atr_res[16] & 0xCF) | 0x20
            target.atr_res = bytes(atr_res)

        return target

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

        The PN531 can be set to listen as a DEP Target for passive and
        active communication mode.

        """
        return super(Device, self).listen_dep(target, timeout)

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        nfcid3t = ttf_params[0:8] + b"\x00\x00"
        args = (mode, tta_params, ttf_params, nfcid3t, b'', timeout)
        return self.chipset.tg_init_tama_target(*args)


def init(transport):
    chipset = Chipset(transport, logger=log)
    device = Device(chipset, logger=log)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device
