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
"""Driver for contacless devices based on the Sony RC-S956
chipset. Products known to use this chipset are the PaSoRi RC-S330,
RC-S360, and RC-S370. The RC-S956 connects to the host as a native USB
device.

The RC-S956 has the same hardware architecture as the NXP PN53x
family, i.e. it has a PN512 Contactless Interface Unit (CIU) coupled
with a 80C51 microcontroller and uses the same frame structure for
host communication and mostly the same commands. However, the firmware
that runs on the 80C51 is different and the most notable difference is
a much stricter state machine. The state machine restricts allowed
commands to certain modes. While direct access to the CIU registers is
possible, some of the things that can be done with a PN53x are
unfortunately prevented by the stricter state machine.

==========  =======  ============
function    support  remarks
==========  =======  ============
sense_tta   yes      Only Type 1 Tags up to 128 byte (Topaz-96)
sense_ttb   yes      ATTRIB by firmware voided with S(DESELECT)
sense_ttf   yes
sense_dep   yes
listen_tta  yes      Only DEP and Type 2 Target
listen_ttb  no
listen_ttf  no
listen_dep  yes      Only passive communication mode
==========  =======  ============

"""
import nfc.clf
from . import pn53x

import time

import logging
log = logging.getLogger(__name__)


class Chipset(pn53x.Chipset):
    CMD = {
        0x00: "Diagnose",
        0x02: "GetFirmwareVersion",
        0x04: "GetGeneralStatus",
        0x06: "ReadRegister",
        0x08: "WriteRegister",
        0x0C: "ReadGPIO",
        0x10: "SetSerialBaudrate",
        0x12: "SetParameters",
        0x16: "PowerDown",
        0x32: "RFConfiguration",
        0x58: "RFRegulationTest",
        0x18: "ResetMode",
        0x1C: "ControlLED",
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
        0x8C: "TgInitTarget",
        0x92: "TgSetGeneralBytes",
        0x86: "TgGetDEPData",
        0x8E: "TgSetDEPData",
        0x94: "TgSetMetaDEPData",
        0x88: "TgGetInitiatorCommand",
        0x90: "TgResponseToInitiator",
        0x8A: "TgGetTargetStatus",
        0xA0: "CommunicateThruEX",
    }
    ERR = {
        0x01: "Time out, the Target has not answered",
        0x02: "Checksum error during RF communication",
        0x03: "Parity error during RF communication",
        0x04: "Incorrect collision bit position in TargetID during SDD",
        0x07: "Overflow detected by the hardware during RF communication",
        0x0A: "RF field not activated in time by active mode peer",
        0x0B: "Protocol error during RF communication",
        0x0C: "More than 260 bytes payload received in ISO-DEP chaining",
        0x0D: "Overheated - antenna drivers deactivated",
        0x10: "Size of RF response packet during SDD was more than 4 bytes",
        0x13: "Format error during RF communication or retry count exceeded",
        0x14: "Authentication A or B failed for Type-A ISO target",
        0x17: "Unmatched block number in R(ACK) from ISO Type A or B card",
        0x23: "Invalid BCC value from ISO Type A card during anticollision",
        0x25: "TgGetDEPData or TgSetDEPData executed at wrong time",
        0x26: "PowerDown command received while USB interface being used",
        0x27: "Abnormal Tg parameter in the host command packet",
        0x29: "Release from the initiator in operation as DEPTarget",
        0x2A: "PUPI information in ATQB response differs from initial value",
        0x2B: "Failure to select a deselected target",
        0x2F: "Already deselected by the initiator in operation as DEPTarget",
        0x31: "Initiator RF-OFF state detected while operating as Target",
        0x32: "Buffer overflow detected by firmware during RF communication",
        0x34: "DEP_REQ(NACK) received but DEP_RES(INF) was never returned",
        0x35: "The received data exceeds LEN in the RF packet",
        0x7f: "Invalid command syntax - received error frame",
        0xfe: "A register write operation failed",
        0xff: "No data received from executing chip command",
    }

    host_command_frame_max_size = 265
    in_list_passive_target_max_target = 1
    in_list_passive_target_brty_range = (0, 1, 2, 3, 4)

    def diagnose(self, test, test_data=None):
        if test == "line":
            size = self.host_command_frame_max_size - 3
            data = bytearray([x & 0xFF for x in range(size)])
            return self.command(0x00, b"\x00" + data, timeout=1.0) == data
        return super(Chipset, self).diagnose(test, test_data)

    def _read_register(self, data):
        # Max 64 registers can be read from RCS956
        assert len(data) <= 128
        return self.command(0x06, data, timeout=0.25)

    def _write_register(self, data):
        # Max 64 registers can be written to RCS956
        assert len(data) <= 192
        status = self.command(0x08, data, timeout=0.25)
        if sum(status) != 0:
            self.chipset_error(0xfe)

    def reset_mode(self):
        """Send a Reset command to set the operation mode to 0."""
        self.command(0x18, b"\x01", timeout=0.1)
        self.transport.write(Chipset.ACK)
        time.sleep(0.010)

    def tg_init_target(self, mode, mifare_params, felica_params,
                       nfcid3t, gt, timeout):
        assert type(mode) is int and mode & 0b11111101 == 0
        assert len(mifare_params) == 6
        assert len(felica_params) == 18
        assert len(nfcid3t) == 10

        data = bytearray([mode]) + mifare_params + felica_params + nfcid3t + gt
        return self.command(0x8c, data, timeout)


class Device(pn53x.Device):
    # Device driver for Sony RC-S956 based contactless devices.

    def __init__(self, chipset, logger):
        assert isinstance(chipset, Chipset)
        # Reset the RCS956 state machine to Mode 0. We may have left
        # it in some other mode when an error has occured.
        chipset.reset_mode()

        super(Device, self).__init__(chipset, logger)

        ic, ver, rev, support = self.chipset.get_firmware_version()
        self._chipset_name = "RCS956v{0:x}.{1:x}".format(ver, rev)
        self.log.debug("chipset is a {0}".format(self._chipset_name))

        self.mute()
        # Set timeout for PSL_RES, ATR_RES, InDataExchange/InCommunicateThru
        self.chipset.rf_configuration(0x02, b"\x0B\x0B\x0A")
        self.chipset.rf_configuration(0x04, b"\x00")
        self.chipset.rf_configuration(0x05, b"\x00\x00\x01")

        self.log.debug("write rf settings for 106A")
        data = bytearray.fromhex("5A F4 3F 11 4D 85 61 6F 26 62 87")
        self.chipset.rf_configuration(0x0A, data)

        self.chipset.set_parameters(0b00001000)
        self.chipset.reset_mode()

        # Set the RFCfg value for RAM-07. RF settings in RAM-07 are
        # used for initial target state. During power-up RAM-07 is
        # loaded from EEPROM-07 and the RFCfg value 0xFD stored in
        # EEPROM-07 for RC-S330/360 prevents passive mode activation
        # at 106A. It works with the RFCfg value 0x59 stored in ROM-07
        # (Neither value makes it work in active mode).
        self.chipset.write_register(0x0328, 0x59)

    def close(self):
        self.mute()
        super(Device, self).close()

    def mute(self):
        self.chipset.reset_mode()
        super(Device, self).mute()

    def sense_tta(self, target):
        """Activate the RF field and probe for a Type A Target.

        The RC-S956 can discover all Type A Targets (Type 1 Tag, Type
        2 Tag, and Type 4A Tag) at 106 kbps. Due to firmware
        restrictions it is not possible to read a Type 1 Tag with
        dynamic memory layout (more than 128 byte memory).

        """
        target = super(Device, self).sense_tta(target)
        if target and target.rid_res:
            # This is a TT1 tag. Unfortunately we can only read it if
            # it is a static memory tag. The RCS956 has implemented
            # the same wrong command codes as PN531/2/3 and directly
            # programming the CIU does not work.
            if target.rid_res[0] >> 4 == 1 and target.rid_res[0] & 15 != 1:
                msg = "The {device} can not read this Type 1 Tag."
                self.log.warning(msg.format(device=self))
                return None
        return target

    def sense_ttb(self, target):
        """Activate the RF field and probe for a Type B Target.

        The RC-S956 can discover Type B Targets (Type 4B Tag) at 106
        kbps. For a Type 4B Tag the firmware automatically sends an
        ATTRIB command that configures the use of DID and 64 byte
        maximum frame size. The driver reverts this configuration with
        a DESELECT and WUPB command to return the target prepared for
        activation (which nfcpy does in the tag activation code).

        """
        return super(Device, self).sense_ttb(target, did=b'\x01')

    def sense_ttf(self, target):
        """Activate the RF field and probe for a Type F Target.

        """
        return super(Device, self).sense_ttf(target)

    def sense_dep(self, target):
        """Search for a DEP Target in active or passive communication mode.

        """
        # Set timeout for PSL_RES and ATR_RES
        self.chipset.rf_configuration(0x02, b"\x0B\x0B\x0A")
        return super(Device, self).sense_dep(target)

    def listen_tta(self, target, timeout):
        """Listen *timeout* seconds for a Type A activation at 106 kbps. The
        ``sens_res``, ``sdd_res``, and ``sel_res`` response data must
        be provided and ``sdd_res`` must be a 4 byte UID that starts
        with ``08h``. Depending on ``sel_res`` an activation may
        return a target with ``tt2_cmd`` or ``atr_req`` attribute. A
        Type 4A Tag activation is not supported.

        """
        if target.sel_res and target.sel_res[0] & 0x20:
            info = "{device} does not support listen as Type 4A Target"
            raise nfc.clf.UnsupportedTargetError(info.format(device=self))
        return super(Device, self).listen_tta(target, timeout)

    def listen_ttb(self, target, timeout):
        """Listen as Type B Target is not supported."""
        info = "{device} does not support listen as Type B Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_ttf(self, target, timeout):
        """Listen as Type F Target is not supported."""
        info = "{device} does not support listen as Type F Target"
        raise nfc.clf.UnsupportedTargetError(info.format(device=self))

    def listen_dep(self, target, timeout):
        """Listen *timeout* seconds to become initialized as a DEP Target.

        The RC-S956 can be set to listen as a DEP Target for passive
        communication mode. Target active communication mode is
        disabled by the driver due to performance issues. It is also
        not possible to fully control the ATR_RES response, only the
        response waiting time (TO byte of ATR_RES) and the general
        bytes can be set by the driver. Because the TO value must be
        set before calling the hardware listen function, it can not be
        different for the Type A of Type F passive initalization (the
        driver uses the higher value if they are different).

        """
        # The RCS956 internal state machine must be in Mode 0 before
        # we enter the listen phase. Also the RFConfiguration command
        # for setting the TO parameter won't work in any other mode.
        self.chipset.reset_mode()

        # Set the WaitForSelected bit in CIU_FelNFC2 register to
        # prevent active mode activation. Target active mode is not
        # really working with this device.
        self.chipset.write_register("CIU_FelNFC2", 0x80)

        # We can not send ATR_RES as as a regular response but must
        # use TgSetGeneralBytes to advance the chipset state machine
        # to mode 3. Thus the ATR_RES is mostly determined by the
        # firmware, we can only control the TO parameter for RWT, but
        # must do it before the actual listen.
        to = target.atr_res[15] & 0x0F
        self.chipset.rf_configuration(0x82, bytearray([to, 2, to]))

        # Disable automatic ATR_RES transmission. This must be done
        # all again because the chipset reactivates the setting after
        # ATR_RES was once send in TgSetGeneralBytes.
        self.chipset.set_parameters(0b00001000)

        # Now we can use the generic pn53x implementation
        return super(Device, self).listen_dep(target, timeout)

    def _init_as_target(self, mode, tta_params, ttf_params, timeout):
        nfcid3t = ttf_params[0:8] + b"\x00\x00"
        args = (mode & 0xFE, tta_params, ttf_params, nfcid3t, b'', timeout)
        return self.chipset.tg_init_target(*args)

    def _send_atr_response(self, atr_res, timeout):
        # Before ATR_RES the device is in Mode 2 which does not allow
        # the use of TgResponseToInitiator. To send the ATR_RES we
        # must use TgSetGeneralBytes and can control only the general
        # bytes and TO which we've set in _listen_dep(). We now copy
        # the DID value from atr_req to atr_res but this will likely
        # have no effect on the actual response. The hope is that the
        # firmware will do the same when sending ATR_RES and we tell
        # the truth to the caller.
        self.log.debug("calling TgSetGeneralBytes to send ATR_RES")
        self.chipset.tg_set_general_bytes(atr_res[17:])
        return self.chipset.tg_get_initiator_command(timeout)

    def _tt1_send_cmd_recv_rsp(self, data, timeout):
        # Special handling for Tag Type 1 (Jewel/Topaz) card commands.

        if data[0] in (0x00, 0x01, 0x1A, 0x53, 0x72):
            # RALL, READ, WRITE-NE, WRITE-E, RID are properly
            # implemented by firmware.
            return self.chipset.in_data_exchange(data, timeout)[0]

        # The other commands can not be executed. The workaround found
        # for PN531, PN532 and PN533 fails with RCS956. While it is
        # possible to properly send a TT1 command and the tag answers
        # as expected, there is no way to get the response data from
        # the CIU FIFO. For whatever reason the FIFO is empty, maybe
        # the firmware constantly polls for new data and just removes
        # it. That the response data was received can be guessed from
        # the fact that the CIU Control register shows has the
        # RxLastBits field set to exactly the correct number of valid
        # bits in the last byte (when parity check is disabled,
        # i.e. the FIFO contains one more bit for each received byte.
        self.log.debug("tt1 command can not be send with this hardware ")
        raise nfc.clf.TransmissionError("tt1 command can not be send")


def init(transport):
    # Write ack to see if we can talk to the device. This raises
    # IOError(EACCES) if it's claimed by some other process.
    transport.write(Chipset.ACK)

    chipset = Chipset(transport, logger=log)
    device = Device(chipset, logger=log)

    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    if device._device_name is None:
        device._device_name = "RC-S330"

    return device
