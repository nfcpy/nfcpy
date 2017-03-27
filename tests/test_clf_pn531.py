# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.pn531

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call
from binascii import hexlify

import base_clf_pn53x
from base_clf_pn53x import CMD, RSP, ACK, NAK, ERR, HEX  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.pn531").setLevel(logging_level)


@pytest.fixture()  # noqa: F811
def transport(mocker):
    mocker.patch('nfc.clf.transport.USB.__init__').return_value = None
    transport = nfc.clf.transport.USB(1, 1)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport._manufacturer_name = "Company"
    transport._product_name = "Reader"
    transport.context = None
    transport.usb_dev = None
    return transport


class TestChipset(base_clf_pn53x.TestChipset):
    @pytest.fixture()
    def chipset(self, transport):
        return nfc.clf.pn531.Chipset(transport, logger=nfc.clf.pn531.log)

    @pytest.mark.parametrize("mode, timeout, command", [
        ("normal", 0, CMD('14 01 00')),
        ("virtual", 1, CMD('14 02 01')),
        ("wired", 2, CMD('14 03 02')),
        ("dual", 3, CMD('14 04 03')),
    ])
    def test_sam_configuration(self, chipset, mode, timeout, command):
        chipset.transport.read.side_effect = [ACK(), RSP('15')]
        assert chipset.sam_configuration(mode, timeout) is None
        assert chipset.transport.write.mock_calls == [call(command)]
        assert chipset.transport.read.mock_calls == [call(100), call(100)]

    @pytest.mark.parametrize("wakeup_enable, command", [
        ("INT0", '16 01'), ("INT1", '16 02'), ("USB",  '16 04'),
        ("RF",   '16 08'), ("HSU",  '16 10'), ("SPI",  '16 20'),
        ("INT0, INT1, RF", '16 0B'), ("SPI, HSU, USB", '16 34'),
    ])
    def test_power_down(self, chipset, wakeup_enable, command):
        chipset.transport.read.side_effect = [ACK(), RSP('17 00')]
        assert chipset.power_down(wakeup_enable) is None
        assert chipset.transport.write.mock_calls == [call(CMD(command))]
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        chipset.transport.read.side_effect = [ACK(), RSP('17 01')]
        with pytest.raises(chipset.Error) as excinfo:
            chipset.power_down(wakeup_enable)
        assert excinfo.value.errno == 1

    def test_tg_init_tama_target(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('8D 01 02 03')]
        mifare = HEX('010203040506')
        felica = HEX('010203040506070809101112131415161718')
        nfcid3 = HEX('01020304050607080910')
        gbytes = HEX('313233')
        args = (0x03, mifare, felica, nfcid3, gbytes, 0.5)
        assert chipset.tg_init_tama_target(*args) == HEX('01 02 03')
        assert chipset.transport.read.mock_calls == [call(100), call(500)]
        assert chipset.transport.write.mock_calls == [
            call(CMD('8C 03 010203040506 010203040506070809101112131415161718'
                     '01020304050607080910 313233'))
        ]


class TestDevice(base_clf_pn53x.TestDevice):
    @pytest.fixture()
    def device(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('01 00' + hexlify(bytearray(range(251)))),  # Diagnose
            ACK(), RSP('03 0304'),                        # GetFirmwareVersion
            ACK(), RSP('15'),                             # SAMConfiguration
            ACK(), RSP('13'),                             # SetTAMAParameters
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        device = nfc.clf.pn531.init(transport)
        device._path = 'usb:001:001'
        assert isinstance(device, nfc.clf.pn531.Device)
        assert isinstance(device.chipset, nfc.clf.pn531.Chipset)
        assert transport.write.mock_calls == [call(_) for _ in [
            CMD('00 00' + hexlify(bytearray(range(251)))),  # Diagnose
            CMD('02'),                                    # GetFirmwareVersion
            CMD('14 0100'),                               # SAMConfiguration
            CMD('12 00'),                                 # SetTAMAParameters
            CMD('32 02000b0a'),                           # RFConfiguration
            CMD('32 0400'),                               # RFConfiguration
            CMD('32 05010001'),                           # RFConfiguration
            CMD('32 0102'),                               # RFConfiguration
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        yield device
        transport.write.reset_mock()
        transport.read.reset_mock()
        transport.read.side_effect = [
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        device.close()
        assert transport.write.mock_calls == [
            call(CMD('32 0102')),                         # RFConfiguration
        ]

    def reg_rsp(self, hexdata):
        return RSP('07' + hexdata)

    def test_chipset_communication_fails(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [ACK(), ERR()]       # Diagnose
        chipset = nfc.clf.pn531.Chipset(transport, logger=nfc.clf.pn531.log)
        with pytest.raises(IOError):
            nfc.clf.pn531.Device(chipset, logger=nfc.clf.pn531.log)
        assert chipset.transport.write.mock_calls == [call(
            CMD('00 00' + ''.join(["%02x" % x for x in range(251)])))
        ]

    def test_sense_tta_target_is_tt1(self, device):
        base = super(TestDevice, self)
        assert base.test_sense_tta_target_is_tt1(device) is None

    def test_sense_tta_target_is_tt2(self, device):
        target = super(TestDevice, self).test_sense_tta_target_is_tt2(device)
        assert target.sens_res == HEX('0044')             # reversed for PN531
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6303'),                               # ReadRegister
            CMD('08 63037f'),                             # WriteRegister
        ]]
        return target

    def test_sense_tta_target_is_dep(self, device):
        target = super(TestDevice, self).test_sense_tta_target_is_dep(device)
        assert target.sens_res == HEX('0044')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
        ]]
        return target

    @pytest.mark.parametrize("sdd, sdd_res", [
        ('088801020304050607', '01020304050607'),
        ('0c880102038804050607080910', '01020304050607080910'),
    ])
    def test_sense_tta_target_tt2_cascade(self, device, sdd, sdd_res):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 01 01 0044 00' + sdd),         # InListPassiveTarget
            ACK(), self.reg_rsp('FF'),                    # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = device.sense_tta(nfc.clf.RemoteTarget('106A'))
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.sel_res == HEX('00')
        assert target.sdd_res == HEX(sdd_res)
        assert target.sens_res == HEX('0044')             # reversed for PN531
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6303'),                               # ReadRegister
            CMD('08 63037f'),                             # WriteRegister
        ]]

    def test_sense_ttb_is_not_supported(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError) as excinfo:
            device.sense_ttb(nfc.clf.RemoteTarget('106B'))
        assert "does not support sense for Type B Target" in str(excinfo.value)

    def test_sense_ttb_no_target_found(self):
        pytest.skip("PN531 does not support TT1")

    def test_sense_ttb_target_found(self):
        pytest.skip("PN531 does not support TT1")

    def test_sense_ttb_deselect_timeout(self):
        pytest.skip("PN531 does not support TT1")

    def test_sense_ttb_unsupported_bitrate(self):
        pytest.skip("PN531 does not support TT1")

    def test_sense_dep_reduce_frame_size(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('47 0001 66f6e98d1c13dfe56de4'
                       '0000000732 46666d 010112'
                       '020207ff 040164 070103'),         # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(
            'D400 30313233343536373839 00000032'
            '46666d 010113 020207ff 040132 070107'))
        target = device.sense_dep(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.atr_req == HEX(
            'D400 30313233343536373839 00000022'
            '46666d 010113 020207ff 040132 070107')
        assert target.atr_res == HEX(
            'D501 66f6e98d1c13dfe56de4 0000000722'
            '46666d 010112 020207ff 040164 070103')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('46 010006 30313233343536373839 46666d'
                '010113 020207ff 040132 070107'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]

    def test_send_cmd_recv_rsp_tt1_cmd(self):
        pytest.skip("PN531 does not support TT1")

    def test_listen_tta_not_activated(self, device):
        super(TestDevice, self).test_listen_tta_not_activated(device)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('08 63013f'),                             # WriteRegister
            CMD('8c 0144000102030000 0102030405060708'
                '   090a0b0c0d0e0f10 1100010203040506'
                '   070000'),                             # TgInitAsTarget
            ACK(),
        ]]

    def test_listen_dep_not_activated(self, device):
        super(TestDevice, self).test_listen_dep_not_activated(device)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('08 63017b6302b06303b0'),                 # WriteRegister
            CMD('8c 0201010102034001 fe01020304050600'
                '   0000000000000000 0001fe0102030405'
                '   060000'),                             # TgInitAsTarget
            ACK(),
        ]]

    def test_get_max_send_data_size(self, device):
        assert device.get_max_send_data_size(target=None) == 252

    def test_get_max_recv_data_size(self, device):
        assert device.get_max_recv_data_size(target=None) == 251
