# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.clf
import nfc.clf.rcs956

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call
import errno

import base_clf_pn53x
from base_clf_pn53x import CMD, RSP, ACK, NAK, ERR, HEX  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.clf").setLevel(logging_level)
logging.getLogger("nfc.clf.rcs956").setLevel(logging_level)


@pytest.fixture()  # noqa: F811
def transport(mocker):
    mocker.patch('nfc.clf.transport.USB.__init__').return_value = None
    transport = nfc.clf.transport.USB(1, 1)
    mocker.patch.object(transport, 'write', autospec=True)
    mocker.patch.object(transport, 'read', autospec=True)
    transport._manufacturer_name = "Manufacturer Name"
    transport._product_name = "Product Name"
    transport.context = None
    transport.usb_dev = None
    return transport


class TestChipset(base_clf_pn53x.TestChipset):
    @pytest.fixture()
    def chipset(self, transport):
        return nfc.clf.rcs956.Chipset(transport, logger=nfc.clf.rcs956.log)

    def test_get_general_status(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('05 010203')]
        assert chipset.get_general_status() == HEX('010203')
        assert chipset.transport.read.mock_calls == [call(100), call(100)]
        assert chipset.transport.write.mock_calls == [call(CMD('04'))]

    @pytest.mark.parametrize("args, command, response, value", [
        ((0x0102,), '06 0102', '07 AA', 0xAA),
        (("CIU_TMode",), '06 631A', '07 BB', 0xBB),
        ((0x0102, "CIU_TMode"), '06 0102631A', '07 AABB', [0xAA, 0xBB]),
    ])
    def test_read_register(self, chipset, args, command, response, value):
        chipset.transport.read.side_effect = [ACK(), RSP(response)]
        assert chipset.read_register(*args) == value
        assert chipset.transport.read.mock_calls == [call(100), call(250)]
        assert chipset.transport.write.mock_calls == [call(CMD(command))]

    @pytest.mark.parametrize("args, command", [
        ((0x0102, 0x00), '08 0102 00'),
        (("CIU_Mode", 0x01), '08 6301 01'),
        (((0x0102, 0x10), ("CIU_Mode", 0x11)), '08 0102 10 6301 11'),
    ])
    def test_write_register(self, chipset, args, command):
        chipset.transport.read.side_effect = [ACK(), RSP('09 00')]
        assert chipset.write_register(*args) is None
        chipset.transport.read.side_effect = [ACK(), RSP('09 01')]
        with pytest.raises(nfc.clf.rcs956.Chipset.Error) as excinfo:
            chipset.write_register(*args)
        assert excinfo.value.errno == 0xfe
        assert chipset.transport.read.mock_calls == 2 * [call(100), call(250)]
        assert chipset.transport.write.mock_calls == 2 * [call(CMD(command))]

    def test_tg_init_as_target(self, chipset):
        chipset.transport.read.side_effect = [ACK(), RSP('8D 01 02 03')]
        mifare = HEX('010203040506')
        felica = HEX('010203040506070809101112131415161718')
        nfcid3 = HEX('01020304050607080910')
        gbytes = HEX('313233')
        args = (0x02, mifare, felica, nfcid3, gbytes, 0.5)
        assert chipset.tg_init_target(*args) == HEX('01 02 03')
        assert chipset.transport.read.mock_calls == [call(100), call(500)]
        assert chipset.transport.write.mock_calls == [
            call(CMD('8C 02 010203040506 010203040506070809101112131415161718'
                     '01020304050607080910 313233'))
        ]


class TestDevice(base_clf_pn53x.TestDevice):
    @pytest.fixture()
    def device(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('01'
                       '000102030405060708090a0b0c0d0e0f'
                       '101112131415161718191a1b1c1d1e1f'
                       '202122232425262728292a2b2c2d2e2f'
                       '303132333435363738393a3b3c3d3e3f'
                       '404142434445464748494a4b4c4d4e4f'
                       '505152535455565758595a5b5c5d5e5f'
                       '606162636465666768696a6b6c6d6e6f'
                       '707172737475767778797a7b7c7d7e7f'
                       '808182838485868788898a8b8c8d8e8f'
                       '909192939495969798999a9b9c9d9e9f'
                       'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
                       'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
                       'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                       'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
                       'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                       'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
                       '000102030405'),                   # Diagnose
            ACK(), RSP('03 33013007'),                    # GetFirmwareVersion
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('13'),                             # SetParameters
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        device = nfc.clf.rcs956.init(transport)
        device._path = 'usb:001:001'
        assert isinstance(device, nfc.clf.rcs956.Device)
        assert isinstance(device.chipset, nfc.clf.rcs956.Chipset)
        assert transport.write.mock_calls == [call(_) for _ in [
            ACK(),
            CMD('18 01'), ACK(),                          # ResetMode
            CMD('00 00'
                '000102030405060708090a0b0c0d0e0f'
                '101112131415161718191a1b1c1d1e1f'
                '202122232425262728292a2b2c2d2e2f'
                '303132333435363738393a3b3c3d3e3f'
                '404142434445464748494a4b4c4d4e4f'
                '505152535455565758595a5b5c5d5e5f'
                '606162636465666768696a6b6c6d6e6f'
                '707172737475767778797a7b7c7d7e7f'
                '808182838485868788898a8b8c8d8e8f'
                '909192939495969798999a9b9c9d9e9f'
                'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
                'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
                'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
                'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
                '000102030405'),                          # Diagnose
            CMD('02'),                                    # GetFirmwareVersion
            CMD('18 01'), ACK(),                          # ResetMode
            CMD('32 0102'),                               # RFConfiguration
            CMD('32 020b0b0a'),                           # RFConfiguration
            CMD('32 0400'),                               # RFConfiguration
            CMD('32 05000001'),                           # RFConfiguration
            CMD('32 0a5af43f114d85616f266287'),           # RFConfiguration
            CMD('12 08'),                                 # SetParameters
            CMD('18 01'), ACK(),                          # ResetMode
            CMD('08 032859'),                             # WriteRegister
        ]]
        transport.write.reset_mock()
        transport.read.reset_mock()
        yield device
        transport.write.reset_mock()
        transport.read.reset_mock()
        transport.read.side_effect = [
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        device.close()
        assert transport.write.mock_calls == [call(_) for _ in [
            CMD('18 01'), ACK(),                          # ResetMode
            CMD('32 0102'),                               # RFConfiguration
        ]]

    def test_device_name_fallback(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('01'
                       '000102030405060708090a0b0c0d0e0f'
                       '101112131415161718191a1b1c1d1e1f'
                       '202122232425262728292a2b2c2d2e2f'
                       '303132333435363738393a3b3c3d3e3f'
                       '404142434445464748494a4b4c4d4e4f'
                       '505152535455565758595a5b5c5d5e5f'
                       '606162636465666768696a6b6c6d6e6f'
                       '707172737475767778797a7b7c7d7e7f'
                       '808182838485868788898a8b8c8d8e8f'
                       '909192939495969798999a9b9c9d9e9f'
                       'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'
                       'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf'
                       'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
                       'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf'
                       'e0e1e2e3e4e5e6e7e8e9eaebecedeeef'
                       'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
                       '000102030405'),                   # Diagnose
            ACK(), RSP('03 33013007'),                    # GetFirmwareVersion
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('13'),                             # SetParameters
            ACK(), RSP('19'),                             # ResetMode
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        transport._product_name = None
        device = nfc.clf.rcs956.init(transport)
        assert isinstance(device, nfc.clf.rcs956.Device)
        assert device.product_name == "RC-S330"

    def reg_rsp(self, hexdata):
        return RSP('07' + hexdata)

    def __test_chipset_communication_fails(self, transport):
        transport.write.return_value = None
        transport.read.side_effect = [ACK(), ERR()]       # Diagnose
        chipset = nfc.clf.rcs956.Chipset(transport, logger=nfc.clf.rcs956.log)
        with pytest.raises(IOError):
            nfc.clf.rcs956.Device(chipset, logger=nfc.clf.rcs956.log)
        assert chipset.transport.write.mock_calls == [call(
            CMD('00 00' + ''.join(["%02x" % (x % 256) for x in range(262)])))
        ]

    def test_sense_tta_target_is_tt1(self, device):
        target = super(TestDevice, self).test_sense_tta_target_is_tt1(device)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.rid_res == HEX('1148 B2565400')
        assert target.sens_res == HEX('000C')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6339'),                               # ReadRegister
            CMD('4A 0104'),                               # InListPassiveTarget
            CMD('40 0178000000000000'),                   # InDataExchange
        ]]
        return target

    def test_sense_tta_large_mem_tt1(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('4B 00'),                          # InListPassiveTarget
            ACK(), self.reg_rsp('93'),                    # ReadRegister
            ACK(), RSP('4B 01010c00b2565400'),            # InListPassiveTarget
            ACK(), RSP('41 001248b2565400'),              # InDataExchange
        ]
        assert device.sense_tta(nfc.clf.RemoteTarget('106A')) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6339'),                               # ReadRegister
            CMD('4A 0104'),                               # InListPassiveTarget
            CMD('40 0178000000000000'),                   # InDataExchange
        ]]

    def test_sense_dep_no_target_found(self, device):
        atr_req = HEX('D400 30313233343536373839 00000000')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('47 01'),                          # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('32 020b0b0a'),                           # RFConfiguration
            CMD('46 01000230313233343536373839'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('47 02'),                          # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        assert device.sense_dep(target) is None
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('32 020b0b0a'),                           # RFConfiguration
            CMD('46 01000230313233343536373839'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]

    def test_sense_dep_target_found(self, device):
        atr_req = HEX('D400 30313233343536373839 00000002'
                      '46666d 010113 020207ff 040132 070107')
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('33'),                             # RFConfiguration
            ACK(), RSP('47 0001 66f6e98d1c13dfe56de4'
                       '0000000702 46666d 010112'
                       '020207ff 040164 070103'),         # InJumpForPSL
            ACK(), RSP('09 00'),                          # WriteRegister
        ]
        target = nfc.clf.RemoteTarget('106A', atr_req=atr_req)
        target = device.sense_dep(target)
        assert isinstance(target, nfc.clf.RemoteTarget)
        assert target.brty == '106A'
        assert target.atr_req == atr_req
        assert target.atr_res == HEX(
            'D501 66f6e98d1c13dfe56de4 0000000702'
            '46666d 010112 020207ff 040164 070103')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('32 020b0b0a'),                           # RFConfiguration
            CMD('46 010006 30313233343536373839 46666d'
                '010113 020207ff 040132 070107'),         # InJumpForPSL
            CMD('08 63013b'),                             # WriteRegister
        ]]
        return target

    @pytest.mark.parametrize("cmd, crcb1, crcb2", [
        ('02', '29', 'b7'),
        ('1B', '77', 'f0'),
        ('54', 'fc', '2c'),
    ])
    def test_send_cmd_recv_rsp_tt1_fifo(self, device, cmd, crcb1, crcb2):
        target = self.test_sense_tta_target_is_tt1(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        tt1_cmd = HEX('%s 10 0000000000000000' % cmd) + target.rid_res[2:6]
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            device.send_cmd_recv_rsp(target, tt1_cmd, 1.0)
        assert str(excinfo.value) == "tt1 command can not be send"
        print(device.chipset.transport.read.call_count)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('06 6302 6303 6305'),                     # ReadRegister
            CMD('08 630200 630300 630540'),               # WriteRegister
            CMD('32 020a0b0f'),                           # RFConfiguration
        ]]

    def test_send_cmd_recv_rsp_tt1_rseg(self, device):
        target = self.test_sense_tta_target_is_tt1(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        cmd = HEX('10 10 0000000000000000') + target.rid_res[2:6]
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            device.send_cmd_recv_rsp(target, cmd, 1.0)
        assert str(excinfo.value) == "tt1 command can not be send"

    def test_send_cmd_recv_rsp_tt1_fifo_with_timeout(self, device):
        target = self.test_sense_tta_target_is_tt1(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        cmd = HEX('02 10 0000000000000000') + target.rid_res[2:6]
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            device.send_cmd_recv_rsp(target, cmd, 1.0)
        assert str(excinfo.value) == "tt1 command can not be send"

    def test_send_cmd_recv_rsp_tt1_fifo_with_crc_error(self, device):
        target = self.test_sense_tta_target_is_tt1(device)
        device.chipset.transport.write.reset_mock()
        device.chipset.transport.read.reset_mock()
        device.chipset.transport.read.side_effect = [
            ACK(), self.reg_rsp('00 00 00'),              # ReadRegister
            ACK(), RSP('09 00'),                          # WriteRegister
            ACK(), RSP('33'),                             # RFConfiguration
        ]
        cmd = HEX('02 10 0000000000000000') + target.rid_res[2:6]
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            device.send_cmd_recv_rsp(target, cmd, 1.0)
        assert str(excinfo.value) == "tt1 command can not be send"

    def test_sense_tta_target_is_tt2(self, device):
        target = super(TestDevice, self).test_sense_tta_target_is_tt2(device)
        assert target.sens_res == HEX('4400')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
            CMD('06 6303'),                               # ReadRegister
            CMD('08 63037f'),                             # WriteRegister
        ]]
        return target

    def test_sense_tta_target_is_dep(self, device):
        target = super(TestDevice, self).test_sense_tta_target_is_dep(device)
        assert target.sens_res == HEX('4400')
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('4A 0100'),                               # InListPassiveTarget
        ]]
        return target

    def test_sense_ttb_target_found(self, device):
        base = super(TestDevice, self)
        base.test_sense_ttb_target_found(device, '42 CA 01')

    def test_sense_ttb_deselect_timeout(self, device):
        base = super(TestDevice, self)
        base.test_sense_ttb_deselect_timeout(device, '42 CA 01')

    def test_listen_tta_not_activated(self, device):
        super(TestDevice, self).test_listen_tta_not_activated(device)
        print(device.chipset.transport.write.mock_calls)
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('08 63013f'),                             # WriteRegister
            CMD('8c 0044000102030000 0102030405060708'
                '   090a0b0c0d0e0f10 1100010203040506'
                '   070000'),                             # TgInitAsTarget
            ACK(),
        ]]

    def test_listen_tta_as_tt4_activated(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            base = super(TestDevice, self)
            base.test_listen_tta_as_tt4_activated(device)

    def test_listen_tta_as_tt4_with_rats(self, device):
        pytest.skip("RCS956 does not support listen for T4AT")

    def test_listen_tta_as_tt4_rcvd_deselect(self, device):
        pytest.skip("RCS956 does not support listen for T4AT")

    def test_listen_tta_as_tt4_initiator_timeout(self, device):
        pytest.skip("RCS956 does not support listen for T4AT")

    def test_listen_tta_as_tt4_initiator_cmd_empty(self, device):
        pytest.skip("RCS956 does not support listen for T4AT")

    def test_listen_ttf_not_activated(self, device):
        with pytest.raises(nfc.clf.UnsupportedTargetError):
            base = super(TestDevice, self)
            base.test_listen_ttf_not_activated(device)

    def test_listen_ttf_get_activated(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_listen_ttf_frame_length_error(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_listen_ttf_unsupported_bitrate(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_listen_ttf_target_value_error(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_listen_dep_not_activated(self, device):
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX("D501 d0d1d2d3d4d5d6d7d8d9 0000000800")
        assert device.listen_dep(target, 0.001) is None
        assert device.chipset.transport.read.call_count == 12
        assert device.chipset.transport.write.mock_calls == [call(_) for _ in [
            CMD('18 01'), ACK(),                        # ResetMode
            CMD('08 630b80'),                           # WriteRegister
            CMD('32 82080208'),                         # RFConfiguration
            CMD('12 08'),                               # SetParameters
            CMD('08 63017b6302b06303b0'),               # WriteRegister
            CMD('8c 0201010102034001 fe01020304050600'
                '   0000000000000000 0001fe0102030405'
                '   060000'),                           # TgInitAsTarget
            ACK(),
        ]]

    def test_listen_dep_passive_106A(self, device):
        sensf_res = '01 01fe010203040506 0000000000000000 0000'
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "106A"
        assert target.sensf_res is None
        assert target.sens_res == HEX("0101")
        assert target.sel_res == HEX("40")
        assert target.sdd_res == HEX("08010203")
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req is None
        assert target.psl_res is None
        assert target.dep_req == HEX(dep_req)
        assert device.chipset.transport.read.call_count == 18
        return target

    def test_listen_dep_passive_424F(self, device):
        sensf_res = '01 01fe010203040506 0000000000000000 0000'
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 26 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX(sensf_res)
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.sensf_res == HEX(sensf_res)
        assert target.sens_res is None
        assert target.sel_res is None
        assert target.sdd_res is None
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req is None
        assert target.psl_res is None
        assert target.dep_req == HEX(dep_req)
        assert device.chipset.transport.read.call_count == 18
        return target

    def test_listen_dep_passive_106A_psl_to_424F(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        psl_res = 'D505 00'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('00'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('00'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req == HEX(psl_req)
        assert target.psl_res == HEX(psl_res)
        assert target.dep_req == HEX(dep_req)
        assert target.sensf_res is None
        assert target.sens_res == HEX("0101")
        assert target.sel_res == HEX("40")
        assert target.sdd_res == HEX("08010203")
        assert device.chipset.transport.read.call_count == 30
        return target

    def test_listen_dep_active_106A_psl_to_424F(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        psl_res = 'D505 00'
        dep_req = 'D406000000'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
            ACK(), RSP('09 00'),                        # WriteRegister
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        target = device.listen_dep(target, 1.0)
        assert isinstance(target, nfc.clf.LocalTarget)
        assert target.brty == "424F"
        assert target.atr_req == HEX(atr_req)
        assert target.atr_res == HEX(atr_res)
        assert target.psl_req == HEX(psl_req)
        assert target.psl_res == HEX(psl_res)
        assert target.dep_req == HEX(dep_req)
        assert target.sensf_res is None
        assert target.sens_res is None
        assert target.sel_res is None
        assert target.sdd_res is None
        assert device.chipset.transport.read.call_count == 30
        return target

    @pytest.mark.parametrize("dep_req", ['D405000000ff', '0000000000'])
    def test_listen_dep_command_data_error(self, device, dep_req):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 04 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + dep_req),           # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX('01 01fe010203040506 0000000000000000 0000')
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_chipset_timeout_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('89 01'),                        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 28

    def test_listen_dep_ioerror_timeout_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 28

    def test_listen_dep_ioerror_exception_after_psl(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        psl_req = 'D404 00 12 03'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('91 00'),                        # TgResponseToInitiator
            ACK(), self.reg_rsp('FD'),                  # ReadRegister
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), IOError(errno.EIO, ""),              # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 28

    def test_listen_dep_chipset_timeout_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 01'),                        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_ioerror_timeout_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_ioerror_exception_after_atr(self, device):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), IOError(errno.EIO, ""),              # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 16

    def test_listen_dep_not_atr_and_then_ioerror(self, device):
        atr_req = 'D4FF 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), IOError(errno.ETIMEDOUT, ""),        # TgInitAsTarget
            ACK(), IOError(errno.EIO, ""),              # TgInitAsTarget
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        with pytest.raises(IOError):
            device.listen_dep(target, 1.0)
        assert device.chipset.transport.read.call_count == 16

    @pytest.mark.parametrize("psl_req", [
        'D404 00 12 03 FF', 'D404 01 12 03'
    ])
    def test_listen_dep_active_106A_psl_req_error(self, device, psl_req):
        atr_req = 'D400 30313233343536373839 00000000'
        atr_res = 'D501 d0d1d2d3d4d5d6d7d8d9 0000000800'
        device.chipset.transport.read.side_effect = [
            ACK(), RSP('19'),                           # ResetMode
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('33'),                           # RFConfiguration
            ACK(), RSP('13'),                           # SetParameters
            ACK(), RSP('09 00'),                        # WriteRegister
            ACK(), RSP('8D 05 11' + atr_req),           # TgInitAsTarget
            ACK(), RSP('93 00'),                        # TgSetGeneralBytes
            ACK(), RSP('89 00 06' + psl_req),           # TgGetInitiatorCommand
        ]
        target = nfc.clf.LocalTarget()
        target.sensf_res = HEX("01 01fe010203040506 0000000000000000 0000")
        target.sens_res = HEX("0101")
        target.sel_res = HEX("40")
        target.sdd_res = HEX("08010203")
        target.atr_res = HEX(atr_res)
        assert device.listen_dep(target, 1.0) is None
        assert device.chipset.transport.read.call_count == 16

    def test_send_rsp_recv_cmd_with_tt3_target(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_send_rsp_recv_cmd_tt3_not_send_data(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_send_rsp_recv_cmd_tt3_timeout_error(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_send_rsp_recv_cmd_tt3_broken_link(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_send_rsp_recv_cmd_tt3_frame_error(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_send_rsp_recv_cmd_tt3_timeout_zero(self, device):
        pytest.skip("RCS956 does not support ttf listen mode")

    def test_get_max_send_data_size(self, device):
        assert device.get_max_send_data_size(target=None) == 263

    def test_get_max_recv_data_size(self, device):
        assert device.get_max_recv_data_size(target=None) == 262
