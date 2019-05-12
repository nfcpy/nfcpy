# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.tag
import nfc.tag.tt4

import mock
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt4").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.mark.parametrize(  # noqa: F811
    "rats_response, max_send, max_recv, result", [
    ('067077010280', 256, 256, "Type4ATag MIU=15 FWT=0.000302"),
    ('067177110280', 256, 256, "Type4ATag MIU=23 FWT=0.000604"),
    ('067277210280', 256, 256, "Type4ATag MIU=31 FWT=0.001208"),
    ('067377310280', 256, 256, "Type4ATag MIU=39 FWT=0.002417"),
    ('067477410280', 256, 256, "Type4ATag MIU=47 FWT=0.004833"),
    ('067577510280', 256, 256, "Type4ATag MIU=63 FWT=0.009666"),
    ('067677610280', 256, 256, "Type4ATag MIU=95 FWT=0.019332"),
    ('067777710280', 256, 256, "Type4ATag MIU=127 FWT=0.038664"),
    ('067877810280', 256, 256, "Type4ATag MIU=255 FWT=0.077329"),
    ('067977910280', 256, 256, "Type4ATag MIU=255 FWT=0.154657"),
    ('067A77A10280', 256, 256, "Type4ATag MIU=255 FWT=0.309314"),
    ('067B77B10280', 256, 256, "Type4ATag MIU=255 FWT=0.618629"),
    ('067C77C10280', 256, 256, "Type4ATag MIU=255 FWT=1.237258"),
    ('067D77D10280', 256, 256, "Type4ATag MIU=255 FWT=2.474516"),
    ('067E77E10280', 256, 256, "Type4ATag MIU=255 FWT=4.949031"),
    ('067F77F10280', 256, 256, "Type4ATag MIU=255 FWT=0.004833"),
    ('067F77F10280', 255, 255, "Type4ATag MIU=254 FWT=0.004833"),
])
def test_init_T4A(mocker, rats_response, max_send, max_recv, result):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch('nfc.ContactlessFrontend.max_send_data_size',
                 new_callable=mock.PropertyMock).return_value = max_send
    mocker.patch('nfc.ContactlessFrontend.max_recv_data_size',
                 new_callable=mock.PropertyMock).return_value = max_recv

    target = nfc.clf.RemoteTarget("106A")
    target.sens_res = HEX("4403")
    target.sel_res = HEX("20")
    target.sdd_res = HEX("04832F9A272D80")

    rats_command = 'E070' if max_recv < 256 else 'E080'
    clf.exchange.return_value = HEX(rats_response)
    tag = nfc.tag.activate(clf, target)
    clf.exchange.assert_called_once_with(HEX(rats_command), 0.03)
    assert isinstance(tag, nfc.tag.tt4.Type4Tag)
    assert str(tag) == result


@pytest.mark.parametrize(  # noqa: F811
    "sensb_res, max_send, max_recv, result", [
    ('5030702A1C00000011000105', 256, 256, "Type4BTag MIU=15 FWT=0.000302"),
    ('5030702A1C00000011001115', 256, 256, "Type4BTag MIU=23 FWT=0.000604"),
    ('5030702A1C00000011002125', 256, 256, "Type4BTag MIU=31 FWT=0.001208"),
    ('5030702A1C00000011003135', 256, 256, "Type4BTag MIU=39 FWT=0.002417"),
    ('5030702A1C00000011004145', 256, 256, "Type4BTag MIU=47 FWT=0.004833"),
    ('5030702A1C00000011005155', 256, 256, "Type4BTag MIU=63 FWT=0.009666"),
    ('5030702A1C00000011006165', 256, 256, "Type4BTag MIU=95 FWT=0.019332"),
    ('5030702A1C00000011007175', 256, 256, "Type4BTag MIU=127 FWT=0.038664"),
    ('5030702A1C00000011008185', 256, 256, "Type4BTag MIU=255 FWT=0.077329"),
    ('5030702A1C00000011009195', 256, 256, "Type4BTag MIU=255 FWT=0.154657"),
    ('5030702A1C0000001100A1A5', 256, 256, "Type4BTag MIU=255 FWT=0.309314"),
    ('5030702A1C0000001100B1B5', 256, 256, "Type4BTag MIU=255 FWT=0.618629"),
    ('5030702A1C0000001100C1C5', 256, 256, "Type4BTag MIU=255 FWT=1.237258"),
    ('5030702A1C0000001100D1D5', 256, 256, "Type4BTag MIU=255 FWT=2.474516"),
    ('5030702A1C0000001100E1E5', 256, 256, "Type4BTag MIU=255 FWT=4.949031"),
    ('5030702A1C0000001100F1F5', 256, 256, "Type4BTag MIU=255 FWT=0.004833"),
    ('5030702A1C0000001100F1F5', 255, 255, "Type4BTag MIU=254 FWT=0.004833"),
])
def test_init_T4B(mocker, sensb_res, max_send, max_recv, result):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch('nfc.ContactlessFrontend.max_send_data_size',
                 new_callable=mock.PropertyMock).return_value = max_send
    mocker.patch('nfc.ContactlessFrontend.max_recv_data_size',
                 new_callable=mock.PropertyMock).return_value = max_recv

    target = nfc.clf.RemoteTarget("106B")
    target.sensb_res = HEX(sensb_res)

    attrib_cmd = '1D30702A1C' + ('00070100' if max_recv < 256 else '00080100')
    clf.exchange.return_value = HEX('00')
    tag = nfc.tag.activate(clf, target)
    clf.exchange.assert_called_once_with(HEX(attrib_cmd), 0.03)
    assert isinstance(tag, nfc.tag.tt4.Type4Tag)
    assert str(tag) == result


def test_init_wrong_technology():
    clf = nfc.ContactlessFrontend()
    target = nfc.clf.RemoteTarget('212F')
    assert nfc.tag.tt4.activate(clf, target) is None


class TestType4Tag:
    @pytest.fixture()  # noqa: F811
    def clf(self, mocker):
        clf = nfc.ContactlessFrontend()
        mocker.patch.object(clf, 'exchange', autospec=True)
        mocker.patch('nfc.ContactlessFrontend.max_send_data_size',
                     new_callable=mock.PropertyMock).return_value = 256
        mocker.patch('nfc.ContactlessFrontend.max_recv_data_size',
                     new_callable=mock.PropertyMock).return_value = 256
        return clf

    @pytest.fixture()
    def target(self):
        target = nfc.clf.RemoteTarget("106A")
        target.sens_res = HEX("4403")
        target.sel_res = HEX("20")
        target.sdd_res = HEX("04832F9A272D80")
        return target

    @pytest.fixture()
    def tag(self, clf, target):
        clf.exchange.side_effect = [HEX('067577810280')]
        tag = nfc.tag.activate(clf, target)
        clf.exchange.assert_called_once_with(HEX('E0 80'), 0.03)
        assert isinstance(tag, nfc.tag.tt4.Type4Tag)
        clf.exchange.reset_mock()
        return tag

    def test_is_present(self, tag):
        commands = [
            (HEX('B2'), 0.08095339233038348),
            (HEX('B2'), 0.08095339233038348),
        ]
        responses = [
            HEX('A3'),
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.is_present is True
        assert tag.is_present is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_dump_ndef_until_command_error(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20003b00340406e10408000000 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55036e666370792e6f7267 9000'),
            HEX('03 000ed1010a55036e666370792e6f7267 9000'),
            HEX('02 00000000000000000000000000000000 9000'),
            HEX('03 6985')
        ]
        tag.clf.exchange.side_effect = responses
        assert '\n'.join(tag.dump()) == """
0x0000: 00 0e d1 01 0a 55 03 6e 66 63 70 79 2e 6f 72 67 |.....U.nfcpy.org|
0x0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
""".strip()

    def test_dump_ndef_until_no_bytes_returned(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20003b00340406e10408000000 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55036e666370792e6f7267 9000'),
            HEX('03 000ed1010a55036e666370792e6f7267 9000'),
            HEX('02 00000000000000000000000000000000 9000'),
            HEX('03 9000')
        ]
        tag.clf.exchange.side_effect = responses
        assert '\n'.join(tag.dump()) == """
0x0000: 00 0e d1 01 0a 55 03 6e 66 63 70 79 2e 6f 72 67 |.....U.nfcpy.org|
0x0010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
""".strip()

    def test_dump_ndef_read_access_not_zero(self, tag):
        responses = [
            HEX('029000'),
            HEX('039000'),
            HEX('02000f9000'),
            HEX('0320003b00340406 e104 0040 80 00 9000'),
            HEX('029000'),
            HEX('03000e9000'),
            HEX('02d1010a55036e666370792e6f72679000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.dump() == []

    def test_format_ndef_wipe_all_data(self, tag):
        commands = [
            (HEX('0200a4040007d2760000850101'), 0.08095339233038348),
            (HEX('0300a4000c02e103'), 0.08095339233038348),
            (HEX('0200b0000002'), 0.08095339233038348),
            (HEX('0300b000020d'), 0.08095339233038348),
            (HEX('0200a4000c02e104'), 0.08095339233038348),
            (HEX('0300b0000002'), 0.08095339233038348),
            (HEX('0200b000020e'), 0.08095339233038348),
            (HEX('0300d60000020000'), 0.08095339233038348),
            (HEX('0200d6000234a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9'
                 'a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9'),
             0.08095339233038348),
            (HEX('0300d6003608a9a9a9a9a9a9a9a9'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e9000'),
            HEX('02 d1010a55036e666370792e6f7267 9000'),
            HEX('03 9000'),
            HEX('02 9000'),
            HEX('03 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format(wipe=0xA9) is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_wipe_is_none(self, tag):
        commands = [
            (HEX('02 00a4040007d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
            (HEX('02 00b000020e'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55036e666370792e6f7267 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format() is True
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_wipe_failure(self, tag):
        commands = [
            (HEX('02 00a4040007d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
            (HEX('02 00b000020e'), 0.08095339233038348),
            (HEX('03 00d60000020000'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55036e666370792e6f7267 9000'),
            HEX('03 ffff'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format(wipe=0) is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_format_ndef_write_not_allowed(self, tag):
        commands = [
            (HEX('0200a4040007d2760000850101'), 0.08095339233038348),
            (HEX('0300a4000c02e103'), 0.08095339233038348),
            (HEX('0200b0000002'), 0.08095339233038348),
            (HEX('0300b000020d'), 0.08095339233038348),
            (HEX('0200a4000c02e104'), 0.08095339233038348),
            (HEX('0300b0000002'), 0.08095339233038348),
            (HEX('0200b000020e'), 0.08095339233038348),
        ]
        responses = [
            HEX('029000'),
            HEX('039000'),
            HEX('02000f9000'),
            HEX('0320003b00340406e104 0040 00 80 9000'),
            HEX('029000'),
            HEX('03000e9000'),
            HEX('02d1010a55036e666370792e6f72679000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.format(wipe=0xA9) is False
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    @pytest.mark.parametrize("cc_file, access", [
        (HEX('000f 20 003b 0034 04 06 e104 0040 00 00'), 'rw'),
        (HEX('000f 20 003b 0034 04 06 e104 0040 80 00'), '.w'),
        (HEX('000f 20 003b 0034 04 06 e104 0040 00 80'), 'r.'),
        (HEX('000f 20 003b 0034 04 06 e104 0040 81 81'), '..'),
    ])
    def test_discover_ndef_access_rights(self, tag, cc_file, access):
        commands = [
            (HEX('0200a4040007d2760000850101'), 0.08095339233038348),
            (HEX('0300a4000c02e103'), 0.08095339233038348),
            (HEX('0200b0000002'), 0.08095339233038348),
            (HEX('0300b000020d'), 0.08095339233038348),
            (HEX('0200a4000c02e104'), 0.08095339233038348),
            (HEX('0300b0000002'), 0.08095339233038348),
            (HEX('0200b000020e'), 0.08095339233038348),
        ]
        responses = [
            HEX('029000'),
            HEX('039000'),
            HEX('02') + cc_file[:2] + HEX('9000'),
            HEX('03') + cc_file[2:] + HEX('9000'),
            HEX('029000'),
            HEX('03000e9000'),
            HEX('02d1010a55036e666370792e6f72679000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert isinstance(tag.ndef, nfc.tag.tt4.Type4Tag.NDEF)
        assert tag.ndef.is_readable is bool(access[0] == 'r')
        assert tag.ndef.is_writeable is bool(access[1] == 'w')
        assert tag.ndef.capacity == 62
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_discover_ndef_invalid_control_tlv(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 05 05 e104 0040 00 00 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None

    @pytest.mark.parametrize("ver, result", [
        ('00', type(None)),
        ('10', nfc.tag.tt4.Type4Tag.NDEF),
        ('20', nfc.tag.tt4.Type4Tag.NDEF),
        ('30', nfc.tag.tt4.Type4Tag.NDEF),
        ('40', type(None)),
    ])
    def test_discover_ndef_version(self, tag, ver, result):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 %s 003b 0034 04 06 e104 0040 00 00 9000' % ver),
            HEX('02 9000'),
            HEX('03 000e9000'),
            HEX('02 d1010a55 036e6663 70792e6f 7267 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert isinstance(tag.ndef, result)

    def test_discover_ndef_cc_length_is_14(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000e 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None

    def test_discover_ndef_cc_length_is_1(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 00 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None

    def test_discover_ndef_no_capabilities_file(self, tag):
        responses = [
            HEX('02 9000'),
            HEX('03 ffff'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None

    def test_discover_ndef_no_application_file(self, tag):
        commands = [
            (HEX('0200a4040007d2760000850101'), 0.08095339233038348),
            (HEX('0300a4040007d2760000850100'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 ffff'),
            HEX('03 ffff'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_discover_ndef_fail_application_file(self, tag):
        commands = [
            (HEX('0200a4040007d2760000850101'), 0.08095339233038348),
            (HEX('b2'), 0.08095339233038348),
            (HEX('b2'), 0.08095339233038348),
            (HEX('b2'), 0.08095339233038348),
            (HEX('b2'), 0.08095339233038348),
            (HEX('b2'), 0.08095339233038348),
        ]
        responses = 6 * [
            nfc.clf.TimeoutError,
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_ndef_data_failure_in_part(self, tag):
        commands = [
            (HEX('02 00a4040007d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
            (HEX('02 00b000020e'), 0.08095339233038348),
            (HEX('03 00b0000f01'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55 036e6663 70792e6f 72 9000'),
            HEX('02 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_ndef_data_failure_in_length(self, tag):
        commands = [
            (HEX('02 00a4040007d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 00 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_read_ndef_data_failure_in_select(self, tag):
        commands = [
            (HEX('02 00a4040007d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02e104'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 ffff'),
        ]
        tag.clf.exchange.side_effect = responses
        assert tag.ndef is None
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_ndef_data_short(self, tag):
        commands = [
            (HEX('02 00a4040007 d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02 e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02 e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
            (HEX('02 00b000020e'), 0.08095339233038348),
            (HEX('03 00d6000005 0003d50000'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55 036e6663 70792e6f 7267 9000'),
            HEX('03 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert isinstance(tag.ndef, nfc.tag.tt4.Type4Tag.NDEF)
        tag.ndef.octets = HEX('D50000')
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_write_ndef_data_long(self, tag):
        commands = [
            (HEX('02 00a4040007 d2760000850101'), 0.08095339233038348),
            (HEX('03 00a4000c02 e103'), 0.08095339233038348),
            (HEX('02 00b0000002'), 0.08095339233038348),
            (HEX('03 00b000020d'), 0.08095339233038348),
            (HEX('02 00a4000c02 e104'), 0.08095339233038348),
            (HEX('03 00b0000002'), 0.08095339233038348),
            (HEX('02 00b000020e'), 0.08095339233038348),
            (HEX('03 00d6000034 0000d5003b30 30303030 30303030 30303030'
                 '30303030 30303030 30303030 30303030 30303030 30303030'
                 '30303030 30303030 3030'), 0.08095339233038348),
            (HEX('02 00d600340c 30303030 30303030 30303030'),
             0.08095339233038348),
            (HEX('03 00d6000002 003e'), 0.08095339233038348),
        ]
        responses = [
            HEX('02 9000'),
            HEX('03 9000'),
            HEX('02 000f 9000'),
            HEX('03 20 003b 0034 04 06 e104 0040 00 00 9000'),
            HEX('02 9000'),
            HEX('03 000e 9000'),
            HEX('02 d1010a55 036e6663 70792e6f 7267 9000'),
            HEX('03 9000'),
            HEX('02 9000'),
            HEX('03 9000'),
        ]
        tag.clf.exchange.side_effect = responses
        assert isinstance(tag.ndef, nfc.tag.tt4.Type4Tag.NDEF)
        tag.ndef.octets = HEX('D5003B') + 59 * b'0'
        assert tag.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_apdu_standard_length(self, tag):
        with pytest.raises(ValueError) as excinfo:
            tag.send_apdu(0, 0, 0, 0, 256 * b'\0')
        assert str(excinfo.value) == "unsupported command data length"

        with pytest.raises(ValueError) as excinfo:
            tag.send_apdu(0, 0, 0, 0, mrl=257)
        assert str(excinfo.value) == "unsupported max response length"

        tag.clf.exchange.side_effect = [HEX('02 A9 9000')]
        assert tag.send_apdu(1, 2, 3, 4, b'56') == b'\xA9'
        tag.clf.exchange.assert_called_once_with(
            HEX('02 01020304 02 3536'), 0.08095339233038348)

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [HEX('03 9A 9000')]
        assert tag.send_apdu(1, 2, 3, 4, mrl=1) == b'\x9A'
        tag.clf.exchange.assert_called_once_with(
            HEX('03 01020304 01'), 0.08095339233038348)

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [HEX('02 A99A 9000')]
        assert tag.send_apdu(1, 2, 3, 4, b'56', 1) == b'\xA9\x9A'
        tag.clf.exchange.assert_called_once_with(
            HEX('02 01020304 02 3536 01'), 0.08095339233038348)

    def test_send_apdu_extended_length(self, tag):
        tag._extended_length_support = True

        with pytest.raises(ValueError) as excinfo:
            tag.send_apdu(0, 0, 0, 0, 65536 * b'\0')
        assert str(excinfo.value) == "invalid command data length"

        with pytest.raises(ValueError) as excinfo:
            tag.send_apdu(0, 0, 0, 0, mrl=65537)
        assert str(excinfo.value) == "invalid max response length"

        tag.clf.exchange.side_effect = [HEX('02 A9 9000')]
        assert tag.send_apdu(1, 2, 3, 4, b'56') == b'\xA9'
        tag.clf.exchange.assert_called_once_with(
            HEX('02 01020304 000002 3536'), 0.08095339233038348)

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [HEX('03 9A 9000')]
        assert tag.send_apdu(1, 2, 3, 4, mrl=1) == b'\x9A'
        tag.clf.exchange.assert_called_once_with(
            HEX('03 01020304 000001'), 0.08095339233038348)

        tag.clf.exchange.reset_mock()
        tag.clf.exchange.side_effect = [HEX('02 A99A 9000')]
        assert tag.send_apdu(1, 2, 3, 4, b'56', 1) == b'\xA9\x9A'
        tag.clf.exchange.assert_called_once_with(
            HEX('02 01020304 000002 3536 0001'), 0.08095339233038348)

    def test_send_apdu_return_errors(self, tag):
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            tag.clf.exchange.side_effect = [HEX('02 90')]
            tag.send_apdu(1, 2, 3, 4, b'56', 1)
        assert excinfo.value.errno == -2

        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            tag.clf.exchange.side_effect = [HEX('03 9192')]
            tag.send_apdu(1, 2, 3, 4, b'56', 1)
        assert excinfo.value.errno == 0x9192


class TestIsoDepInitiator:
    @pytest.fixture()  # noqa: F811
    def clf(self, mocker):
        clf = nfc.ContactlessFrontend()
        mocker.patch.object(clf, 'exchange', autospec=True)
        mocker.patch('nfc.ContactlessFrontend.max_send_data_size',
                     new_callable=mock.PropertyMock).return_value = 256
        mocker.patch('nfc.ContactlessFrontend.max_recv_data_size',
                     new_callable=mock.PropertyMock).return_value = 256
        return clf

    @pytest.fixture()
    def dep(self, clf):
        return nfc.tag.tt4.IsoDepInitiator(clf, 8, 1.0)

    def test_presence_check_and_timeout(self, dep):
        commands = [
            (HEX('B2'), 1.003624778761062),
            (HEX('B2'), 1.0),
            (HEX('B2'), 2.0),
        ]
        responses = [
            HEX('02 0000'),
            HEX('02 0000'),
            nfc.clf.TimeoutError,
        ]
        dep.clf.exchange.side_effect = responses
        dep.exchange(None)
        dep.exchange(None, 1.0)
        with pytest.raises(nfc.clf.TimeoutError):
            dep.exchange(None, 2.0)
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_less_than_miu(self, dep):
        commands = [
            (HEX('02 01'), 1.0),
            (HEX('03 0102'), 1.0),
            (HEX('02 01020304050607'), 1.0),
        ]
        responses = [
            HEX('02 0203'),
            HEX('03 0203'),
            HEX('02 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('01'), 1.0) == HEX('0203')
        assert dep.exchange(HEX('0102'), 1.0) == HEX('0203')
        assert dep.exchange(HEX('01020304050607'), 1.0) == HEX('0203')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_more_than_miu(self, dep):
        commands = [
            (HEX('12 01020304050607'), 1.0),
            (HEX('03 08'), 1.0)
        ]
        responses = [
            HEX('A2'),
            HEX('03 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102030405060708'), 1.0) == HEX('0203')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_retransmit_after_ack(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('02 0102'), 1.0),
        ]
        responses = [
            HEX('A3'),
            HEX('02 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('0203')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_with_transmission_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('B2'), 1.0),
            (HEX('03 0304'), 1.0),
            (HEX('B3'), 1.0),
        ]
        responses = [
            HEX(''),
            HEX('02 0203'),
            HEX(''),
            HEX(''),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('0203')
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0304'), 1.0)
        assert excinfo.value.errno == nfc.tag.RECEIVE_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_with_timeout_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('B2'), 1.0),
            (HEX('03 0304'), 1.0),
            (HEX('B3'), 1.0),
        ]
        responses = [
            nfc.clf.TimeoutError,
            HEX('02 0203'),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('0203')
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0304'), 1.0)
        assert excinfo.value.errno == nfc.tag.TIMEOUT_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_with_protocol_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
        ]
        responses = [
            nfc.clf.ProtocolError,
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_recv_waiting_time_ext(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('F2 02'), 2.0),
        ]
        responses = [
            HEX('F2 02'),
            HEX('02 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('0203')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_recv_wrong_pni(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
        ]
        responses = [
            HEX('03 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_more_recv_not_ack(self, dep):
        commands = [
            (HEX('12 01020304050607'), 1.0),
        ]
        responses = [
            HEX('02 0203'),
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102030405060708'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_send_last_recv_not_inf(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
        ]
        responses = [
            HEX('22'),
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_with_no_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A2'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            HEX('13 0304'),
            HEX('02 0506'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('010203040506')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_retry_transmission_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A2'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            HEX(''),
            HEX('13 0304'),
            HEX('02 0506'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('010203040506')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_with_transmission_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A3'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            HEX(''),
            HEX(''),
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.RECEIVE_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_retry_timeout_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A2'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            nfc.clf.TimeoutError,
            HEX('13 0304'),
            HEX('02 0506'),
        ]
        dep.clf.exchange.side_effect = responses
        assert dep.exchange(HEX('0102'), 1.0) == HEX('010203040506')
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_with_timeout_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A3'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.TIMEOUT_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_with_protocol_error(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            nfc.clf.ProtocolError,
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]

    def test_recv_more_with_wrong_pni(self, dep):
        commands = [
            (HEX('02 0102'), 1.0),
            (HEX('A3'), 1.0),
            (HEX('A2'), 1.0),
        ]
        responses = [
            HEX('12 0102'),
            HEX('13 0304'),
            HEX('03 0506'),
        ]
        dep.clf.exchange.side_effect = responses
        with pytest.raises(nfc.tag.tt4.Type4TagCommandError) as excinfo:
            dep.exchange(HEX('0102'), 1.0)
        assert excinfo.value.errno == nfc.tag.PROTOCOL_ERROR
        assert dep.clf.exchange.mock_calls == [mock.call(*_) for _ in commands]
