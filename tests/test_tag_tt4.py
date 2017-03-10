# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import sys
import mock
import pytest
from pytest_mock import mocker  # noqa: F401

import logging
logging.basicConfig(level=logging.WARN)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.tag").setLevel(logging_level)
logging.getLogger("nfc.tag.tt4").setLevel(logging_level)

sys.modules['usb1'] = mock.Mock  # fake usb1 for testing on travis-ci


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

    def test_dump(self, tag):
        responses = [
            HEX('029000'),
            HEX('039000'),
            HEX('02000f9000'),
            HEX('0320003b00340406e104080000009000'),
            HEX('029000'),
            HEX('03000e9000'),
            HEX('02d1010a55036e666370792e6f72679000'),
            HEX('03000ed1010a55036e666370792e6f72679000'),
            HEX('027265346d6f62696c652e6f72675101109000'),
            HEX('035402656e4d4946415245346d6f62696c9000'),
            HEX('02650000000000000000000000000000009000'),
        ] + 64 * [
            HEX('03000000000000000000000000000000009000'),
            HEX('02000000000000000000000000000000009000'),
        ] + [
            HEX('036985')
        ]
        tag.clf.exchange.side_effect = responses
        lines = tag.dump()
        assert len(lines) == 132
        assert '\n'.join(lines[:10]) == """
0x0000: 00 0e d1 01 0a 55 03 6e 66 63 70 79 2e 6f 72 67 |.....U.nfcpy.org|
0x0010: 72 65 34 6d 6f 62 69 6c 65 2e 6f 72 67 51 01 10 |re4mobile.orgQ..|
0x0020: 54 02 65 6e 4d 49 46 41 52 45 34 6d 6f 62 69 6c |T.enMIFARE4mobil|
0x0030: 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |e...............|
0x0040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
0x0050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
0x0060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
0x0070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
0x0080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
0x0090: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 |................|
""".strip()
