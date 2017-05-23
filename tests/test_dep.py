# -*- coding: latin-1 -*-
from __future__ import absolute_import, division

import nfc
import nfc.dep

import pytest
from pytest_mock import mocker  # noqa: F401
from mock import call

import logging
logging.basicConfig(level=logging.DEBUG-1)
logging_level = logging.getLogger().getEffectiveLevel()
logging.getLogger("nfc.dep").setLevel(logging_level)


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("106A")
    target.sens_res = HEX("4400")
    target.sel_res = HEX("00")
    target.sdd_res = HEX("0102030405060708")
    return target


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    mocker.patch.object(clf, 'sense', autospec=True)
    clf.sense.return_value = None
    return clf


class TestInitiator:
    atr_res = 'D501 01FE0102030405060708 0000000832 46666D010113'
    atr_res_frame = '18' + atr_res

    @pytest.fixture()
    def dep(self, clf):
        return nfc.dep.Initiator(clf)

    def test_activate_active_no_target_found(self, dep):
        assert dep.activate(acm=True) is None
        assert dep.clf.sense.call_count == 3

    @pytest.mark.parametrize("brty", ["106A", "212F", "424F"])
    def test_activate_active_target_without_psl(self, dep, brty):
        target = nfc.clf.RemoteTarget(brty, atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    @pytest.mark.parametrize("brs, brty", [(1, "212F"), (2, "424F")])
    def test_activate_active_target_106_with_psl(self, dep, brs, brty):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('F0 04 D50500')]
        assert dep.activate(None, brs=brs) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    @pytest.mark.parametrize("brs, brty", [(1, "212F"), (2, "424F")])
    def test_activate_active_target_212_with_psl(self, dep, brs, brty):
        target = nfc.clf.RemoteTarget("212F", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('04 D50500')]
        assert dep.activate(None, brs=brs) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == brty
        assert dep.acm is True

    def test_activate_psl_res_communication_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [nfc.clf.CommunicationError]
        assert dep.activate() is None

    def test_activate_passive_no_target_found(self, dep):
        assert dep.activate(acm=False) is None
        assert dep.clf.sense.call_count == 2

    def test_activate_passive_target_106(self, dep):
        target = nfc.clf.RemoteTarget("106A")
        target.sens_res = HEX('0101')
        target.sdd_res = HEX('01020304')
        target.sel_res = HEX('40')
        dep.clf.sense.side_effect = [None, target]
        dep.clf.exchange.side_effect = [HEX('F0' + self.atr_res_frame)]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == "106A"
        assert dep.acm is False

    def test_activate_passive_target_212(self, dep):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX('01 01FE010203040506 0000000000000000')
        dep.clf.sense.side_effect = [None, None, target]
        dep.clf.exchange.side_effect = [HEX(self.atr_res_frame)]
        assert dep.activate(None, brs=1) == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.target.brty == "212F"
        assert dep.acm is False

    def test_activate_atr_res_communication_error(self, dep):
        target = nfc.clf.RemoteTarget("212F")
        target.sensf_res = HEX('01 01FE010203040506 0000000000000000')
        dep.clf.sense.side_effect = [None, None, target]
        dep.clf.exchange.side_effect = [nfc.clf.CommunicationError]
        assert dep.activate(None, brs=1) is None

    def test_activate_active_target_unsupported_error(self, dep):
        dep.clf.sense.side_effect = [
            nfc.clf.UnsupportedTargetError, None, None, None, None,
        ]
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 3
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 5

    def test_activate_active_target_communication_error(self, dep):
        dep.clf.sense.side_effect = [
            nfc.clf.CommunicationError, None, None, None, None, None,
        ]
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 3
        assert dep.activate() is None
        assert dep.clf.sense.call_count == 6

    @pytest.mark.parametrize("release, command, response", [
        (True, 'F004D40A00', 'F004D50B00'),
        (True, 'F004D40A00', 'F004D50B01'),
        (False, 'F004D40800', 'F004D50900'),
        (False, 'F004D40800', 'F004D50901'),
        (True, 'F004D40A00', 'F004D50900'),
        (False, 'F004D40800', 'F004D50B00'),
    ])
    def test_deactivate_with_rls_or_dsl(self, dep, release, command, response):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX(response)]
        assert dep.activate(None, did=0, brs=0) == HEX('46666D010113')
        assert dep.deactivate(release) is None
        assert dep.clf.exchange.mock_calls == [call(HEX(command), 0.1)]

    def test_exchange_two_bytes_at_106_kbps(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('F0 06 D507 00 0304')]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.exchange(HEX('0102'), timeout=1) == HEX('0304')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_miu_bytes_at_106_kbps(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [HEX('F0 FF D507 00' + 251 * 'bb')]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.miu == 251
        assert dep.exchange(HEX(251 * 'aa'), timeout=1) == HEX(251 * 'bb')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 00' + 251 * 'aa'), 0.07732861356932154),
        ]

    def test_exchange_more_bytes_at_106_kbps(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 40'),
            HEX('F0 FF D507 11' + 251 * 'bb'),
            HEX('F0 05 D507 02 bb'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.miu == 251
        assert dep.exchange(HEX(252 * 'aa'), timeout=1) == HEX(252 * 'bb')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 10' + 251 * 'aa'), 0.07732861356932154),
            call(HEX('F0 05 D406 01 aa'), 0.07732861356932154),
            call(HEX('F0 04 D406 42'), 0.07732861356932154),
        ]

    def test_exchange_send_recv_with_rtox(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 40'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 FF D507 11' + 251 * 'bb'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 02 bb'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.miu == 251
        assert dep.exchange(HEX(252 * 'aa'), timeout=1) == HEX(252 * 'bb')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 10' + 251 * 'aa'), 0.07732861356932154),
            call(HEX('F0 05 D406 01 aa'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
            call(HEX('F0 04 D406 42'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
        ]

    def test_exchange_send_data_too_many_rtox(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 90 02'),
            HEX('F0 05 D507 90 03'),
            HEX('F0 05 D507 90 01'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.TimeoutError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "timeout extension"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 02'), 0.15465722713864308),
            call(HEX('F0 05 D406 90 03'), 0.23198584070796463),
        ]

    def test_exchange_recv_data_too_many_rtox(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D507 10 0304'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 90 01'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.TimeoutError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "timeout extension"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 41'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
            call(HEX('F0 05 D406 90 01'), 0.07732861356932154),
        ]

    @pytest.mark.parametrize("rtox", ['00', '3C'])
    def test_exchange_get_rtox_out_of_range(self, dep, rtox):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 05 D507 90' + rtox),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "NFC-DEP RTOX must be in range 1 to 59"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_send_data_get_unexpected_ack(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 40'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "unexpected or out-of-sequence NFC-DEP ACK PDU"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_send_data_get_invalid_pni(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D507 01 0304'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "wrong NFC-DEP packet number"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_recv_more_get_invalid_pni(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D507 10 0304'),
            HEX('F0 06 D507 00 0506'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "wrong NFC-DEP packet number"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 41'), 0.07732861356932154),
        ]

    def test_exchange_send_data_get_unexpected_inf(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D507 F0 0304'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "expected NFC-DEP INF PDU after sending"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_recv_more_get_unexpected_inf(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D507 10 0304'),
            HEX('F0 06 D507 F1 0506'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "NFC-DEP chaining not continued after ACK"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 41'), 0.07732861356932154),
        ]

    def test_exchange_attention_recoverable_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            HEX('F0 04 D507 80'),
            HEX('F0 06 D507 00 0304'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.exchange(HEX('0102'), timeout=1) == HEX('0304')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_attention_unrecoverable_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
            nfc.clf.TimeoutError,
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "unrecoverable NFC-DEP error in attention request"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
        ]

    def test_exchange_attention_rtox_after_attention(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            HEX('F0 04 D507 90'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "received NFC-DEP RTOX response to NACK or ATN"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
        ]

    def test_exchange_attention_invalid_response(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            HEX('F0 04 D507 40'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "expected NFC-DEP Attention response"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 80'), 0.07732861356932154),
        ]

    def test_exchange_attention_raises_timeout_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TimeoutError,
            HEX('F0 04 D507 80'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.TimeoutError):
            dep.exchange(HEX('0102'), timeout=0.0001)
        assert dep.clf.exchange.call_count == 1

    def test_exchange_retransmission_recoverable_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            nfc.clf.TransmissionError,
            HEX('F0 06 D507 00 0304'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        assert dep.exchange(HEX('0102'), timeout=1) == HEX('0304')
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
        ]

    def test_exchange_retransmission_unrecoverable_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            nfc.clf.TransmissionError,
            nfc.clf.TransmissionError,
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "unrecoverable NFC-DEP error in retransmission request"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
        ]

    def test_exchange_retransmission_rtox_after_nack(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            HEX('F0 04 D507 90'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "received NFC-DEP RTOX response to NACK or ATN"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
        ]

    def test_exchange_retransmission_invalid_response(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            HEX('F0 04 D507 40'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "unrecoverable NFC-DEP transmission error"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
        ]

    def test_exchange_retransmission_raises_timeout_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            HEX('F0 04 D507 80'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.TimeoutError):
            dep.exchange(HEX('0102'), timeout=0.0001)
        assert dep.clf.exchange.call_count == 1

    def test_exchange_raises_timeout_error(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = []
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.TimeoutError):
            dep.exchange(HEX('0102'), timeout=0)
        assert dep.clf.exchange.call_count == 0

    def test_exchange_target_sends_nack_pdu(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 50'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "received NFC-DEP NACK PDU from Target"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_decode_frame_error_start_byte(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('FF 04 D507 50'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "first NFC-DEP frame byte must be F0h for 106A"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_decode_frame_error_frame_length(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 03 D507 50'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "NFC-DEP frame length byte must be data length + 1"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]

    def test_exchange_decode_frame_error_min_length(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX('F0 02 D5'),
            HEX('F0 02 D5'),
            HEX('F0 02 D5'),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == \
            "unrecoverable NFC-DEP error in retransmission request"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
            call(HEX('F0 04 D406 50'), 0.07732861356932154),
        ]

    @pytest.mark.parametrize("rsp_frame", [
        'F0 06 D407 00 0304', 'F0 06 D500 00 0304', 'F0 06 D502 00 0304',
        'F0 06 D504 00 0304', 'F0 06 D506 00 0304', 'F0 06 D508 00 0304',
        'F0 06 D50A 00 0304',
    ])
    def test_exchange_decode_frame_error_rsp_code(self, dep, rsp_frame):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        dep.clf.exchange.side_effect = [
            HEX(rsp_frame),
        ]
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0102'), timeout=1)
        assert str(excinfo.value) == "invalid NFC-DEP response code"
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 06 D406 00 0102'), 0.07732861356932154),
        ]
