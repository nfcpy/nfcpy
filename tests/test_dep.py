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


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'sense', autospec=True)
    mocker.patch.object(clf, 'listen', autospec=True)
    mocker.patch.object(clf, 'exchange', autospec=True)
    clf.sense.return_value = None
    clf.listen.return_value = None
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
        assert dep.general_bytes == HEX('46666D010113')
        assert dep.role == "Initiator"
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
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 FF D507 00' + dep.miu * 'bb')
        ]
        assert (dep.exchange(HEX(dep.miu * 'aa'), timeout=1)
                == HEX(dep.miu * 'bb'))
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 00' + dep.miu * 'aa'), 0.07732861356932154),
        ]

    def test_exchange_more_bytes_at_106_kbps(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 40'),
            HEX('F0 FF D507 11' + dep.miu * 'bb'),
            HEX('F0 05 D507 02 bb'),
        ]
        assert (dep.exchange(HEX((dep.miu + 1) * 'aa'), timeout=1)
                == HEX((dep.miu + 1) * 'bb'))
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 10' + dep.miu * 'aa'), 0.07732861356932154),
            call(HEX('F0 05 D406 01 aa'), 0.07732861356932154),
            call(HEX('F0 04 D406 42'), 0.07732861356932154),
        ]

    def test_exchange_send_recv_with_rtox(self, dep):
        target = nfc.clf.RemoteTarget("106A", atr_res=HEX(self.atr_res))
        dep.clf.sense.return_value = target
        assert dep.activate(None, brs=0) == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D507 40'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 FF D507 11' + dep.miu * 'bb'),
            HEX('F0 05 D507 90 01'),
            HEX('F0 05 D507 02 bb'),
        ]
        assert (dep.exchange(HEX((dep.miu + 1) * 'aa'), timeout=1)
                == HEX((dep.miu + 1) * 'bb'))
        assert dep.clf.exchange.mock_calls == [
            call(HEX('F0 FF D406 10' + dep.miu * 'aa'), 0.07732861356932154),
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


class TestTarget:
    atr_req = 'D400 01FE0102030405060708 00000032 46666D010113'
    atr_req_frame = '17' + atr_req

    @pytest.fixture()
    def dep(self, clf):
        return nfc.dep.Target(clf)

    def test_activate_active_not_initiated(self, dep):
        assert dep.activate(timeout=1.0) is None
        assert dep.clf.listen.call_count == 1

    @pytest.mark.parametrize("brty", ["106A", "212F", "424F"])
    def test_activate_active_initiator_without_psl(self, dep, brty):
        target = nfc.clf.RemoteTarget(brty, atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        assert isinstance(dep.target, nfc.clf.RemoteTarget)
        assert dep.general_bytes == HEX('46666D010113')
        assert dep.role == "Target"
        assert dep.target.brty == brty

    @pytest.mark.parametrize("request", [
        HEX(''), nfc.clf.CommunicationError,
    ])
    def test_deactivate_with_immediate_return(self, dep, request):
        target = nfc.clf.RemoteTarget('106A')
        target.atr_req = HEX('D400 01FE0102030405060708 01000032 46666D010113')
        target.dep_req = HEX('D406 04 01 0000')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [request]
        assert dep.deactivate(HEX('0000')) is None
        assert dep.clf.exchange.mock_calls[0][1] == (HEX('F007D50704010000'),)
        assert dep.clf.exchange.call_count == 1

    @pytest.mark.parametrize("req, res, last", [
        ('08', '09', HEX('')),
        ('0A', '0B', HEX('')),
        ('08', '09', nfc.clf.CommunicationError),
        ('0A', '0B', nfc.clf.CommunicationError),
    ])
    def test_deactivate_with_deselect_or_release(self, dep, req, res, last):
        target = nfc.clf.RemoteTarget('106A')
        target.atr_req = HEX('D400 01FE0102030405060708 01000032 46666D010113')
        target.dep_req = HEX('D406 04 01 0000')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 05 D406 84 01'),   # DEP REQ ATN DID 1 -> reply
            HEX('F0 06 D404 010000'),  # PSL REQ with DID 1 -> ignore
            HEX('F0 04 D4'+req+'02'),  # DSL/RLS REQ with DID 2 -> ignore
            HEX('F0 04 D4'+req+'01'),  # DSL/RLS REQ with DID 1 -> reply
            last,
        ]
        assert dep.deactivate(HEX('0000')) is None
        assert dep.clf.exchange.mock_calls[0][1] == (HEX('F007D50704010000'),)
        assert dep.clf.exchange.mock_calls[1][1] == (HEX('F005D5078401'),)
        assert dep.clf.exchange.mock_calls[2][1] == (None,)
        assert dep.clf.exchange.mock_calls[3][1] == (None,)
        dep.clf.exchange.assert_called_with(HEX('F004D5'+res+'01'), timeout=0)
        assert dep.clf.exchange.call_count == 5

    def test_exchange_maximum_information_unit(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 FF D406 01' + dep.miu * '22'),
            HEX('F0 FF D406 02' + dep.miu * '44'),
            HEX('F0 FF D406 03' + dep.miu * '66'),
            HEX('F0 FF D406 00' + dep.miu * '88'),
            HEX('F0 FF D406 01' + dep.miu * 'aa'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(dep.miu * HEX('11'), 1.0) == dep.miu * HEX('22')
        assert dep.exchange(dep.miu * HEX('33'), 1.0) == dep.miu * HEX('44')
        assert dep.exchange(dep.miu * HEX('55'), 1.0) == dep.miu * HEX('66')
        assert dep.exchange(dep.miu * HEX('77'), 1.0) == dep.miu * HEX('88')
        assert dep.exchange(dep.miu * HEX('99'), 1.0) == dep.miu * HEX('aa')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 FF D507 00' + dep.miu * '11'),
            HEX('F0 FF D507 01' + dep.miu * '33'),
            HEX('F0 FF D507 02' + dep.miu * '55'),
            HEX('F0 FF D507 03' + dep.miu * '77'),
            HEX('F0 FF D507 00' + dep.miu * '99'),
        ]

    def test_exchange_larger_information_unit(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D406 41'),
            HEX('F0 FF D406 12' + dep.miu * 'bb'),
            HEX('F0 05 D406 03 bb'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert (dep.exchange((dep.miu + 1) * HEX('aa'), 1.0)
                == (dep.miu + 1) * HEX('bb'))
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 FF D507 10' + dep.miu * 'aa'),
            HEX('F0 05 D507 01 aa'),
            HEX('F0 04 D507 42'),
        ]

    def test_exchange_error_expected_ack_in_chaining(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 05 D406 01 bb'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange((dep.miu + 1) * HEX('aa'), 1.0)
        assert str(excinfo.value) == "expected ACK in NFC-DEP chaining"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 FF D507 10' + dep.miu * 'aa'),
        ]

    def test_exchange_recv_more_with_wrong_packet_number(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 FF D406 11' + dep.miu * 'bb'),
            HEX('F0 05 D406 03 bb'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('aa'), 1.0)
        assert str(excinfo.value) == "wrong NFC-DEP packet number"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 05 D507 00 aa'),
            HEX('F0 04 D507 41'),
        ]

    def test_exchange_with_invalid_packet_number(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 0506'),
            HEX('F0 06 D406 00 090A'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('0304'), 1.0) == HEX('0506')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('0708'), 1.0)
        assert str(excinfo.value) == "wrong NFC-DEP packet number"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 0304'),
            HEX('F0 06 D507 01 0708'),
        ]

    def test_exchange_error_send_data_empty(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        with pytest.raises(ValueError) as excinfo:
            dep.exchange(b'', 1.0)
        assert str(excinfo.value) == "send_data must not be empty"
        assert dep.clf.exchange.call_count == 0

    def test_exchange_send_data_with_transmission_error(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            nfc.clf.TransmissionError,
            None,
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('aa'), 1.0) is None
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 05 D507 00 aa'),
            None,
        ]

    def test_exchange_recv_more_with_transmission_error(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 FF D406 11' + dep.miu * 'bb'),
            nfc.clf.TransmissionError,
            None,
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('aa'), 1.0) is None
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 05 D507 00 aa'),
            HEX('F0 04 D507 41'),
            None,
        ]

    def test_exchange_recv_attention_request(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D406 80'),
            HEX('F0 06 D406 01 2222'),
            HEX('F0 06 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 04 D507 80'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_exchange_recv_retransmission_request(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 04 D406 50'),
            HEX('F0 06 D406 01 2222'),
            HEX('F0 06 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_exchange_recv_req_with_same_pni(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 06 D406 01 2222'),
            HEX('F0 06 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_exchange_recv_deselect_request(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 03 D408'),
            None,
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) is None
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
            HEX('F0 03 D509'),
        ]

    def test_exchange_recv_release_request(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 03 D40A'),
            None,
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) is None
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
            HEX('F0 03 D50B'),
        ]

    def test_exchange_recv_ignore_commands(self, dep):
        target = nfc.clf.RemoteTarget('106A')
        target.atr_req = HEX('D400 01FE0102030405060708 01000032 46666D010113')
        target.dep_req = HEX('D406 04 01 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 07 D406 05 01 2222'),
            HEX('F0 17 D400 01FE0102030405060708 01000032 46666D010113'),
            HEX('F0 07 D406 06 00 4444'),
            HEX('F0 07 D406 06 01 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 07 D507 04 01 1111'),
            HEX('F0 07 D507 05 01 3333'),
            None,
            None,
        ]

    def test_exchange_at_212F(self, dep):
        target = nfc.clf.RemoteTarget('212F', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('06 D406 01 2222'),
            HEX('06 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('06 D507 00 1111'),
            HEX('06 D507 01 3333'),
        ]

    def test_exchange_error_invalid_start_byte(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('FF 06 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('3333'), 1.0)
        assert str(excinfo.value) == \
            "first NFC-DEP frame byte must be F0h for 106A"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_exchange_error_incorrect_frame_length(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 07 D406 02 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('3333'), 1.0)
        assert str(excinfo.value) == \
            "NFC-DEP frame length byte must be data length + 1"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_exchange_error_frame_too_short(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 02 D4'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        with pytest.raises(nfc.clf.TransmissionError) as excinfo:
            dep.exchange(HEX('3333'), 1.0)
        assert str(excinfo.value) == \
            "NFC-DEP frame length byte must be from 3 to 255"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
        ]

    @pytest.mark.parametrize("cmd_code", ['D006', 'D401', 'D402'])
    def test_exchange_error_invalid_command_code(self, dep, cmd_code):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 06 D406 01 2222'),
            HEX('F0 06 %s 02 4444' % cmd_code),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            dep.exchange(HEX('3333'), 1.0)
        assert str(excinfo.value) == \
            "invalid NFC-DEP command code"
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 06 D507 00 1111'),
            HEX('F0 06 D507 01 3333'),
        ]

    def test_send_timeout_extension(self, dep):
        target = nfc.clf.RemoteTarget('106A', atr_req=HEX(self.atr_req))
        target.dep_req = HEX('D406 00 0102')
        dep.clf.listen.return_value = target
        assert dep.activate() == HEX('46666D010113')
        dep.clf.exchange.side_effect = [
            HEX('F0 05 D406 90 01'),
            HEX('F0 06 D406 01 2222'),
            HEX('F0 05 D406 90 02'),
            HEX('F0 06 D406 02 4444'),
            HEX('F0 06 D406 03 4444'),
        ]
        assert dep.exchange(None, 1.0) == HEX('0102')
        assert dep.send_timeout_extension(1) == 1
        assert dep.exchange(HEX('1111'), 1.0) == HEX('2222')
        assert dep.send_timeout_extension(2) == 2
        assert dep.exchange(HEX('3333'), 1.0) == HEX('4444')
        assert dep.send_timeout_extension(1) is None
        assert [c[1][0] for c in dep.clf.exchange.mock_calls] == [
            HEX('F0 05 D507 90 01'),
            HEX('F0 06 D507 00 1111'),
            HEX('F0 05 D507 90 02'),
            HEX('F0 06 D507 01 3333'),
            HEX('F0 05 D507 90 01'),
        ]


class TestDepPdu:
    @pytest.mark.parametrize("atr, s, l, id3, , did, bs, br, pp, gb, lr", [
        (HEX('D400 01FE0102030405060708 01020332 46666D'), 'ATR-REQ '
         'NFCID3=01fe0102030405060708 DID=01 BS=02 BR=03 PP=32 GB=46666d',
         19, HEX('01FE0102030405060708'), 1, 2, 3, 0x32, HEX('46666d'), 254),
        (HEX('D400 01FE0102030405060708 01020320 46666D'), 'ATR-REQ '
         'NFCID3=01fe0102030405060708 DID=01 BS=02 BR=03 PP=20 GB=',
         16, HEX('01FE0102030405060708'), 1, 2, 3, 0x20, HEX(''), 192),
        (HEX('D400 01FE0102030405060708 01020312'), 'ATR-REQ '
         'NFCID3=01fe0102030405060708 DID=01 BS=02 BR=03 PP=12 GB=',
         16, HEX('01FE0102030405060708'), 1, 2, 3, 0x12, HEX(''), 128),
        (HEX('D400 01FE0102030405060708 00020302'), 'ATR-REQ '
         'NFCID3=01fe0102030405060708 DID=00 BS=02 BR=03 PP=02 GB=',
         16, HEX('01FE0102030405060708'), 0, 2, 3, 0x02, HEX(''), 64),
    ])
    def test_atr_req(self, atr, s, l, id3, did, bs, br, pp, gb, lr):
        pdu = nfc.dep.ATR_REQ.decode(atr)
        assert str(pdu) == s
        assert len(pdu) == l
        assert pdu.nfcid3 == id3
        assert pdu.did == did
        assert pdu.bs == bs
        assert pdu.br == br
        assert pdu.pp == pp
        assert pdu.lr == lr
        assert pdu.gb == gb
        assert pdu.encode() == atr[0:l]
        assert nfc.dep.ATR_REQ.decode(HEX('D401')) is None

    @pytest.mark.parametrize("atr, s, l, id3, , did, bs, br, to, pp, gb, wt", [
        (HEX('D501 01FE0102030405060708 0102030432 4666'), 'ATR-RES '
         'NFCID3=01fe0102030405060708 DID=01 BS=02 BR=03 TO=04 PP=32 GB=4666',
         19, HEX('01FE0102030405060708'), 1, 2, 3, 4, 0x32, HEX('4666'), 4),
        (HEX('D501 01FE0102030405060708 010203FF32 4666'), 'ATR-RES '
         'NFCID3=01fe0102030405060708 DID=01 BS=02 BR=03 TO=ff PP=32 GB=4666',
         19, HEX('01FE0102030405060708'), 1, 2, 3, 4, 0x32, HEX('4666'), 15),
    ])
    def test_atr_res(self, atr, s, l, id3, did, bs, br, to, pp, gb, wt):
        pdu = nfc.dep.ATR_RES.decode(atr)
        assert str(pdu) == s
        assert len(pdu) == l
        assert pdu.nfcid3 == id3
        assert pdu.did == did
        assert pdu.bs == bs
        assert pdu.br == br
        assert pdu.pp == pp
        assert pdu.wt == wt
        assert pdu.gb == gb
        assert pdu.encode() == atr[0:l]
        assert nfc.dep.ATR_RES.decode(HEX('D500')) is None

    def test_psl_req(self):
        pdu = nfc.dep.PSL_REQ.decode(HEX('D404 01 91 22'))
        assert str(pdu) == 'PSL-REQ DID=01 BRS=91 FSL=22'
        assert pdu.did == 0x01
        assert pdu.brs == 0x91
        assert pdu.dsi == 2
        assert pdu.dri == 1
        assert pdu.fsl == 0x22
        assert pdu.lr == 192
        assert pdu.encode() == HEX('D404 01 91 22')
        assert nfc.dep.PSL_REQ.decode(HEX('D405')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.PSL_REQ.decode(HEX('D404 00 11'))
        assert str(excinfo.value) == "invalid format of the PSL-REQ"

    def test_psl_res(self):
        pdu = nfc.dep.PSL_RES.decode(HEX('D505 01'))
        assert str(pdu) == 'PSL-RES DID=01'
        assert pdu.did == 0x01
        assert pdu.encode() == HEX('D505 01')
        assert nfc.dep.PSL_REQ.decode(HEX('D504')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.PSL_RES.decode(HEX('D505'))
        assert str(excinfo.value) == "invalid format of the PSL-RES"

    def test_dsl_req(self):
        pdu = nfc.dep.DSL_REQ.decode(HEX('D408 01'))
        assert str(pdu) == 'DSL-REQ DID=1'
        assert pdu.did == 1
        assert pdu.encode() == HEX('D408 01')
        pdu = nfc.dep.DSL_REQ.decode(HEX('D408'))
        assert str(pdu) == 'DSL-REQ DID=None'
        assert pdu.did is None
        assert pdu.encode() == HEX('D408')
        assert nfc.dep.DSL_REQ.decode(HEX('D409')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.DSL_REQ.decode(HEX('D408 00 11'))
        assert str(excinfo.value) == "invalid format of the DSL-REQ"

    def test_dsl_res(self):
        pdu = nfc.dep.DSL_RES.decode(HEX('D509 01'))
        assert str(pdu) == 'DSL-RES DID=1'
        assert pdu.did == 1
        assert pdu.encode() == HEX('D509 01')
        pdu = nfc.dep.DSL_RES.decode(HEX('D509'))
        assert str(pdu) == 'DSL-RES DID=None'
        assert pdu.did is None
        assert pdu.encode() == HEX('D509')
        assert nfc.dep.DSL_RES.decode(HEX('D508')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.DSL_RES.decode(HEX('D509 00 11'))
        assert str(excinfo.value) == "invalid format of the DSL-RES"

    def test_rls_req(self):
        pdu = nfc.dep.RLS_REQ.decode(HEX('D40A 01'))
        assert str(pdu) == 'RLS-REQ DID=1'
        assert pdu.did == 1
        assert pdu.encode() == HEX('D40A 01')
        pdu = nfc.dep.RLS_REQ.decode(HEX('D40A'))
        assert str(pdu) == 'RLS-REQ DID=None'
        assert pdu.did is None
        assert pdu.encode() == HEX('D40A')
        assert nfc.dep.RLS_REQ.decode(HEX('D40B')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.RLS_REQ.decode(HEX('D40A 00 11'))
        assert str(excinfo.value) == "invalid format of the RLS-REQ"

    def test_rls_res(self):
        pdu = nfc.dep.RLS_RES.decode(HEX('D50B 01'))
        assert str(pdu) == 'RLS-RES DID=1'
        assert pdu.did == 1
        assert pdu.encode() == HEX('D50B 01')
        pdu = nfc.dep.RLS_RES.decode(HEX('D50B'))
        assert str(pdu) == 'RLS-RES DID=None'
        assert pdu.did is None
        assert pdu.encode() == HEX('D50B')
        assert nfc.dep.RLS_RES.decode(HEX('D50A')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.RLS_RES.decode(HEX('D50B 00 11'))
        assert str(excinfo.value) == "invalid format of the RLS-RES"

    def test_dep_req(self):
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 00 1122'))
        assert str(pdu) == 'DEP-REQ INF PNI=0 DID=None NAD=None DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.LastInformation
        assert pdu.encode() == HEX('D406 00 1122')
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 11 1122'))
        assert str(pdu) == 'DEP-REQ I++ PNI=1 DID=None NAD=None DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.MoreInformation
        assert pdu.encode() == HEX('D406 11 1122')
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 42 1122'))
        assert str(pdu) == 'DEP-REQ ACK PNI=2 DID=None NAD=None DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.PositiveAck
        assert pdu.encode() == HEX('D406 42 1122')
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 53 1122'))
        assert str(pdu) == 'DEP-REQ NAK PNI=3 DID=None NAD=None DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.NegativeAck
        assert pdu.encode() == HEX('D406 53 1122')
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 84 01 1122'))
        assert str(pdu) == 'DEP-REQ ATN PNI=0 DID=1 NAD=None DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.Attention
        assert pdu.encode() == HEX('D406 84 01 1122')
        pdu = nfc.dep.DEP_REQ.decode(HEX('D406 9C 01 02 1122'))
        assert str(pdu) == 'DEP-REQ TOX PNI=0 DID=1 NAD=2 DATA=1122'
        assert pdu.pfb.type == nfc.dep.DEP_REQ.TimeoutExtension
        assert pdu.encode() == HEX('D406 9C 01 02 1122')
        assert nfc.dep.DEP_REQ.decode(HEX('D407 00 1122')) is None
        with pytest.raises(nfc.clf.ProtocolError) as excinfo:
            nfc.dep.DEP_REQ.decode(HEX('D406'))
        assert str(excinfo.value) == "invalid format of the DEP-REQ"
