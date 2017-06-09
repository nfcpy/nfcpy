# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import pytest
import nfc.llcp.pdu


def HEX(s):
    return bytearray.fromhex(s)


# =============================================================================
# PDU Parameter Tests
# =============================================================================
class TestParameter:
    @pytest.mark.parametrize("octets, T, L, V", [
        ("0000", 0, 0, b''),
        ("0001A5", 0, 1, b'\xA5'),
        ("0101AB", 1, 1, 0xAB),            # VERSION
        ("0202FC5A", 2, 2, 0x045A),        # MIUX
        ("0302A55A", 3, 2, 0xA55A),        # WKS
        ("0401AB", 4, 1, 0xAB),            # LTO
        ("0501FA", 5, 1, 0x0A),            # RW
        ("05010B", 5, 1, 0x0B),            # RW
        ("060141", 6, 1, b'A'),            # SN
        ("0600", 6, 0, b''),               # SN
        ("0701FD", 7, 1, 0x05),            # OPT
        ("0802A541", 8, 2, (0xA5, b'A')),  # SDREQ
        ("0801A5", 8, 1, (0xA5, b'')),     # SDREQ
        ("0902A581", 9, 2, (0xA5, 0x81)),  # SDRES
        ("0A02A55A", 10, 2, b'\xA5\x5A'),  # ECPK
        ("0A01A5", 10, 1, b'\xA5'),        # ECPK
        ("0A00", 10, 0, b''),              # ECPK
        ("0B02A55A", 11, 2, b'\xA5\x5A'),  # RN
        ("0B00", 11, 0, b''),              # RN
        ("FF01A5", 255, 1, b'\xA5'),
    ])
    def test_decode_pass(self, octets, T, L, V):
        octets = bytes(HEX(octets + 'FF'))
        assert nfc.llcp.pdu.Parameter.decode(octets, 0) == (T, L, V)
        assert nfc.llcp.pdu.Parameter.decode(b'\1' + octets, 1) == (T, L, V)

    @pytest.mark.parametrize("T, V, octets", [
        (1, 0xAB, "0101AB"),            # VERSION
        (2, 0x045A, "0202045A"),        # MIUX
        (3, 0xA55A, "0302A55A"),        # WKS
        (4, 0xAB, "0401AB"),            # LTO
        (5, 0x0A, "05010A"),            # RW
        (6, b'A', "060141"),            # SN
        (7, 0x05, "070105"),            # OPT
        (8, (0xA5, b'A'), "0802A541"),  # SDREQ
        (9, (0xA5, 0x81), "0902A581"),  # SDRES
        (10, b'\xA5\x5A', "0A02A55A"),  # ECPK
        (11, b'\xA5\x5A', "0B02A55A"),  # RN
    ])
    def test_encode_pass(self, T, V, octets):
        octets = bytes(HEX(octets))
        assert nfc.llcp.pdu.Parameter.encode(T, V) == octets

    @pytest.mark.parametrize("octets", [
        "00", "0001",
        "0100AB", "0102AB",            # VERSION
        "0201FC5A", "0203FC5A",        # MIUX
        "0301A55A", "0303A55A",        # WKS
        "0400AB", "0402AB",            # LTO
        "0500FA", "0502FA",            # RW
        "0700FD", "0702FD",            # OPT
        "0800", "0803A541",            # SDREQ
        "0900", "0903A581", "0902A5",  # SDRES
    ])
    def test_decode_fail(self, octets):
        octets = bytes(HEX(octets))
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            nfc.llcp.pdu.Parameter.decode(octets, 0)

    @pytest.mark.parametrize("T, V", [
        (0, 0), (255, 0), (1, b'ab'),
        (6, 256 * b'a'),       # SN
        (8, (0, 255 * b'a')),  # SDREQ
        (10, 256 * b'x'),      # ECPK
        (11, 256 * b'x'),      # RN
    ])
    def test_encode_fail(self, T, V):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            nfc.llcp.pdu.Parameter.encode(T, V)


# =============================================================================
# Protocol Data Unit Tests
# =============================================================================
@pytest.mark.parametrize("octets, offset, size", [
    ("",   0, 0),
    ("00", 0, 1),
    ("00", 1, 1),
    ("00", 0, 2),
])
def test_decode_pdu_fail_short_data(octets, offset, size):
    with pytest.raises(nfc.llcp.pdu.DecodeError):
        nfc.llcp.pdu.decode(HEX(octets), offset, size)


@pytest.mark.parametrize("arg", [int(1), b'ABC'])
def test_encode_pdu_fail_wrong_type(arg):
    with pytest.raises(AttributeError):
        nfc.llcp.pdu.encode(arg)


class TestProtocolDataUnit:
    PDU = nfc.llcp.pdu.ProtocolDataUnit

    @pytest.mark.parametrize("args, dsap, ssap", [
        ((HEX('1001'),), 4, 1),
        ((HEX('00FFFF'), 1), 63, 63),
        ((HEX('1001FF'), 0, 2), 4, 1)
    ])
    def test_decode_header_pass(self, args, dsap, ssap):
        assert self.PDU.decode_header(*args) == (dsap, ssap)

    @pytest.mark.parametrize("args, errstr", [
        ((HEX('00'),), "insufficient pdu header bytes"),
        ((HEX('0000'), 1), "insufficient pdu header bytes"),
        ((HEX('000000'), 1, 1), "insufficient pdu header bytes"),
    ])
    def test_decode_header_fail(self, args, errstr):
        with pytest.raises(nfc.llcp.pdu.DecodeError) as excinfo:
            self.PDU.decode_header(*args)
        assert str(excinfo.value) == errstr

    @pytest.mark.parametrize("ptype, dsap, ssap, octets", [
        (0, 0, 0, HEX('0000')),
        (1, 2, 3, HEX('0843'))
    ])
    def test_encode_header_pass(self, ptype, dsap, ssap, octets):
        assert self.PDU(ptype, dsap, ssap).encode_header() == octets

    @pytest.mark.parametrize("ptype, dsap, ssap, errstr", [
        (1, None, 3, "pdu dsap and ssap field can not be None"),
        (1, 2, None, "pdu dsap and ssap field can not be None"),
        (1, -2, 3, "pdu dsap and ssap field can not be < 0"),
        (1, 2, -3, "pdu dsap and ssap field can not be < 0"),
        (1, 64, 3, "pdu dsap and ssap field can not be > 63"),
        (1, 2, 64, "pdu dsap and ssap field can not be > 63"),
    ])
    def test_encode_header_fail(self, ptype, dsap, ssap, errstr):
        with pytest.raises(nfc.llcp.pdu.EncodeError) as excinfo:
            self.PDU(ptype, dsap, ssap).encode_header()
        assert str(excinfo.value) == errstr


class TestNumberedProtocolDataUnit:
    PDU = nfc.llcp.pdu.NumberedProtocolDataUnit

    @pytest.mark.parametrize("args, dsap, ssap, ns, nr", [
        ((HEX('100123'),), 4, 1, 2, 3),
        ((HEX('00FFFF45'), 1), 63, 63, 4, 5),
        ((HEX('100167FF'), 0, 3), 4, 1, 6, 7)
    ])
    def test_decode_header_pass(self, args, dsap, ssap, ns, nr):
        assert self.PDU.decode_header(*args) == (dsap, ssap, ns, nr)

    @pytest.mark.parametrize("args, errstr", [
        ((HEX('0000'),), "numbered pdu header length error"),
        ((HEX('000000'), 1), "numbered pdu header length error"),
        ((HEX('00000000'), 1, 2), "numbered pdu header length error"),
    ])
    def test_decode_header_fail(self, args, errstr):
        with pytest.raises(nfc.llcp.pdu.DecodeError) as excinfo:
            self.PDU.decode_header(*args)
        assert str(excinfo.value) == errstr

    @pytest.mark.parametrize("ptype, dsap, ssap, ns, nr, octets", [
        (0, 0, 0, 0, 0, HEX('000000')),
        (1, 2, 3, 4, 5, HEX('084345'))
    ])
    def test_encode_header_pass(self, ptype, dsap, ssap, ns, nr, octets):
        assert self.PDU(ptype, dsap, ssap, ns, nr).encode_header() == octets

    @pytest.mark.parametrize("ns, nr, errstr", [
        (None, 5, "pdu ns and nr field can not be None"),
        (4, None, "pdu ns and nr field can not be None"),
        (-4, 5, "pdu ns and nr field can not be < 0"),
        (4, -5, "pdu ns and nr field can not be < 0"),
        (16, 5, "pdu ns and nr field can not be > 15"),
        (4, 16, "pdu ns and nr field can not be > 15"),
    ])
    def test_encode_header_fail(self, ns, nr, errstr):
        with pytest.raises(nfc.llcp.pdu.EncodeError) as excinfo:
            self.PDU(1, 2, 3, ns, nr).encode_header()
        assert str(excinfo.value) == errstr


# ----------------------------------------------------------------------------
# SYMM PDU
# ----------------------------------------------------------------------------
class TestSymmetry:
    pdu_class = nfc.llcp.pdu.Symmetry

    @pytest.mark.parametrize("octets, offset, size", [
        ("0000", 0, 2),
        ("FF0000FF", 1, 2),
    ])
    def test_decode_pass(self, octets, offset, size):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "SYMM"
        assert pdu.dsap == 0
        assert pdu.ssap == 0
        assert "SYMM" in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0000"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "1000",
        "0001",
        "000000",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (1, 0),
        (0, 1),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# PAX PDU
# ----------------------------------------------------------------------------
class TestParameterExchange:
    pdu_class = nfc.llcp.pdu.ParameterExchange

    @pytest.mark.parametrize(
        "octets, offset, size, plen, ver, miu, wks, lto, lsc, dpc", [
            ("0040",           0, 2, 2, (0,  0), 128, 0x0000,  100, 0, 0),
            ("FF0040FF",       1, 2, 2, (0,  0), 128, 0x0000,  100, 0, 0),
            ("00400101A5",     0, 5, 5, (10, 5), 128, 0x0000,  100, 0, 0),
            ("004002020000",   0, 6, 6, (0,  0), 128, 0x0000,  100, 0, 0),
            ("00400202F367",   0, 6, 6, (0,  0), 999, 0x0000,  100, 0, 0),
            ("00400302A55A",   0, 6, 6, (0,  0), 128, 0xA55A,  100, 0, 0),
            ("00400401FF",     0, 5, 5, (0,  0), 128, 0x0000, 2550, 0, 0),
            ("00400701FF",     0, 5, 5, (0,  0), 128, 0x0000,  100, 3, 1),
            ("0040070102",     0, 5, 5, (0,  0), 128, 0x0000,  100, 2, 0),
            ("0040070104",     0, 5, 5, (0,  0), 128, 0x0000,  100, 0, 1),
            ("00400701040000", 0, 7, 5, (0,  0), 128, 0x0000,  100, 0, 1),
            ("00400000070104", 0, 7, 5, (0,  0), 128, 0x0000,  100, 0, 1),
        ]
    )
    def test_decode_pass(self, octets, offset, size,
                         plen, ver, miu, wks, lto, lsc, dpc):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == plen
        assert pdu.name == "PAX"
        assert pdu.dsap == 0
        assert pdu.ssap == 0
        assert pdu.version == ver
        assert pdu.version_text == "{}.{}".format(*ver)
        assert pdu.miu == miu
        assert pdu.wks == wks
        assert len(pdu.wks_text) if pdu.wks else True
        assert pdu.lto == lto
        assert pdu.lsc == lsc
        assert len(pdu.lsc_text)
        assert pdu.dpc == dpc
        assert len(pdu.dpc_text)
        assert "PAX " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0040"),
        ((0, 0, 0x5A), "004001015A"),
        ((0, 0, None, 1), "004002020001"),
        ((0, 0, None, None, 0xA55A), "00400302A55A"),
        ((0, 0, None, None, None, 0xA5), "00400401A5"),
        ((0, 0, None, None, None, None, 0xA5), "00400701A5"),
        ((0, 0, 0x5A, None, None, None, 0xA5), "004001015A0701A5"),
        ((0, 0, None, None, 0xA55A, None, 0xA5), "00400302A55A0701A5"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "1040",
        "0041",
        "0040FFFF",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (1, 0), (0, 1),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()

    def test_setattr_version(self):
        pdu = self.pdu_class(0, 0)
        pdu.version = (5, 10)
        assert nfc.llcp.pdu.encode(pdu) == HEX("004001015A")

    def test_setattr_miu(self):
        pdu = self.pdu_class(0, 0)
        pdu.miu = 128 + 0x07FF
        assert nfc.llcp.pdu.encode(pdu) == HEX("0040020207FF")

    def test_setattr_wks(self):
        pdu = self.pdu_class(0, 0)
        pdu.wks = 0xA55A
        assert nfc.llcp.pdu.encode(pdu) == HEX("00400302A55A")

    def test_setattr_lto(self):
        pdu = self.pdu_class(0, 0)
        pdu.lto = 320
        assert nfc.llcp.pdu.encode(pdu) == HEX("0040040120")

    def test_setattr_lsc(self):
        pdu = self.pdu_class(0, 0)
        pdu.lsc = 2
        assert nfc.llcp.pdu.encode(pdu) == HEX("0040070102")

    def test_setattr_dpc(self):
        pdu = self.pdu_class(0, 0)
        pdu.dpc = 1
        assert nfc.llcp.pdu.encode(pdu) == HEX("0040070104")


# ----------------------------------------------------------------------------
# AGF PDU
# ----------------------------------------------------------------------------
class TestAggregatedFrame:
    pdu_class = nfc.llcp.pdu.AggregatedFrame

    @pytest.mark.parametrize("octets, offset, size, pdu_list", [
        ("0080", 0, 2, tuple()),
        ("FF0080FF", 1, 2, tuple()),
        ("008000020000", 0, 6, ("0000",)),
        ("00800002000000020000", 0, 10, ("0000", "0000")),
    ])
    def test_decode_pass(self, octets, offset, size, pdu_list):
        agf = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(agf, self.pdu_class)
        assert len(agf) == size
        assert agf.name == "AGF"
        assert agf.dsap == 0
        assert agf.ssap == 0
        assert agf.count == len(pdu_list)
        assert "AGF " in str(agf)
        i = -1
        for i, pdu in enumerate(agf):
            assert pdu == nfc.llcp.pdu.decode(HEX(pdu_list[i]))
            assert pdu == agf.first if i == 0 else True
        assert i+1 == len(pdu_list)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0080"),
        ((0, 0, []), "0080"),
        ((0, 0, [nfc.llcp.pdu.Symmetry()]), "008000020000"),
        ((0, 0, 2*[nfc.llcp.pdu.Symmetry()]), "00800002000000020000"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "008000",
        "108000",
        "008100",
        "0080000200",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (1, 0),
        (0, 1),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# UI PDU
# ----------------------------------------------------------------------------
class TestUnnumberedInformation:
    pdu_class = nfc.llcp.pdu.UnnumberedInformation

    @pytest.mark.parametrize("octets, offset, size, data", [
        ("80C1", 0, 2, b''),
        ("FF80C1FF", 1, 2, b''),
        ("80C1414243", 0, 2, b''),
        ("80C1414243", 0, 5, b'ABC'),
    ])
    def test_decode_pass(self, octets, offset, size, data):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "UI"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.data == data
        assert pdu.name in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "00C0"),
        ((0, 0, b'ABC'), "00C0414243"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)


# ----------------------------------------------------------------------------
# CONNECT PDU
# ----------------------------------------------------------------------------
class TestConnect:
    pdu_class = nfc.llcp.pdu.Connect

    @pytest.mark.parametrize("octets, offset, size, lpdu, miu, rw, sn", [
        ("8101",             0, 2, 2, 128, 1, None),
        ("FF8101FF",         1, 2, 2, 128, 1, None),
        ("81010202F367",     0, 6, 6, 999, 1, None),
        ("81010501F9",       0, 5, 5, 128, 9, None),
        ("81010600",         0, 4, 2, 128, 1, b''),
        ("810106024142",     0, 6, 6, 128, 1, b'AB'),
        ("8101000006024142", 0, 8, 6, 128, 1, b'AB'),
    ])
    def test_decode_pass(self, octets, offset, size, lpdu, miu, rw, sn):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == lpdu
        assert pdu.name == "CONNECT"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.miu == miu
        assert pdu.rw == rw
        assert pdu.sn == sn
        assert "CONN" in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0100"),
        ((0, 0, 129), "010002020001"),
        ((0, 0, 128, 2), "0100050102"),
        ((0, 0, 128, 1, b"ABC"), "01000603414243"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)


# ----------------------------------------------------------------------------
# DISC PDU
# ----------------------------------------------------------------------------
class TestDisconnect:
    pdu_class = nfc.llcp.pdu.Disconnect

    @pytest.mark.parametrize("octets, offset, size", [
        ("8141",     0, 2),
        ("FF8141FF", 1, 2),
    ])
    def test_decode_pass(self, octets, offset, size):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "DISC"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert "DISC" in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0140"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)


# ----------------------------------------------------------------------------
# CC PDU
# ----------------------------------------------------------------------------
class TestConnectionComplete:
    pdu_class = nfc.llcp.pdu.ConnectionComplete

    @pytest.mark.parametrize("octets, offset, size, lpdu, miu, rw", [
        ("8181",             0, 2, 2, 128, 1),
        ("FF8181FF",         1, 2, 2, 128, 1),
        ("81810202F367",     0, 6, 6, 999, 1),
        ("81810501F9",       0, 5, 5, 128, 9),
        ("818100000202F367", 0, 8, 6, 999, 1),
    ])
    def test_decode_pass(self, octets, offset, size, lpdu, miu, rw):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == lpdu
        assert pdu.name == "CC"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.miu == miu
        assert pdu.rw == rw
        assert "CC  " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0180"),
        ((0, 0, 129), "018002020001"),
        ((0, 0, 128, 2), "0180050102"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)


# ----------------------------------------------------------------------------
# DM PDU
# ----------------------------------------------------------------------------
class TestDisconnectedMode:
    pdu_class = nfc.llcp.pdu.DisconnectedMode

    @pytest.mark.parametrize("octets, offset, size, reason", [
        ("81C100",     0, 3, 0),
        ("81C1FF",     0, 3, 255),
        ("FF81C100FF", 1, 3, 0),
    ])
    def test_decode_pass(self, octets, offset, size, reason):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "DM"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.reason == reason
        assert len(pdu.reason_text)
        assert "DM  " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "01C000"),
        ((0, 0, 1), "01C001"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "81C1",
        "81C10000",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))


# ----------------------------------------------------------------------------
# FRMR PDU
# ----------------------------------------------------------------------------
class TestFrameReject:
    pdu_class = nfc.llcp.pdu.FrameReject

    @pytest.mark.parametrize("octets, offset, size, b0, b1, b2, b3", [
        ("820100000000",     0, 6,  0,  0,  0,  0),
        ("820160616263",     0, 6, 96, 97, 98, 99),
        ("FF820100000000FF", 1, 6,  0,  0,  0,  0),
    ])
    def test_decode_pass(self, octets, offset, size, b0, b1, b2, b3):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "FRMR"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.rej_flags == b0 >> 4 & 15
        assert pdu.rej_ptype == b0 >> 0 & 15
        assert pdu.ns == b1 >> 4 & 15
        assert pdu.nr == b1 >> 0 & 15
        assert pdu.vs == b2 >> 4 & 15
        assert pdu.vr == b2 >> 0 & 15
        assert pdu.vsa == b3 >> 4 & 15
        assert pdu.vra == b3 >> 0 & 15
        assert "FRMR" in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "020000000000"),
        ((0, 0, 1, 2, 3, 4, 5, 6, 7, 8), "020012345678"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "8201",
        "820100",
        "82010000",
        "8201000000",
        "82010000000000",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    def check_bv_init_pdu_frmr_from_pdu(self, pdu, flags, frame):
        class DLC:
            send_cnt, recv_cnt = 3, 4
            send_ack, recv_ack = 5, 6
            pass
        frmr = self.pdu_class.from_pdu(pdu, flags, DLC())
        assert frmr.encode() == HEX(frame)

    @pytest.mark.parametrize("pdu, flags, octets", [
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "W",    "02008C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "I",    "02004C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "R",    "02002C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "S",    "02001C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "WIRS", "0200FC123456"),
        (nfc.llcp.pdu.ReceiveReady(0, 0, 2),    "WR",   "0200AD023456"),
        (nfc.llcp.pdu.ReceiveNotReady(0, 0, 2), "SI",   "02005E023456"),
    ])
    def test_bv_init_pdu_frmr_from_pdu(self, pdu, flags, octets):
        class DLC:
            send_cnt, recv_cnt = 3, 4
            send_ack, recv_ack = 5, 6

        frmr = self.pdu_class.from_pdu(pdu, flags, DLC())
        assert frmr.encode() == HEX(octets)


# ----------------------------------------------------------------------------
# SNL PDU
# ----------------------------------------------------------------------------
class TestServiceNameLookup:
    pdu_class = nfc.llcp.pdu.ServiceNameLookup

    @pytest.mark.parametrize("octets, offset, size, plen, sdreq, sdres", [
        ("0641",                 0,  2,  2, [],             []),
        ("000641",               1,  2,  2, [],             []),
        ("064100",               0,  3,  2, [],             []),
        ("06410000",             0,  4,  2, [],             []),
        ("0641000008020141",     0,  8,  6, [(0x01, b'A')], []),
        ("06410000080201410000", 0, 10,  6, [(0x01, b'A')], []),
        ("06410802014109020211", 0, 10, 10, [(0x01, b'A')], [(0x02, 0x11)]),
        ("06410902021108020141", 0, 10, 10, [(0x01, b'A')], [(0x02, 0x11)]),
    ])
    def test_decode_pass(self, octets, offset, size, plen, sdreq, sdres):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == plen
        assert pdu.name == "SNL"
        assert pdu.dsap == 1
        assert pdu.ssap == 1
        assert pdu.sdreq == sdreq
        assert pdu.sdres == sdres
        assert "SNL " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0240"),
        ((0, 0, [], []), "0240"),
        ((0, 0, [(11, b'AB')], []), "024008030B4142"),
        ((0, 0, [(11, b'AB'), (12, b'CD')], []), "024008030B414208030C4344"),
        ((0, 0, [], [(11, 0xA5)]), "024009020BA5"),
        ((0, 0, [], [(11, 0xA5), (12, 0x5A)]), "024009020BA509020C5A"),
        ((0, 0, [(11, b'AB')], [(11, 0xA5)]), "024008030B414209020BA5"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "0642",
        "1641",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))


# ----------------------------------------------------------------------------
# DPS PDU
# ----------------------------------------------------------------------------
class TestDataProtectionSetup:
    pdu_class = nfc.llcp.pdu.DataProtectionSetup

    @pytest.mark.parametrize("octets, offset, size, plen, ecpk, rn", [
        ("0280",             0,  None, 2, None,  None),
        ("000280",           1,     2, 2, None,  None),
        ("02800A00",         0,  None, 2, b'',   None),
        ("02800B00",         0,  None, 2, None,  b''),
        ("02800A024142",     0,  None, 6, b'AB', None),
        ("02800B024142",     0,  None, 6, None,  b'AB'),
        ("02800A0241420B00", 0,  None, 6, b'AB', b''),
        ("02800B0241420A00", 0,  None, 6, b'',   b'AB'),
        ("028000000A000B00", 0,  None, 2, b'',   b''),
    ])
    def test_decode_pass(self, octets, offset, size, plen, ecpk, rn):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == plen
        assert pdu.name == "DPS"
        assert pdu.dsap == 0
        assert pdu.ssap == 0
        assert pdu.ecpk == ecpk
        assert pdu.rn == rn
        assert "DPS " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0), "0280"),
        ((0, 0, b'AB'), "02800A024142"),
        ((0, 0, None, b'CD'), "02800B024344"),
        ((0, 0, b'AB', b'CD'), "02800A0241420B024344"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "0281",
        "1280",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (1, 0),
        (0, 1),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# I PDU
# ----------------------------------------------------------------------------
class TestInformation:
    pdu_class = nfc.llcp.pdu.Information

    @pytest.mark.parametrize("octets, offset, size, ns, nr, data", [
        ("830100",       0, 3, 0, 0, b''),
        ("830196",       0, 3, 9, 6, b''),
        ("FF830196FF",   1, 3, 9, 6, b''),
        ("830100414243", 0, 6, 0, 0, b'ABC'),
    ])
    def test_decode_pass(self, octets, offset, size, ns, nr, data):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "I"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.ns == ns
        assert pdu.nr == nr
        assert pdu.data == data
        assert "I   " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0, 0, 0), "030000"),
        ((0, 0, 1, 2), "030012"),
        ((0, 0, 1, 2, b'ABC'), "030012414243"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "8301",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (0, 0, 0, None),
        (0, 0, None, 0),
        (0, 0, -1, 0),
        (0, 0, 0, -1),
        (0, 0, 16, 0),
        (0, 0, 0, 16),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# RR PDU
# ----------------------------------------------------------------------------
class TestReceiveReady:
    pdu_class = nfc.llcp.pdu.ReceiveReady

    @pytest.mark.parametrize("octets, offset, size, nr", [
        ("834101",     0, 3, 1),
        ("8341F9",     0, 3, 9),
        ("FF834101FF", 1, 3, 1),
    ])
    def test_decode_pass(self, octets, offset, size, nr):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "RR"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.ns == 0
        assert pdu.nr == nr
        assert "RR  " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0,  0), "034000"),
        ((0, 0, 15), "03400F"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "8341",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (0, 0, None),
        (0, 0, -1),
        (0, 0, 16),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# RNR PDU
# ----------------------------------------------------------------------------
class TestReceiveNotReady:
    pdu_class = nfc.llcp.pdu.ReceiveNotReady

    @pytest.mark.parametrize("octets, offset, size, nr", [
        ("838101",     0, 3, 1),
        ("8381F9",     0, 3, 9),
        ("FF838101FF", 1, 3, 1),
    ])
    def test_decode_pass(self, octets, offset, size, nr):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == "RNR"
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.ns == 0
        assert pdu.nr == nr
        assert "RNR " in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((0, 0,  0), "038000"),
        ((0, 0, 15), "03800F"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("octets", [
        "8381",
    ])
    def test_decode_fail(self, octets):
        octets = HEX(octets)
        with pytest.raises(nfc.llcp.pdu.DecodeError):
            self.pdu_class.decode(octets, 0, len(octets))

    @pytest.mark.parametrize("args", [
        (0, 0, None),
        (0, 0, -1),
        (0, 0, 16),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()


# ----------------------------------------------------------------------------
# Unknown PDU
# ----------------------------------------------------------------------------
class TestUnknownProtocolDataUnit:
    pdu_class = nfc.llcp.pdu.UnknownProtocolDataUnit

    @pytest.mark.parametrize("octets, offset, size, name, payload", [
        ("83C1",       0, 2, '1111', b''),
        ("FF83C1FF",   1, 2, '1111', b''),
        ("83C1414243", 0, 5, '1111', b'ABC'),
    ])
    def test_decode_pass(self, octets, offset, size, name, payload):
        pdu = nfc.llcp.pdu.decode(HEX(octets), offset, size)
        assert isinstance(pdu, self.pdu_class)
        assert len(pdu) == size
        assert pdu.name == name
        assert pdu.dsap == 32
        assert pdu.ssap == 1
        assert pdu.payload == payload
        assert name in str(pdu)

    @pytest.mark.parametrize("args, octets", [
        ((15, 0, 0, b''), "03C0"),
        ((15, 0, 0, b'ABC'), "03C0414243"),
        ((15, 63, 63, b'ABC'), "FFFF414243"),
    ])
    def test_encode_pass(self, args, octets):
        pdu = self.pdu_class(*args)
        assert nfc.llcp.pdu.encode(pdu) == HEX(octets)

    @pytest.mark.parametrize("args", [
        (15, None, 0, b''),
        (15, 0, None, b''),
        (15, 64, 0, b''),
        (15, 0, 64, b''),
        (15, -1, 0, b''),
        (15, 0, -1, b''),
    ])
    def test_encode_fail(self, args):
        with pytest.raises(nfc.llcp.pdu.EncodeError):
            self.pdu_class(*args).encode()
