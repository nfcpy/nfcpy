import sys, os
sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc.llcp.pdu
from nose.tools import raises

# =============================================================================
# PDU Parameter Tests
# =============================================================================

def check_bv_decode_tlv(data, offset, size, T, L, V):
    data = bytearray.fromhex(data)
    t, l, v = nfc.llcp.pdu.Parameter.decode(data, offset, size)
    assert t == T
    assert l == L
    assert v == V

@raises(nfc.llcp.pdu.DecodeError)
def check_bi_decode_tlv(data, offset, size):
    data = bytearray.fromhex(data)
    nfc.llcp.pdu.Parameter.decode(data, offset, size)

def test_bv_decode_tlv():
    test_vector = (
        ("0001A5", 0, 3, 0, 1, b'\xA5'),
        ("FF01A5", 0, 3, 255, 1, b'\xA5'),
        ("FF00A5", 0, 3, 255, 0, b''))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv():
    test_vector = (
        ("01", 0, 1),
        ("0101", 0, 2),
    )
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_version():
    test_vector = (
        ("0101AB", 0, 3, 1, 1, 0xAB),
        ("0101ABFF", 0, 4, 1, 1, 0xAB),
        ("FF0101ABFF", 1, 4, 1, 1, 0xAB))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_version():
    test_vector = (("0100AB", 0, 3), ("0102AB", 0, 3))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_miux():
    test_vector = (
        ("0202FC5A", 0, 4, 2, 2, 0x045A),
        ("FF0202FC5AFF", 1, 5, 2, 2, 0x045A))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_miux():
    test_vector = (("0201FC5A", 0, 4), ("0203FC5A", 0, 4))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_wks():
    def check(data, offset, size):
        data = bytearray.fromhex(data)
        t, l, v = nfc.llcp.pdu.Parameter.decode(data, offset, size)
        assert t == 3
        assert l == 2
        assert v == 0xA55A
    test_vector = (
        ("0302A55A", 0, 4, 3, 2, 0xA55A),
        ("FF0302A55AFF", 1, 5, 3, 2, 0xA55A))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_wks():
    test_vector = (("0301A55A", 0, 4), ("0303A55A", 0, 4))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_lto():
    test_vector = (
        ("0401AB", 0, 3, 4, 1, 0xAB),
        ("0401ABFF", 0, 4, 4, 1, 0xAB),
        ("FF0401ABFF", 1, 4, 4, 1, 0xAB))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_lto():
    test_vector = (("0400AB", 0, 3), ("0402AB", 0, 3))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_rw():
    test_vector = (
        ("0501FA", 0, 3, 5, 1, 0x0A),
        ("0501FAFF", 0, 4, 5, 1, 0x0A),
        ("FF0501FAFF", 1, 4, 5, 1, 0x0A))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_rw():
    test_vector = (("0500FA", 0, 3), ("0502FA", 0, 3))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_sn():
    test_vector = (
        ("060141", 0, 3, 6, 1, b'A'),
        ("060141FF", 0, 4, 6, 1, b'A'),
        ("FF060141FF", 1, 4, 6, 1, b'A'),
        ("060041", 0, 3, 6, 0, b''))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bv_decode_tlv_opt():
    test_vector = (
        ("0701FD", 0, 3, 7, 1, 0x05),
        ("0701FDFF", 0, 4, 7, 1, 0x05),
        ("FF0701FDFF", 1, 4, 7, 1, 0x05))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_opt():
    test_vector = (("0700FD", 0, 3), ("0702FD", 0, 3))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_sdreq():
    test_vector = (
        ("0802A541", 0, 4, 8, 2, (0xA5, b'A')),
        ("0802A541FF", 0, 5, 8, 2, (0xA5, b'A')),
        ("FF0802A541FF", 1, 5, 8, 2, (0xA5, b'A')),
        ("0801A5", 0, 3, 8, 1, (0xA5, b'')))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_sdreq():
    test_vector = (("0800", 0, 2), ("0803A541", 0, 5))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_sdres():
    test_vector = (
        ("0902A581", 0, 4, 9, 2, (0xA5, 0x81)),
        ("0902A581FF", 0, 5, 9, 2, (0xA5, 0x81)),
        ("FF0902A581FF", 1, 5, 9, 2, (0xA5, 0x81)))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bi_decode_tlv_sdres():
    test_vector = (("0900", 0, 2), ("0903A581", 0, 4), ("0902A5", 0, 4))
    for data, offset, size in test_vector:
        yield check_bi_decode_tlv, data, offset, size

def test_bv_decode_tlv_ecpk():
    test_vector = (
        ("0A02A55A", 0, 4, 10, 2, b'\xA5\x5A'),
        ("0A02A55AFF", 0, 5, 10, 2, b'\xA5\x5A'),
        ("FF0A02A55AFF", 1, 5, 10, 2, b'\xA5\x5A'),
        ("0A00", 0, 2, 10, 0, b''),
        ("0A0100", 0, 3, 10, 1, b'\x00'))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def test_bv_decode_tlv_rn():
    test_vector = (
        ("0B02A55A", 0, 4, 11, 2, b'\xA5\x5A'),
        ("0B02A55AFF", 0, 5, 11, 2, b'\xA5\x5A'),
        ("FF0B02A55AFF", 1, 5, 11, 2, b'\xA5\x5A'),
        ("0B00", 0, 2, 11, 0, b''),
        ("0B0100", 0, 3, 11, 1, b'\x00'))
    for data, offset, size, T, L, V in test_vector:
        yield check_bv_decode_tlv, data, offset, size, T, L, V

def check_bv_encode_tlv(T, V, data):
    assert bytearray.fromhex(data) == nfc.llcp.pdu.Parameter.encode(T, V)

@raises(nfc.llcp.pdu.EncodeError)
def check_bi_encode_tlv(T, V):
    nfc.llcp.pdu.Parameter.encode(T, V)

def test_bi_encode_tlv():
    test_vector = (
        (0, 0), (255, 0), (1, b'ab'))
    for T, V in test_vector:
        yield check_bi_encode_tlv, T, V
    
def test_bv_encode_tlv_version():
    test_vector = (
        (1,   0, "010100"),
        (1, 171, "0101AB"),
        (1, 255, "0101FF"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_miux():
    test_vector = (
        (2,   0, "02020000"),
        (2, 171, "020200AB"),
        (2, 256, "02020100"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_wks():
    test_vector = (
        (3,   0, "03020000"),
        (3, 171, "030200AB"),
        (3, 256, "03020100"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_lto():
    test_vector = (
        (4,   0, "040100"),
        (4, 171, "0401AB"),
        (4, 255, "0401FF"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_lto():
    test_vector = (
        (5,   0, "050100"),
        (5, 171, "0501AB"),
        (5, 255, "0501FF"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_sn():
    test_vector = (
        (6, b'', "0600"),
        (6, b'AB', "06024142"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bi_encode_tlv_sn():
    test_vector = ((6, bytes(bytearray(range(256)))),)
    for T, V in test_vector:
        yield check_bi_encode_tlv, T, V

def test_bv_encode_tlv_opt():
    test_vector = (
        (7,   0, "070100"),
        (7, 171, "0701AB"),
        (7, 255, "0701FF"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_sdreq():
    test_vector = (
        (8, (0x00, b''), "080100"),
        (8, (0xAB, b''), "0801AB"),
        (8, (0xBA, b'AB'), "0803BA4142"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bi_encode_tlv_sdreq():
    test_vector = ((8, (0, bytes(bytearray(range(255))))),)
    for T, V in test_vector:
        yield check_bi_encode_tlv, T, V

def test_bv_encode_tlv_sdres():
    test_vector = (
        (9, (0x00, 0x00), "09020000"),
        (9, (0xA5, 0x5A), "0902A55A"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bv_encode_tlv_ecpk():
    test_vector = (
        (10, b'', "0A00"),
        (10, b'AB', "0A024142"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bi_encode_tlv_ecpk():
    test_vector = ((10, bytes(bytearray(range(256)))),)
    for T, V in test_vector:
        yield check_bi_encode_tlv, T, V

def test_bv_encode_tlv_rn():
    test_vector = (
        (11, b'', "0B00"),
        (11, b'AB', "0B024142"))
    for T, V, data in test_vector:
        yield check_bv_encode_tlv, T, V, data

def test_bi_encode_tlv_rn():
    test_vector = ((11, bytes(bytearray(range(256)))),)
    for T, V in test_vector:
        yield check_bi_encode_tlv, T, V

# =============================================================================
# Protocol Data Unit Tests
# =============================================================================

@raises(nfc.llcp.pdu.DecodeError)
def check_bi_decode_pdu(frame, offset, size):
    nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)

def test_bi_decode_pdu():
    test_vector = (
        ("",   0, 0),
        ("00", 0, 1),
        ("00", 1, 1),
        ("00", 0, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def check_bv_encode_pdu(pdu_type, pdu_args, frame):
    pdu = pdu_type(*pdu_args)
    frame = bytearray.fromhex(frame)
    assert nfc.llcp.pdu.encode(pdu) == frame

@raises(nfc.llcp.pdu.EncodeError)
def check_bi_encode_pdu(pdu_type, pdu_args):
    nfc.llcp.pdu.encode(pdu_type(*pdu_args))

def test_bv_encode_pdu_symm():
    pdu_type = nfc.llcp.pdu.Symmetry
    test_vector = (
        ((0, 0), "0000"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# SYMM PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_symm(frame, offset, size):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.Symmetry)
    assert len(pdu) == size
    assert pdu.name == "SYMM"
    assert pdu.dsap == 0
    assert pdu.ssap == 0
    assert len(str(pdu))

def test_bv_decode_pdu_symm():
    test_vector = (
        ("0000", 0, 2),
        ("FF0000FF", 1, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bv_decode_pdu_symm, frame, offset, size

def test_bi_decode_pdu_symm():
    test_vector = (
        ("1000", 0, 2),
        ("0001", 0, 2),
        ("000000", 0, 3),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bi_encode_pdu_symm():
    pdu_type = nfc.llcp.pdu.Symmetry
    test_vector = (
        (1, 0),
        (0, 1),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# PAX PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_pax(frame, offset, size, plen,
                            ver, miu, wks, lto, lsc, dpc):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.ParameterExchange)
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
    assert len(str(pdu))

def test_bv_decode_pdu_pax():
    test_vector = (
        ("0040",           0, 2, 2, (0, 0), 128, 0x0000,  100, 0, 0),
        ("FF0040FF",       1, 2, 2, (0, 0), 128, 0x0000,  100, 0, 0),
        ("00400101A5",     0, 5, 5, (10,5), 128, 0x0000,  100, 0, 0),
        ("004002020000",   0, 6, 6, (0, 0), 128, 0x0000,  100, 0, 0),
        ("00400202F367",   0, 6, 6, (0, 0), 999, 0x0000,  100, 0, 0),
        ("00400302A55A",   0, 6, 6, (0, 0), 128, 0xA55A,  100, 0, 0),
        ("00400401FF",     0, 5, 5, (0, 0), 128, 0x0000, 2550, 0, 0),
        ("00400701FF",     0, 5, 5, (0, 0), 128, 0x0000,  100, 3, 1),
        ("0040070102",     0, 5, 5, (0, 0), 128, 0x0000,  100, 2, 0),
        ("0040070104",     0, 5, 5, (0, 0), 128, 0x0000,  100, 0, 1),
        ("00400701040000", 0, 7, 5, (0, 0), 128, 0x0000,  100, 0, 1),
        ("0040070104FFFF", 0, 7, 5, (0, 0), 128, 0x0000,  100, 0, 1),
        ("00400000070104", 0, 7, 5, (0, 0), 128, 0x0000,  100, 0, 1),
    )
    for frame, offset, size, plen, ver, miu, wks, lto, lsc, dpc in test_vector:
        yield (check_bv_decode_pdu_pax, frame, offset, size,
               plen, ver, miu, wks, lto, lsc, dpc)

def test_bi_decode_pdu_pax():
    test_vector = (
        ("1040", 0, 2),
        ("0041", 0, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_pax():
    pdu_type = nfc.llcp.pdu.ParameterExchange
    test_vector = (
        ((0, 0), "0040"),
        ((0, 0, 0x5A), "004001015A"),
        ((0, 0, None, 1), "004002020001"),
        ((0, 0, None, None, 0xA55A), "00400302A55A"),
        ((0, 0, None, None, None, 0xA5), "00400401A5"),
        ((0, 0, None, None, None, None, 0xA5), "00400701A5"),
        ((0, 0, 0x5A, None, None, None, 0xA5), "004001015A0701A5"),
        ((0, 0, None, None, 0xA55A, None, 0xA5), "00400302A55A0701A5"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bv_setattr_pdu_pax_version():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.version = (5, 10)
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("004001015A")

def test_bv_setattr_pdu_pax_miu():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.miu = 128 + 0x07FF
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("0040020207FF")

def test_bv_setattr_pdu_pax_wks():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.wks = 0xA55A
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("00400302A55A")

def test_bv_setattr_pdu_pax_lto():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.lto = 320
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("0040040120")

def test_bv_setattr_pdu_pax_lsc():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.lsc = 2
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("0040070102")

def test_bv_setattr_pdu_pax_dpc():
    pdu = nfc.llcp.pdu.ParameterExchange(0, 0)
    pdu.dpc = 1
    assert nfc.llcp.pdu.encode(pdu) == bytearray.fromhex("0040070104")

def test_bi_encode_pdu_pax():
    pdu_type = nfc.llcp.pdu.ParameterExchange
    test_vector = (
        (1, 0),
        (0, 1),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# AGF PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_agf(frame, offset, size, pdu_list):
    agf = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(agf, nfc.llcp.pdu.AggregatedFrame)
    assert len(agf) == size
    assert agf.name == "AGF"
    assert agf.dsap == 0
    assert agf.ssap == 0
    i = -1
    for i, pdu in enumerate(agf):
        assert pdu == nfc.llcp.pdu.decode(bytearray.fromhex(pdu_list[i]))
    assert i+1 == len(pdu_list)
    assert len(str(agf))

def test_bv_decode_pdu_agf():
    test_vector = (
        ("0080", 0, 2, tuple()),
        ("FF0080FF", 1, 2, tuple()),
        ("008000020000", 0, 6, ("0000",)),
        ("00800002000000020000", 0, 10, ("0000", "0000")),
    )
    for frame, offset, size, pdu_list in test_vector:
        yield check_bv_decode_pdu_agf, frame, offset, size, pdu_list
    
def test_bi_decode_pdu_agf():
    test_vector = (
        ("008000", 0, None),
        ("108000", 0, None),
        ("008100", 0, None),
        ("0080000200", 0, None),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_agf():
    pdu_type = nfc.llcp.pdu.AggregatedFrame
    test_vector = (
        ((0, 0), "0080"),
        ((0, 0, []), "0080"),
        ((0, 0, [nfc.llcp.pdu.Symmetry()]), "008000020000"),
        ((0, 0, 2*[nfc.llcp.pdu.Symmetry()]), "00800002000000020000"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_agf():
    pdu_type = nfc.llcp.pdu.AggregatedFrame
    test_vector = (
        (1, 0),
        (0, 1),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# UI PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_ui(frame, offset, size, data):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.UnnumberedInformation)
    assert len(pdu) == size
    assert pdu.name == "UI"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.data == data
    assert len(str(pdu))

def test_bv_decode_pdu_ui():
    test_vector = (
        ("80C1", 0, 2, b''),
        ("FF80C1FF", 1, 2, b''),
        ("80C1414243", 0, 2, b''),
        ("80C1414243", 0, 5, b'ABC'),
    )
    for frame, offset, size, data in test_vector:
        yield check_bv_decode_pdu_ui, frame, offset, size, data

def test_bv_encode_pdu_ui():
    pdu_type = nfc.llcp.pdu.UnnumberedInformation
    test_vector = (
        ((0, 0), "00C0"),
        ((0, 0, b'ABC'), "00C0414243"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# CONNECT PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_connect(frame, offset, size, lpdu, miu, rw, sn):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.Connect)
    assert len(pdu) == lpdu
    assert pdu.name == "CONNECT"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.miu == miu
    assert pdu.rw == rw
    assert pdu.sn == sn
    assert len(str(pdu))

def test_bv_decode_pdu_connect():
    test_vector = (
        ("8101",             0, 2, 2, 128, 1, None),
        ("FF8101FF",         1, 2, 2, 128, 1, None),
        ("81010202F367",     0, 6, 6, 999, 1, None),
        ("81010501F9",       0, 5, 5, 128, 9, None),
        ("81010600",         0, 4, 2, 128, 1, b''),
        ("810106024142",     0, 6, 6, 128, 1, b'AB'),
        ("8101000006024142", 0, 8, 6, 128, 1, b'AB'),
        ("810106024142FFFF", 0, 8, 6, 128, 1, b'AB'),
    )
    for frame, offset, size, lp, miu, rw, sn in test_vector:
        yield check_bv_decode_pdu_connect, frame, offset, size, lp, miu, rw, sn

def test_bv_encode_pdu_connect():
    pdu_type = nfc.llcp.pdu.Connect
    test_vector = (
        ((0, 0), "0100"),
        ((0, 0, 129), "010002020001"),
        ((0, 0, 128, 2), "0100050102"),
        ((0, 0, 128, 1, b"ABC"), "01000603414243"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# DISC PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_disc(frame, offset, size):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.Disconnect)
    assert len(pdu) == size
    assert pdu.name == "DISC"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert len(str(pdu))

def test_bv_decode_pdu_disc():
    test_vector = (
        ("8141",     0, 2),
        ("FF8141FF", 1, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bv_decode_pdu_disc, frame, offset, size

def test_bv_encode_pdu_disc():
    pdu_type = nfc.llcp.pdu.Disconnect
    test_vector = (
        ((0, 0), "0140"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# CC PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_cc(frame, offset, size, lpdu, miu, rw):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.ConnectionComplete)
    assert len(pdu) == lpdu
    assert pdu.name == "CC"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.miu == miu
    assert pdu.rw == rw
    assert len(str(pdu))

def test_bv_decode_pdu_cc():
    test_vector = (
        ("8181",             0, 2, 2, 128, 1),
        ("FF8181FF",         1, 2, 2, 128, 1),
        ("81810202F367",     0, 6, 6, 999, 1),
        ("81810501F9",       0, 5, 5, 128, 9),
        ("818100000202F367", 0, 8, 6, 999, 1),
        ("81810202F367FFFF", 0, 8, 6, 999, 1),
    )
    for frame, offset, size, lp, miu, rw in test_vector:
        yield check_bv_decode_pdu_cc, frame, offset, size, lp, miu, rw

def test_bv_encode_pdu_cc():
    pdu_type = nfc.llcp.pdu.ConnectionComplete
    test_vector = (
        ((0, 0), "0180"),
        ((0, 0, 129), "018002020001"),
        ((0, 0, 128, 2), "0180050102"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# DM PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_dm(frame, offset, size, reason):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.DisconnectedMode)
    assert len(pdu) == size
    assert pdu.name == "DM"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.reason == reason
    assert len(pdu.reason_text)
    assert len(str(pdu))

def test_bv_decode_pdu_dm():
    test_vector = (
        ("81C100",     0, 3, 0),
        ("81C1FF",     0, 3, 255),
        ("FF81C100FF", 1, 3, 0),
    )
    for frame, offset, size, reason in test_vector:
        yield check_bv_decode_pdu_dm, frame, offset, size, reason

def test_bi_decode_pdu_dm():
    test_vector = (
        ("81C1", 0, None),
        ("81C10000", 0, None),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_dm():
    pdu_type = nfc.llcp.pdu.DisconnectedMode
    test_vector = (
        ((0, 0), "01C000"),
        ((0, 0, 1), "01C001"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# FRMR PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_frmr(frame, offset, size, b0, b1, b2, b3):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.FrameReject)
    assert len(pdu) == size
    assert pdu.name == "FRMR"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.rej_flags == b0 >> 4 & 15
    assert pdu.rej_ptype == b0 >> 0 & 15
    assert pdu.ns        == b1 >> 4 & 15
    assert pdu.nr        == b1 >> 0 & 15
    assert pdu.vs        == b2 >> 4 & 15
    assert pdu.vr        == b2 >> 0 & 15
    assert pdu.vsa       == b3 >> 4 & 15
    assert pdu.vra       == b3 >> 0 & 15
    assert len(str(pdu))

def test_bv_decode_pdu_frmr():
    test_vector = (
        ("820100000000",     0, 6,  0,  0,  0,  0),
        ("820160616263",     0, 6, 96, 97, 98, 99),
        ("FF820100000000FF", 1, 6,  0,  0,  0,  0),
    )
    for frame, offset, size, b0, b1, b2, b3 in test_vector:
        yield check_bv_decode_pdu_frmr, frame, offset, size, b0, b1, b2, b3

def test_bi_decode_pdu_frmr():
    test_vector = (
        ("8201", 0, None),
        ("820100", 0, None),
        ("82010000", 0, None),
        ("8201000000", 0, None),
        ("82010000000000", 0, None),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_frmr():
    pdu_type = nfc.llcp.pdu.FrameReject
    test_vector = (
        ((0, 0), "020000000000"),
        ((0, 0, 1, 2, 3, 4, 5, 6, 7, 8), "020012345678"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def check_bv_init_pdu_frmr_from_pdu(pdu, flags, frame):
    class DLC:
        send_cnt, recv_cnt = 3, 4
        send_ack, recv_ack = 5, 6
        pass
    frmr = nfc.llcp.pdu.FrameReject.from_pdu(pdu, flags, DLC())
    assert frmr.encode() == bytearray.fromhex(frame)

def test_bv_init_pdu_frmr_from_pdu():
    test_vector = (
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "W",    "02008C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "I",    "02004C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "R",    "02002C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "S",    "02001C123456"),
        (nfc.llcp.pdu.Information(0, 0, 1, 2),  "WIRS", "0200FC123456"),
        (nfc.llcp.pdu.ReceiveReady(0, 0, 2),    "WR",   "0200AD023456"),
        (nfc.llcp.pdu.ReceiveNotReady(0, 0, 2), "SI",   "02005E023456"),
    )
    for pdu, flags, frame in test_vector:
        yield check_bv_init_pdu_frmr_from_pdu, pdu, flags, frame

def test_bv_init_pdu_frmr_from_rr_pdu():
    pass

def test_bv_init_pdu_frmr_from_rnr_pdu():
    pass

# ----------------------------------------------------------------------------
# SNL PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_snl(frame, offset, size, plen, sdreq, sdres):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.ServiceNameLookup)
    assert len(pdu) == plen
    assert pdu.name == "SNL"
    assert pdu.dsap == 1
    assert pdu.ssap == 1
    assert pdu.sdreq == sdreq
    assert pdu.sdres == sdres
    assert len(str(pdu))

def test_bv_decode_pdu_snl():
    test_vector = (
        ("0641",                 0,  2,  2, [],             []),
        ("000641",               1,  2,  2, [],             []),
        ("064100",               0,  3,  2, [],             []),
        ("06410000",             0,  4,  2, [],             []),
        ("064100FF08020141",     0,  8,  2, [],             []),
        ("0641000008020141",     0,  8,  6, [(0x01, b'A')], []),
        ("06410000080201410000", 0, 10,  6, [(0x01, b'A')], []),
        ("06410802014109020211", 0, 10, 10, [(0x01, b'A')], [(0x02, 0x11)]),
        ("06410902021108020141", 0, 10, 10, [(0x01, b'A')], [(0x02, 0x11)]),
    )
    for frame, offset, size, plen, sdreq, sdres in test_vector:
        yield (check_bv_decode_pdu_snl, frame, offset, size, plen, sdreq, sdres)

def test_bi_decode_pdu_snl():
    test_vector = (
        ("0642", 0, None),
        ("1641", 0, None),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_snl():
    pdu_type = nfc.llcp.pdu.ServiceNameLookup
    test_vector = (
        ((0, 0), "0240"),
        ((0, 0, [], []), "0240"),
        ((0, 0, [(11, b'AB')], []), "024008030B4142"),
        ((0, 0, [(11, b'AB'), (12, b'CD')], []), "024008030B414208030C4344"),
        ((0, 0, [], [(11, 0xA5)]), "024009020BA5"),
        ((0, 0, [], [(11, 0xA5), (12, 0x5A)]), "024009020BA509020C5A"),
        ((0, 0, [(11, b'AB')], [(11, 0xA5)]), "024008030B414209020BA5"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

# ----------------------------------------------------------------------------
# DPS PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_dps(frame, offset, size, plen, ecpk, rn):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.DataProtectionSetup)
    assert len(pdu) == plen
    assert pdu.name == "DPS"
    assert pdu.dsap == 0
    assert pdu.ssap == 0
    assert pdu.ecpk == ecpk
    assert pdu.rn == rn
    assert len(str(pdu))

def test_bv_decode_pdu_dps():
    test_vector = (
        ("0280",             0,  None, 2, None,  None),
        ("000280",           1,     2, 2, None,  None),
        ("02800A00",         0,  None, 2, b'',   None),
        ("02800B00",         0,  None, 2, None,  b''),
        ("02800A024142",     0,  None, 6, b'AB', None),
        ("02800B024142",     0,  None, 6, None,  b'AB'),
        ("02800A0241420B00", 0,  None, 6, b'AB', b''),
        ("02800B0241420A00", 0,  None, 6, b'',   b'AB'),
        ("028000000A000B00", 0,  None, 2, b'',   b''),
    )
    for frame, offset, size, plen, ecpk, rn in test_vector:
        yield (check_bv_decode_pdu_dps, frame, offset, size, plen, ecpk, rn)

def test_bi_decode_pdu_dps():
    test_vector = (
        ("0281", 0, None),
        ("1280", 0, None),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_dps():
    pdu_type = nfc.llcp.pdu.DataProtectionSetup
    test_vector = (
        ((0, 0), "0280"),
        ((0, 0, b'AB'), "02800A024142"),
        ((0, 0, None, b'CD'), "02800B024344"),
        ((0, 0, b'AB', b'CD'), "02800A0241420B024344"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_dps():
    pdu_type = nfc.llcp.pdu.DataProtectionSetup
    test_vector = (
        (1, 0),
        (0, 1),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# I PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_i(frame, offset, size, ns, nr, data):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.Information)
    assert len(pdu) == size
    assert pdu.name == "I"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.ns == ns
    assert pdu.nr == nr
    assert pdu.data == data
    assert len(str(pdu))

def test_bv_decode_pdu_i():
    test_vector = (
        ("830100",       0, 3, 0, 0, b''),
        ("830196",       0, 3, 9, 6, b''),
        ("FF830196FF",   1, 3, 9, 6, b''),
        ("830100414243", 0, 6, 0, 0, b'ABC'),
    )
    for frame, offset, size, ns, nr, data in test_vector:
        yield check_bv_decode_pdu_i, frame, offset, size, ns, nr, data

def test_bi_decode_pdu_i():
    test_vector = (
        ("8301", 0, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_i():
    pdu_type = nfc.llcp.pdu.Information
    test_vector = (
        ((0, 0, 0, 0), "030000"),
        ((0, 0, 1, 2), "030012"),
        ((0, 0, 1, 2, b'ABC'), "030012414243"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_i():
    pdu_type = nfc.llcp.pdu.Information
    test_vector = (
        (0, 0, 0, None),
        (0, 0, None, 0),
        (0, 0, -1, 0),
        (0, 0, 0, -1),
        (0, 0, 16, 0),
        (0, 0, 0, 16),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# RR PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_rr(frame, offset, size, nr):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.ReceiveReady)
    assert len(pdu) == size
    assert pdu.name == "RR"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.ns == 0
    assert pdu.nr == nr
    assert len(str(pdu))

def test_bv_decode_pdu_rr():
    test_vector = (
        ("834101",     0, 3, 1),
        ("8341F9",     0, 3, 9),
        ("FF834101FF", 1, 3, 1),
    )
    for frame, offset, size, nr in test_vector:
        yield check_bv_decode_pdu_rr, frame, offset, size, nr

def _test_bi_decode_pdu_rr():
    test_vector = (
        ("8341", 0, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_rr():
    pdu_type = nfc.llcp.pdu.ReceiveReady
    test_vector = (
        ((0, 0,  0), "034000"),
        ((0, 0, 15), "03400F"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_rr():
    pdu_type = nfc.llcp.pdu.ReceiveReady
    test_vector = (
        (0, 0, None),
        (0, 0, -1),
        (0, 0, 16),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# RNR PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_rnr(frame, offset, size, nr):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.ReceiveNotReady)
    assert len(pdu) == size
    assert pdu.name == "RNR"
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.ns == 0
    assert pdu.nr == nr
    assert len(str(pdu))

def test_bv_decode_pdu_rnr():
    test_vector = (
        ("838101",     0, 3, 1),
        ("8381F9",     0, 3, 9),
        ("FF838101FF", 1, 3, 1),
    )
    for frame, offset, size, nr in test_vector:
        yield check_bv_decode_pdu_rnr, frame, offset, size, nr

def _test_bi_decode_pdu_rnr():
    test_vector = (
        ("8381", 0, 2),
    )
    for frame, offset, size in test_vector:
        yield check_bi_decode_pdu, frame, offset, size

def test_bv_encode_pdu_rnr():
    pdu_type = nfc.llcp.pdu.ReceiveNotReady
    test_vector = (
        ((0, 0,  0), "038000"),
        ((0, 0, 15), "03800F"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_rnr():
    pdu_type = nfc.llcp.pdu.ReceiveNotReady
    test_vector = (
        (0, 0, None),
        (0, 0, -1),
        (0, 0, 16),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

# ----------------------------------------------------------------------------
# Unknown PDU
# ----------------------------------------------------------------------------
def check_bv_decode_pdu_unknown(frame, offset, size, name, payload):
    pdu = nfc.llcp.pdu.decode(bytearray.fromhex(frame), offset, size)
    assert isinstance(pdu, nfc.llcp.pdu.UnknownProtocolDataUnit)
    assert len(pdu) == size
    assert pdu.name == name
    assert pdu.dsap == 32
    assert pdu.ssap == 1
    assert pdu.payload == payload
    assert len(str(pdu))

def test_bv_decode_pdu_unknown():
    test_vector = (
        ("83C1",       0, 2, '1111', b''),
        ("FF83C1FF",   1, 2, '1111', b''),
        ("83C1414243", 0, 5, '1111', b'ABC'),
    )
    for frame, offset, size, name, payload in test_vector:
        yield check_bv_decode_pdu_unknown, frame, offset, size, name, payload

def test_bv_encode_pdu_unknown():
    pdu_type = nfc.llcp.pdu.UnknownProtocolDataUnit
    test_vector = (
        ((15, 0, 0, b''), "03C0"),
        ((15, 0, 0, b'ABC'), "03C0414243"),
        ((15, 63, 63, b'ABC'), "FFFF414243"),
    )
    for pdu_args, frame in test_vector:
        yield check_bv_encode_pdu, pdu_type, pdu_args, frame

def test_bi_encode_pdu_unknown():
    pdu_type = nfc.llcp.pdu.UnknownProtocolDataUnit
    test_vector = (
        (15, None, 0, b''),
        (15, 0, None, b''),
        (15, 64, 0, b''),
        (15, 0, 64, b''),
        (15, -1, 0, b''),
        (15, 0, -1, b''),
    )
    for pdu_args in test_vector:
        yield check_bi_encode_pdu, pdu_type, pdu_args

@raises(AttributeError)
def test_bi_encode_pdu_wrong_type_is_int():
    nfc.llcp.pdu.encode(1)

@raises(AttributeError)
def test_bi_encode_pdu_wrong_type_is_str():
    nfc.llcp.pdu.encode(b'ABC')

