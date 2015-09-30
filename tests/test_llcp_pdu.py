import sys, os
sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc.llcp.pdu
from nose.tools import raises

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
    test_vector = (("01", 0, 1), ("0101", 0, 1), ("0001", 0, 2))
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

