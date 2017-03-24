# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import pytest
import nfc.llcp.sec


# =============================================================================
# NIST SP800-38C CCM Example Vector Encrypt/Decrypt
# =============================================================================
def test_ccm_example_vector_1_encrypt():
    K = bytearray.fromhex("40414243 44454647 48494a4b 4c4d4e4f")
    N = bytearray.fromhex("10111213 141516")
    A = bytearray.fromhex("00010203 04050607")
    P = bytearray.fromhex("20212223")
    C = bytearray.fromhex("7162015b 4dac255d")

    aad = bytes(A)
    txt = bytes(P)
    key = bytes(K)
    nonce = bytes(N)

    assert C == nfc.llcp.sec.CipherSuite1._encrypt(aad, txt, key, nonce, 4)


def test_ccm_example_vector_1_decrypt():
    K = bytearray.fromhex("40414243 44454647 48494a4b 4c4d4e4f")
    N = bytearray.fromhex("10111213 141516")
    A = bytearray.fromhex("00010203 04050607")
    P = bytearray.fromhex("20212223")
    C = bytearray.fromhex("7162015b 4dac255d")

    aad = bytes(A)
    txt = bytes(C)
    key = bytes(K)
    nonce = bytes(N)

    assert P == nfc.llcp.sec.CipherSuite1._decrypt(aad, txt, key, nonce, 4)


def test_ccm_example_vector_2_encrypt():
    K = bytearray.fromhex("40414243 44454647 48494a4b 4c4d4e4f")
    N = bytearray.fromhex("10111213 14151617")
    A = bytearray.fromhex("00010203 04050607 08090a0b 0c0d0e0f")
    P = bytearray.fromhex("20212223 24252627 28292a2b 2c2d2e2f")
    C = bytearray.fromhex("d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd")

    aad = bytes(A)
    txt = bytes(P)
    key = bytes(K)
    nonce = bytes(N)

    assert C == nfc.llcp.sec.CipherSuite1._encrypt(aad, txt, key, nonce, 6)


def test_ccm_example_vector_2_decrypt():
    K = bytearray.fromhex("40414243 44454647 48494a4b 4c4d4e4f")
    N = bytearray.fromhex("10111213 14151617")
    A = bytearray.fromhex("00010203 04050607 08090a0b 0c0d0e0f")
    P = bytearray.fromhex("20212223 24252627 28292a2b 2c2d2e2f")
    C = bytearray.fromhex("d2a1f0e0 51ea5f62 081a7792 073d593d 1fc64fbf accd")

    aad = bytes(A)
    txt = bytes(C)
    key = bytes(K)
    nonce = bytes(N)

    assert P == nfc.llcp.sec.CipherSuite1._decrypt(aad, txt, key, nonce, 6)


# =============================================================================
# ECDH_anon_WITH_AEAD_AES_128_CCM_4
# =============================================================================
def test_bv_cs1_initialize_by_name():
    cipher = nfc.llcp.sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_4")
    assert isinstance(cipher, nfc.llcp.sec.CipherSuite1)
    assert cipher.icv_size == 4
    assert len(cipher.random_nonce) == 8
    assert len(cipher.public_key_x) == 32
    assert len(cipher.public_key_y) == 32


@pytest.fixture(scope="module")
def local_cipher_suite():
    return nfc.llcp.sec.CipherSuite1()


@pytest.fixture(scope="module")
def local_ecpk(local_cipher_suite):
    return local_cipher_suite.public_key_x + local_cipher_suite.public_key_y


@pytest.fixture(scope="module")
def local_nonce(local_cipher_suite):
    return local_cipher_suite.random_nonce


@pytest.fixture(scope="module")
def remote_cipher_suite():
    return nfc.llcp.sec.CipherSuite1()


@pytest.fixture(scope="module")
def remote_ecpk(remote_cipher_suite):
    return remote_cipher_suite.public_key_x + remote_cipher_suite.public_key_y


@pytest.fixture(scope="module")
def remote_nonce(remote_cipher_suite):
    return remote_cipher_suite.random_nonce


def test_bi_cs1_initialize_by_name():
    cipher = nfc.llcp.sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_5")
    assert cipher is None


def test_bv_cs1_calculate_session_key(remote_ecpk, remote_nonce):
    cs = nfc.llcp.sec.CipherSuite1()
    assert cs.calculate_session_key(remote_ecpk, rn_i=remote_nonce)
    assert cs.calculate_session_key(remote_ecpk, rn_t=remote_nonce)


@pytest.mark.parametrize("ecpk_len", [None, 0, 63, 65])
def test_bi_cs1_public_key_wrong_size(ecpk_len):
    with pytest.raises(nfc.llcp.sec.KeyAgreementError):
        cipher = nfc.llcp.sec.CipherSuite1()
        ecpk = bytearray(range(ecpk_len)) if ecpk_len is not None else None
        cipher.calculate_session_key(ecpk, bytearray(range(8)))


@pytest.mark.parametrize("rn_i_len, rn_t_len", [
    (None, None),
    (0, None), (7, None), (9, None),
    (None, 0), (None, 7), (None, 9),
])
def test_bi_cs1_random_nonce_wrong_size(rn_i_len, rn_t_len):
    with pytest.raises(nfc.llcp.sec.KeyAgreementError):
        cipher = nfc.llcp.sec.CipherSuite1()
        ecpk = bytearray(range(64))
        rn_i = bytearray(range(rn_i_len)) if rn_i_len is not None else None
        rn_t = bytearray(range(rn_t_len)) if rn_t_len is not None else None
        cipher.calculate_session_key(ecpk, rn_i, rn_t)


def test_bi_cs1_public_key_not_on_curve():
    with pytest.raises(nfc.llcp.sec.KeyAgreementError):
        cipher = nfc.llcp.sec.CipherSuite1()
        ecpk = bytearray(range(64))
        cipher.calculate_session_key(ecpk, bytearray(8))


@pytest.mark.parametrize("a, p", [
    (b'ADATA', b'PLAINTEXT'),
    (b'', b'PLAINTEXT'),
    (b'ADATA', b''),
    (b'', b''),
])
def test_bv_cs1_encrypt_decrypt(local_cipher_suite, remote_cipher_suite, a, p):
    cs_i = local_cipher_suite
    cs_t = remote_cipher_suite
    pk_i = cs_i.public_key_x + cs_i.public_key_y
    pk_t = cs_t.public_key_x + cs_t.public_key_y
    rn_i = cs_i.random_nonce
    rn_t = cs_t.random_nonce
    cs_i.calculate_session_key(pk_t, rn_t=rn_t)
    cs_t.calculate_session_key(pk_i, rn_i=rn_i)

    c = cs_i.encrypt(a, p)
    assert len(c) == len(p) + 4
    assert cs_t.decrypt(a, c) == p


def test_bv_cs1_last_packet_send_counter(remote_ecpk, remote_nonce):
    cs = nfc.llcp.sec.CipherSuite1()
    cs.calculate_session_key(remote_ecpk, remote_nonce)
    assert cs._pcs == 0
    cs._pcs = (1 << 64) - 2
    assert cs.encrypt(b'ADATA', b'PLAINTEXT')


def test_bv_cs1_packet_send_counter_overflow(remote_ecpk, remote_nonce):
    with pytest.raises(nfc.llcp.sec.EncryptionError):
        cs = nfc.llcp.sec.CipherSuite1()
        cs.calculate_session_key(remote_ecpk, remote_nonce)
        assert cs._pcs == 0
        assert cs._pcr == 0
        cs._pcs = (1 << 64) - 1
        cs.encrypt(b'ADATA', b'PLAINTEXT')


def test_bv_cs1_last_packet_recv_counter(remote_ecpk, remote_nonce):
    cs = nfc.llcp.sec.CipherSuite1()
    cs.calculate_session_key(remote_ecpk, remote_nonce)
    assert cs._pcr == 0
    cs._pcr = (1 << 64) - 2
    nonce = bytes(bytearray.fromhex("00 00000000 FFFFFFFF FFFFFFFE"))
    c = nfc.llcp.sec.CipherSuite1._encrypt(b'A', b'P', cs._k_encr, nonce, 4)
    assert cs.decrypt(b'A', c)


def test_bv_cs1_packet_recv_counter_overflow(remote_ecpk, remote_nonce):
    with pytest.raises(nfc.llcp.sec.DecryptionError):
        cs = nfc.llcp.sec.CipherSuite1()
        cs.calculate_session_key(remote_ecpk, remote_nonce)
        assert cs._pcr == 0
        cs._pcr = (1 << 64) - 1
        nonce = bytes(bytearray.fromhex("00 00000000 FFFFFFFF FFFFFFFF"))
        c = nfc.llcp.sec.CipherSuite1._encrypt(
            b'A', b'P', cs._k_encr, nonce, 4)
        cs.decrypt(b'A', c)


def test_bi_cs1_packet_recv_counter_mismatch(remote_ecpk, remote_nonce):
    with pytest.raises(nfc.llcp.sec.DecryptionError):
        cs = nfc.llcp.sec.CipherSuite1()
        cs.calculate_session_key(remote_ecpk, remote_nonce)
        assert cs._pcr == 0
        nonce = bytes(bytearray.fromhex("00 00000000 00000000 00000001"))
        c = nfc.llcp.sec.CipherSuite1._encrypt(
            b'A', b'P', cs._k_encr, nonce, 4)
        cs.decrypt(b'A', c)


def test_bi_cs1_set_invalid_tag_size(remote_ecpk, remote_nonce):
    with pytest.raises(nfc.llcp.sec.EncryptionError):
        cs = nfc.llcp.sec.CipherSuite1()
        cs.calculate_session_key(remote_ecpk, remote_nonce)
        assert cs._ccm_t == 4
        cs._ccm_t = 5
        cs.encrypt(b'A', b'P')
