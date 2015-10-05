import sys, os
sys.path.insert(1, os.path.split(sys.path[0])[0])

import nfc.llcp.sec
from nose.tools import raises

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

def test_bi_cs1_initialize_by_name():
    cipher = nfc.llcp.sec.cipher_suite("ECDH_anon_WITH_AEAD_AES_128_CCM_5")
    assert cipher is None

def test_bv_cs1_calculate_session_key():
    cs_1 = nfc.llcp.sec.CipherSuite1()
    cs_2 = nfc.llcp.sec.CipherSuite1()
    ecpk = cs_2.public_key_x + cs_2.public_key_y
    rn_i = cs_2.random_nonce
    rn_t = cs_2.random_nonce
    assert cs_1.calculate_session_key(ecpk, rn_i=rn_i)
    assert cs_1.calculate_session_key(ecpk, rn_t=rn_t)

@raises(nfc.llcp.sec.KeyAgreementError)
def check_bi_cs1_public_key_wrong_size(ecpk_len):
    cipher = nfc.llcp.sec.CipherSuite1()
    ecpk = bytearray(range(ecpk_len)) if ecpk_len is not None else None
    cipher.calculate_session_key(ecpk, bytearray(range(8)))

def test_bi_cs1_public_key_wrong_size():
    test_vector = (None, 0, 63, 65)
    for ecpk_len in test_vector:
        yield check_bi_cs1_public_key_wrong_size, ecpk_len

@raises(nfc.llcp.sec.KeyAgreementError)
def check_bi_cs1_random_nonce_wrong_size(rn_i_len, rn_t_len):
    cipher = nfc.llcp.sec.CipherSuite1()
    ecpk = bytearray(range(64))
    rn_i = bytearray(range(rn_i_len)) if rn_i_len is not None else None
    rn_t = bytearray(range(rn_t_len)) if rn_t_len is not None else None
    cipher.calculate_session_key(ecpk, rn_i, rn_t)

def test_bi_cs1_random_nonce_wrong_size():
    test_vector = (
        (None, None),
        (0, None), (7, None), (9, None),
        (None, 0), (None, 7), (None, 9),
    )
    for rn_i_len, rn_t_len in test_vector:
        yield check_bi_cs1_random_nonce_wrong_size, rn_i_len, rn_t_len
    
@raises(nfc.llcp.sec.KeyAgreementError)
def test_bi_cs1_public_key_not_on_curve():
    cipher = nfc.llcp.sec.CipherSuite1()
    ecpk = bytearray(range(64))
    cipher.calculate_session_key(ecpk, bytearray(8))

def check_bv_cs1_encrypt_decrypt(a, p):
    cs_i = nfc.llcp.sec.CipherSuite1()
    cs_t = nfc.llcp.sec.CipherSuite1()
    pk_i = cs_i.public_key_x + cs_i.public_key_y
    pk_t = cs_t.public_key_x + cs_t.public_key_y
    rn_i = cs_i.random_nonce
    rn_t = cs_t.random_nonce
    cs_i.calculate_session_key(pk_t, rn_t=rn_t)
    cs_t.calculate_session_key(pk_i, rn_i=rn_i)

    c = cs_i.encrypt(a, p)
    assert len(c) == len(p) + 4
    assert cs_t.decrypt(a, c) == p

def test_bv_cs1_encrypt_decrypt():
    test_vector = (
        (b'ADATA', b'PLAINTEXT'),
        (b'', b'PLAINTEXT'),
        (b'ADATA', b''),
        (b'', b''),
    )
    for a, p in test_vector:
        yield check_bv_cs1_encrypt_decrypt, a, p

def test_bv_cs1_last_packet_send_counter():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._pcs == 0
    cs_a._pcs = (1<<64) - 2
    assert cs_a.encrypt(b'ADATA', b'PLAINTEXT')

@raises(nfc.llcp.sec.EncryptionError)
def test_bv_cs1_packet_send_counter_overflow():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._pcs == 0
    assert cs_a._pcr == 0
    cs_a._pcs = (1<<64) - 1
    cs_a.encrypt(b'ADATA', b'PLAINTEXT')

def test_bv_cs1_last_packet_recv_counter():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._pcr == 0
    cs_a._pcr = (1<<64) - 2
    nonce = bytes(bytearray.fromhex("00 00000000 FFFFFFFF FFFFFFFE"))
    c = nfc.llcp.sec.CipherSuite1._encrypt(b'A', b'P', cs_a._k_encr, nonce, 4)
    assert cs_a.decrypt(b'A', c)

@raises(nfc.llcp.sec.DecryptionError)
def test_bv_cs1_packet_recv_counter_overflow():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._pcr == 0
    cs_a._pcr = (1<<64) - 1
    nonce = bytes(bytearray.fromhex("00 00000000 FFFFFFFF FFFFFFFF"))
    c = nfc.llcp.sec.CipherSuite1._encrypt(b'A', b'P', cs_a._k_encr, nonce, 4)
    cs_a.decrypt(b'A', c)

@raises(nfc.llcp.sec.DecryptionError)
def test_bi_cs1_packet_recv_counter_mismatch():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._pcr == 0
    nonce = bytes(bytearray.fromhex("00 00000000 00000000 00000001"))
    c = nfc.llcp.sec.CipherSuite1._encrypt(b'A', b'P', cs_a._k_encr, nonce, 4)
    cs_a.decrypt(b'A', c)

@raises(nfc.llcp.sec.EncryptionError)
def test_bi_cs1_set_invalid_tag_size():
    cs_a = nfc.llcp.sec.CipherSuite1()
    cs_b = nfc.llcp.sec.CipherSuite1()
    pk_b = cs_b.public_key_x + cs_b.public_key_y
    cs_a.calculate_session_key(pk_b, cs_b.random_nonce)
    assert cs_a._ccm_t == 4
    cs_a._ccm_t = 5
    cs_a.encrypt(b'A', b'P')
