# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

import logging
log = logging.getLogger(__name__)

import struct
import ctypes
import ctypes.util
from ctypes import c_void_p, c_int, c_size_t
from binascii import hexlify

OpenSSL = None

class Error(Exception): pass
class EncryptError(Error): pass
class DecryptError(Error): pass
class KeyError(Error): pass

def cipher_suite(name):
    if name == "ECDH_anon_WITH_AEAD_AES_128_CCM_4":
        return CipherSuite1()

class CipherSuite1:
    _ccm_t = 4
    _ccm_q = 2
    _ccm_n = 13
    
    def __init__(self):
        self.random_nonce = None
        self.public_key_x = None
        self.public_key_y = None
        ec_key = OpenSSL.EC_KEY.new_by_curve_name(OpenSSL.NID_X9_62_prime256v1)
        if ec_key and ec_key.generate_key() and ec_key.check_key():
            pubkey = ec_key.get_public_key()
            x, y = pubkey.get_affine_coordinates_GFp(ec_key.get_group())
            self.public_key_x, self.public_key_y  = (x, y)
            self.random_nonce = OpenSSL.rand_bytes(8)
            self._ec_key = ec_key

    def calculate_session_key(self, ecpk, rn_i=None, rn_t=None):
        assert len(ecpk) == 64, "ecpk must be 64 byte"
        assert rn_i or rn_t, "one of rn_i or rn_t must be set"
        rn_i = rn_i if rn_i else self.random_nonce
        rn_t = rn_t if rn_t else self.random_nonce
        if rn_i: assert len(rn_i) == 8, "rn_i must be 8 byte"
        if rn_t: assert len(rn_t) == 8, "rn_t must be 8 byte"
        ec_key = OpenSSL.EC_KEY.new_by_curve_name(415)
        ec_key.set_public_key_affine_coordinates(ecpk[:32], ecpk[32:])
        secret = OpenSSL.ECDH(self._ec_key).compute_key(ec_key.get_public_key())
        cipher = OpenSSL.EVP_aes_128_cbc()
        k_encr = OpenSSL.CMAC(cipher).init(rn_i+rn_t).update(secret).final()
        log.debug("remote ecpk-x %r", hexlify(ecpk[:32]))
        log.debug("remote ecpk-y %r", hexlify(ecpk[32:]))
        log.debug("shared secret %r", hexlify(secret))
        log.debug("shared nonce  %r", hexlify(rn_i+rn_t))
        log.debug("session key   %r", hexlify(k_encr))
        self._pcs = self._pcr = 0
        self._k_encr = k_encr
        return self._k_encr

    @property
    def icv_size(self):
        return self._ccm_t
    
    def encrypt(self, a, p):
        # The nonce N is a leftmost 40-bit fixed part all bits zero
        # and a rightmost 64-bit counter part taken from PC(S).
        nonce = struct.pack('!xxxxxQ', self._pcs)
        if self._pcs < 0xFFFFFFFFFFFFFFFF: self._pcs += 1
        else: raise EncryptError("send counter out of range")
        
        # The encryption key was computed in calculate_session_key()
        key = self._k_encr

        # OpenSSLWrapper methods raise AssertionError when any of the
        # operations failed.
        try:
            return self._encrypt(bytes(a), bytes(p), key, nonce, self._ccm_t)
        except AssertionError:
            error = "encrypt failed for message %d" % self._pcs
            log.error(error); raise EncryptError(error)

    @staticmethod
    def _encrypt(aad, txt, key, nonce, tlen):
        # from https://wiki.openssl.org/index.php/
        # EVP_Authenticated_Encryption_and_Decryption#
        # Authenticated_Encryption_using_CCM_mode
        evp = OpenSSL.EVP()
        evp.encrypt_init(OpenSSL.EVP_aes_128_ccm())
        evp.cipher_ctx.ctrl_set(OpenSSL.EVP.CTRL_CCM_SET_IVLEN, len(nonce))
        evp.cipher_ctx.ctrl_set(OpenSSL.EVP.CTRL_CCM_SET_TAG, tlen)
        evp.encrypt_init(key=key, iv=nonce)
        evp.encrypt_update(None, None, len(txt))
        evp.encrypt_update(None, aad, len(aad))
        return evp.encrypt_update(len(txt), txt, len(txt)) + \
            evp.cipher_ctx.ctrl_get(OpenSSL.EVP.CTRL_CCM_GET_TAG, tlen)

    def decrypt(self, a, c):
        # The nonce N is a leftmost 40-bit fixed part all bits zero
        # and a rightmost 64-bit counter part taken from PC(R).
        nonce = struct.pack('!xxxxxQ', self._pcr)
        if self._pcr < 0xFFFFFFFFFFFFFFFF: self._pcr += 1
        else: raise EncryptError("recv counter out of range")

        # The decryption key was computed in calculate_session_key()
        key = self._k_encr
        
        # OpenSSLWrapper methods raise AssertionError when any of the
        # operations failed.
        try:
            return self._decrypt(bytes(a), bytes(c), key, nonce, self._ccm_t)
        except AssertionError:
            error = "decrypt failed for message %d" % self._pcr
            log.error(error); raise DecryptError(error)

    @staticmethod
    def _decrypt(aad, txt, key, nonce, tlen):
        # from https://wiki.openssl.org/index.php/
        # EVP_Authenticated_Encryption_and_Decryption#
        # Authenticated_Decryption_using_CCM_mode
        tag = txt[-tlen:]
        txt = txt[:-tlen]
        evp = OpenSSL.EVP()
        evp.decrypt_init(OpenSSL.EVP_aes_128_ccm())
        evp.cipher_ctx.ctrl_set(OpenSSL.EVP.CTRL_CCM_SET_IVLEN, len(nonce))
        evp.cipher_ctx.ctrl_set(OpenSSL.EVP.CTRL_CCM_SET_TAG, len(tag), tag)
        evp.decrypt_init(key=key, iv=nonce)
        evp.decrypt_update(None, None, len(txt))
        evp.decrypt_update(None, aad, len(aad))
        return evp.decrypt_update(len(txt), txt, len(txt))

class OpenSSLWrapper:
    NID_X9_62_prime256v1 = 415 # NIST Curve P-256
    
    def __init__(self, libcrypto):
        self.crypto = ctypes.CDLL(libcrypto)
        self.crypto.BN_new.restype = c_void_p
        self.crypto.BN_num_bits.restype = c_int
        self.crypto.BN_bn2bin.restype = c_int
        self.crypto.BN_bin2bn.restype = c_void_p
        self.crypto.BN_free.restype = None
        self.crypto.RAND_bytes.restype = c_int
        self.crypto.EC_KEY_new_by_curve_name.restype = c_void_p
        self.crypto.EC_KEY_generate_key.restype = c_int
        self.crypto.EC_KEY_check_key.restype = c_int
        self.crypto.EC_KEY_set_public_key.restype = c_int
        self.crypto.EC_KEY_set_public_key_affine_coordinates.restype = c_int
        self.crypto.EC_KEY_get0_public_key.restype = c_void_p
        self.crypto.EC_KEY_get0_group.restype = c_void_p
        self.crypto.EC_KEY_free.restype = None
        self.crypto.EC_POINT_new.restype = c_void_p
        self.crypto.EC_POINT_get_affine_coordinates_GFp.restype = c_int
        self.crypto.EC_POINT_set_affine_coordinates_GFp.restype = c_int
        self.crypto.EC_POINT_free.restype = None
        self.crypto.ECDH_OpenSSL.restype = c_void_p
        self.crypto.ECDH_set_method.restype = c_int
        self.crypto.ECDH_compute_key.restype = c_int
        self.crypto.CMAC_CTX_new.restype = c_void_p
        self.crypto.CMAC_CTX_free.restype = None
        self.crypto.CMAC_Init.restype = c_int
        self.crypto.CMAC_Update.restype = c_int
        self.crypto.CMAC_Final.restype = c_int

        self.crypto.EVP_CIPHER_CTX_new.restype = c_void_p
        self.crypto.EVP_CIPHER_CTX_init.restype = None
        self.crypto.EVP_CIPHER_CTX_ctrl.restype = c_int
        self.crypto.EVP_CIPHER_CTX_free.restype = None
        
        self.crypto.EVP_EncryptInit_ex.restype = c_int
        self.crypto.EVP_EncryptUpdate.restype = c_int
        self.crypto.EVP_EncryptFinal.restype = c_int
        self.crypto.EVP_DecryptInit_ex.restype = c_int
        self.crypto.EVP_DecryptUpdate.restype = c_int
        self.crypto.EVP_DecryptFinal.restype = c_int
        
        self.crypto.EVP_aes_128_cbc.restype = c_void_p
        self.crypto.EVP_aes_128_cbc.argtypes = []
        self.crypto.EVP_aes_128_ccm.restype = c_void_p
        self.crypto.EVP_aes_128_ccm.argtypes = []

        self.EVP_aes_128_cbc = self.crypto.EVP_aes_128_cbc    
        self.EVP_aes_128_ccm = self.crypto.EVP_aes_128_ccm
    
    class BIGNUM:
        def __init__(self, bignum, release=False):
            self._bignum = bignum
            self._release = release

        def __del__(self):
            if self._release:
                OpenSSL.crypto.BN_free(self)

        @property
        def _as_parameter_(self):
            return c_void_p(self._bignum)

        @staticmethod
        def new():
            # BIGNUM *BN_new(void);
            bignum = OpenSSL.crypto.BN_new()
            if bignum is None: log.error("BN_new")
            else: return OpenSSL.BIGNUM(bignum, release=True)
        
        def num_bits(self):
            return OpenSSL.crypto.BN_num_bits(self)

        def num_bytes(self):
            return (self.num_bits() + 7) // 8
            
        def bn2bin(self):
            # int BN_bn2bin(const BIGNUM *a, unsigned char *to);
            strbuf = ctypes.create_string_buffer(self.num_bytes())
            OpenSSL.crypto.BN_bn2bin(self, strbuf)
            return strbuf.raw

        @staticmethod
        def bin2bn(s):
            # BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
            strbuf = ctypes.create_string_buffer(str(s), len(s))
            res = OpenSSL.crypto.BN_bin2bn(strbuf, len(s), None)
            if res is None: log.error("BN_bin2bn")
            else: return OpenSSL.BIGNUM(res)

    def rand_bytes(self, num):
        # int RAND_bytes(unsigned char *buf, int num);
        buf = ctypes.create_string_buffer(num)
        res = self.crypto.RAND_bytes(buf, c_int(num))
        if res == 0: log.error("RAND_bytes")
        return buf.raw if res != 0 else None

    class EC_KEY:
        def __init__(self, ec_key):
            self._ec_key = ec_key

        def __del__(self):
            OpenSSL.crypto.EC_KEY_free(self)

        @property
        def _as_parameter_(self):
            return c_void_p(self._ec_key)

        @staticmethod
        def new_by_curve_name(nid):
            # EC_KEY *EC_KEY_new_by_curve_name(int nid);
            res = OpenSSL.crypto.EC_KEY_new_by_curve_name(c_int(nid))
            if res is None: log.error("EC_KEY_new_by_curve_name")
            return OpenSSL.EC_KEY(res) if res else None

        def generate_key(self):
            # int EC_KEY_generate_key(EC_KEY *key);
            res = OpenSSL.crypto.EC_KEY_generate_key(self)
            if res == 0: log.error("EC_KEY_generate_key")
            return bool(res)

        def check_key(self):
            # int EC_KEY_check_key(const EC_KEY *key);
            res = OpenSSL.crypto.EC_KEY_check_key(self)
            if res == 0: log.error("EC_KEY_check_key")
            return bool(res)

        def set_public_key(self, ec_point):
            # int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
            r = OpenSSL.crypto.EC_KEY_set_public_key(self, ec_point)
            assert r == 1, "EC_KEY_set_public_key"

        def set_public_key_affine_coordinates(self, pubkey_x, pubkey_y):
            # int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key,
            #     BIGNUM *x, BIGNUM *y);
            r = OpenSSL.crypto.EC_KEY_set_public_key_affine_coordinates(
                self, *map(OpenSSL.BIGNUM.bin2bn, (pubkey_x, pubkey_y)))
            assert r == 1, "EC_KEY_set_public_key_affine_coordinates"

        def get_public_key(self):
            # const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
            res = OpenSSL.crypto.EC_KEY_get0_public_key(self)
            if res is None: log.error("EC_KEY_get0_public_key")
            return OpenSSL.EC_POINT(res)

        def get_group(self):
            # const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
            res = OpenSSL.crypto.EC_KEY_get0_group(self)
            if res is None: log.error("EC_KEY_get0_group")
            return OpenSSL.EC_GROUP(res)

    class EC_GROUP:
        def __init__(self, ec_group):
            self._ec_group = ec_group

        @property
        def _as_parameter_(self):
            return c_void_p(self._ec_group)

    class EC_POINT:
        def __init__(self, ec_point, release=False):
            self._ec_point = ec_point
            self._release = release

        def __del__(self):
            if self._release:
                OpenSSL.crypto.EC_POINT_free(self)

        @property
        def _as_parameter_(self):
            return c_void_p(self._ec_point)

        @staticmethod
        def new(ec_group):
            # EC_POINT *EC_POINT_new(const EC_GROUP *group);
            ec_point = OpenSSL.crypto.EC_POINT_new(ec_group)
            if ec_point is None: log.error("EC_POINT_new")
            else: return OpenSSL.EC_POINT(ec_point, release=True)

        def get_affine_coordinates_GFp(self, ec_group):
            # int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group,
            #     const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
            x, y = (OpenSSL.BIGNUM.new(), OpenSSL.BIGNUM.new())
            func = OpenSSL.crypto.EC_POINT_get_affine_coordinates_GFp
            res = func(ec_group, self, x, y, None)
            if res == 0: log.error("EC_POINT_get_affine_coordinates_GFp")
            else: return (x.bn2bin(), y.bn2bin())

        def set_affine_coordinates_GFp(ec_group, pubkey_x, pubkey_y):
            # int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
            #     EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
            x = OpenSSL.BIGNUM.bin2bn(pubkey_x)
            y = OpenSSL.BIGNUM.bin2bn(pubkey_y)
            r = OpenSSL.crypto.EC_POINT_set_affine_coordinates_GFp(
                ec_group, self, x, y, None)
            assert r == 1, "EC_POINT_set_affine_coordinates_GFp"

    class ECDH:
        def __init__(self, local_key):
            self.key = local_key
            method = OpenSSL.crypto.ECDH_OpenSSL()
            OpenSSL.crypto.ECDH_set_method(self.key, c_void_p(method))
            
        def compute_key(self, pub_key):
            # int ECDH_compute_key(void *out, size_t outlen,
            #     const EC_POINT *pub_key, EC_KEY *ecdh,
            #     void *(*KDF)(const void *in, size_t inlen,
            #          void *out, size_t *outlen));
            strbuf = ctypes.create_string_buffer(32)
            args = (strbuf, 32, pub_key, self.key, None)
            r = OpenSSL.crypto.ECDH_compute_key(*args)
            assert r == 32, "ECDH_compute_key"
            return strbuf.raw # the shared secret z

    class CMAC:
        def __init__(self, cipher):
            # CMAC_CTX *CMAC_CTX_new(void);
            self._cmac_ctx = OpenSSL.crypto.CMAC_CTX_new()
            self._cipher = cipher

        def __del__(self):
            # void CMAC_CTX_free(CMAC_CTX *ctx);
            OpenSSL.crypto.CMAC_CTX_free(self)

        @property
        def _as_parameter_(self):
            return c_void_p(self._cmac_ctx)

        def init(self, key):
            # int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen, 
            #     const EVP_CIPHER *cipher, ENGINE *impl);
            assert len(key) == 16
            keybuf = ctypes.create_string_buffer(str(key), 16)
            keylen = ctypes.c_size_t(16)
            cipher = ctypes.c_void_p(self._cipher)
            r = OpenSSL.crypto.CMAC_Init(self, keybuf, keylen, cipher, None)
            assert r == 1, "CMAC_Init"
            return self

        def update(self, msg):
            # int CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen);
            msgbuf = ctypes.create_string_buffer(str(msg), len(msg))
            msglen = ctypes.c_size_t(len(msg))
            r = OpenSSL.crypto.CMAC_Update(self, msgbuf, msglen)
            assert r == 1, "CMAC_Update"
            return self

        def final(self):
            macbuf = ctypes.create_string_buffer(16)
            maclen = ctypes.c_size_t(0)
            rc = OpenSSL.crypto.CMAC_Final(self, macbuf, ctypes.byref(maclen))
            assert rc == 1 and maclen.value == 16, "CMAC_Final"
            return macbuf.raw

    class EVP:
        CTRL_CCM_SET_IVLEN = 0x09
        CTRL_CCM_GET_TAG = 0x10
        CTRL_CCM_SET_TAG = 0x11
        CTRL_CCM_SET_L = 0x14

        class CIPHER_CTX:
            def __init__(self):
                # EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
                ctx = OpenSSL.crypto.EVP_CIPHER_CTX_new()
                if ctx is None: raise AssertionError("EVP_CIPHER_CTX_new")
                self._ctx = ctx

            def __del__(self):
                # void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
                OpenSSL.crypto.EVP_CIPHER_CTX_free(self)

            @property
            def _as_parameter_(self):
                return c_void_p(self._ctx)

            def init(self):
                # void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *ctx);
                OpenSSL.crypto.EVP_CIPHER_CTX_init(self)

            def ctrl_set(self, op, arg, ptr=None):
                # int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type,
                #                         int arg, void *ptr);
                r = OpenSSL.crypto.EVP_CIPHER_CTX_ctrl(self, op, arg, ptr)
                if r != 1: raise AssertionError("EVP_CIPHER_CTX_ctrl")

            def ctrl_get(self, op, arg):
                # int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type,
                #                         int arg, void *ptr);
                outbuf = ctypes.create_string_buffer(arg)
                r = OpenSSL.crypto.EVP_CIPHER_CTX_ctrl(self, op, arg, outbuf)
                if r != 1: raise AssertionError("EVP_CIPHER_CTX_ctrl")
                return outbuf.raw

        def __init__(self, evp_cipher_ctx=None):
            if evp_cipher_ctx: self._ctx = evp_cipher_ctx
            else: self._ctx = OpenSSL.EVP.CIPHER_CTX()

        @property
        def cipher_ctx(self):
            return self._ctx
        
        def encrypt_init(self, evp_cipher=None, key=None, iv=None):
            # int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx,
            #     const EVP_CIPHER *type, ENGINE *impl,
            #     unsigned char *key, unsigned char *iv);
            r = OpenSSL.crypto.EVP_EncryptInit_ex(
                self._ctx, c_void_p(evp_cipher), None, key, iv)
            if r != 1: raise AssertionError("EVP_EncryptInit_ex")

        def encrypt_update(self, out_len, message, msg_len=None):
            # int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
            #     int *outl, unsigned char *in, int inl);
            if out_len is None:
                out_buf = None
                out_len = c_int(0)
            else:
                out_buf = ctypes.create_string_buffer(out_len)
                out_len = c_int(out_len)
            if msg_len is None:
                msg_len = len(message)
            r = OpenSSL.crypto.EVP_EncryptUpdate(
                self._ctx, out_buf, ctypes.byref(out_len), message, msg_len)
            if r != 1: raise AssertionError("EVP_EncryptUpdate")
            return out_buf.raw[0:out_len.value] if out_buf else b''
        
        def encrypt_final(self, out_len):
            # int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
            #     int *outl);
            out_buf = ctypes.create_string_buffer(out_len)
            out_len = c_int(out_len)
            r = OpenSSL.crypto.EVP_EncryptFinal(
                self._ctx, out_buf, ctypes.byref(out_len))
            if r != 1: raise AssertionError("EVP_EncryptFinal")
            return out_buf.raw[0:out_len.value] if out_buf else b''
        
        def decrypt_init(self, evp_cipher=None, key=None, iv=None):
            # int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx,
            #     const EVP_CIPHER *type, ENGINE *impl,
            #     unsigned char *key, unsigned char *iv);
            r = OpenSSL.crypto.EVP_DecryptInit_ex(
                self._ctx, c_void_p(evp_cipher), None, key, iv)
            if r != 1: raise AssertionError("EVP_DecryptInit_ex")

        def decrypt_update(self, out_len, message, msg_len=None):
            # int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
            #     int *outl, unsigned char *in, int inl);
            if out_len is None:
                out_buf = None
                out_len = c_int(0)
            else:
                out_buf = ctypes.create_string_buffer(out_len)
                out_len = c_int(out_len)
            if msg_len is None:
                msg_len = len(message)
            r = OpenSSL.crypto.EVP_EncryptUpdate(
                self._ctx, out_buf, ctypes.byref(out_len), message, msg_len)
            if r != 1: raise AssertionError("EVP_DecryptUpdate")
            return out_buf.raw[0:out_len.value] if out_buf else b''
        
        def decrypt_final(self, out_len):
            # int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
            #     int *outl);
            out_buf = ctypes.create_string_buffer(out_len)
            out_len = c_int(out_len)
            r = OpenSSL.crypto.EVP_DecryptFinal(
                self._ctx, out_buf, ctypes.byref(out_len))
            if r != 1: raise AssertionError("EVP_DecryptFinal")
            return out_buf.raw[0:out_len.value] if out_buf else b''
        
libcrypto = ctypes.util.find_library('crypto')
if libcrypto is not None:
    OpenSSL = OpenSSLWrapper(libcrypto)

if __name__ == "__main__":
    if OpenSSL:
        K = bytearray.fromhex("40414243 44454647 48494a4b 4c4d4e4f")
        N = bytearray.fromhex("10111213 141516")
        A = bytearray.fromhex("00010203 04050607")
        P = bytearray.fromhex("20212223")
        C = bytearray.fromhex("7162015b 4dac255d")

        aad = bytes(A)
        key = bytes(K)
        nonce = bytes(N)
        
        if C == CipherSuite1._encrypt(aad, bytes(P), key, nonce, 4):
            print("NIST SP800-38C Example Vector 1 passed encrypt")
        
        if P == CipherSuite1._decrypt(aad, bytes(C), key, nonce, 4):
            print("NIST SP800-38C Example Vector 1 passed decrypt")

        c = CipherSuite1._encrypt(aad, b'', key, nonce, 4)
        if b'' == CipherSuite1._decrypt(aad, c, key, nonce, 4):
            print("Zero-length plaintext passed encrypt/decrypt")

