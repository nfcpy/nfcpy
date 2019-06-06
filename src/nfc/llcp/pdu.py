# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import struct
from binascii import hexlify

import logging
log = logging.getLogger(__name__)


class Error(Exception):
    pass


class DecodeError(Error):
    pass


class EncodeError(Error):
    pass


class Parameter:
    VERSION, MIUX, WKS, LTO, RW, SN, OPT, SDREQ, SDRES, ECPK, RN = range(1, 12)

    @staticmethod
    def decode(data, offset):
        try:
            T, L = struct.unpack_from('BB', data, offset)
            V = struct.unpack_from('%ds' % L, data, offset+2)[0]
        except struct.error as error:
            msg = " while decoding TLV %r" % hexlify(data[offset:])
            raise DecodeError(str(error) + msg)

        if T == Parameter.VERSION:
            if L != 1:
                raise DecodeError("VERSION TLV length error")
            V = struct.unpack('B', V)[0]
        elif T == Parameter.MIUX:
            if L != 2:
                raise DecodeError("MIUX TLV length error")
            V = struct.unpack('>H', V)[0]
            if V & 0xF800:
                log.warning("MIUX TLV reserved bits set")
                V = V & 0x07FF
        elif T == Parameter.WKS:
            if L != 2:
                raise DecodeError("WKS TLV length error")
            V = struct.unpack('>H', V)[0]
        elif T == Parameter.LTO:
            if L != 1:
                raise DecodeError("LTO TLV length error")
            V = struct.unpack('B', V)[0]
        elif T == Parameter.RW:
            if L != 1:
                raise DecodeError("RW TLV length error")
            V = struct.unpack('B', V)[0]
            if V & 0xF0:
                log.warning("RW TLV reserved bits set")
                V = V & 0x0F
        elif T == Parameter.SN and L == 0:
            log.warning("SN TLV with zero-length service name")
        elif T == Parameter.OPT:
            if L != 1:
                raise DecodeError("OPT TLV length error")
            V = struct.unpack_from('B', V)[0]
            if V & 0xF8:
                log.warning("OPT TLV reserved bits set")
                V = V & 0x07
        elif T == Parameter.SDREQ:
            if L == 0:
                raise DecodeError("SDREQ TLV length error")
            if L == 1:
                log.warning("SDREQ TLV with zero-length service name")
            V = struct.unpack('B%ds' % (L-1), V)
        elif T == Parameter.SDRES:
            if L != 2:
                raise DecodeError("SDRES TLV length error")
            V = struct.unpack('BB', V)
        elif T == Parameter.ECPK:
            if L == 0:
                log.warning("ECPK TLV with zero-length value")
            if L & 1:
                log.warning("ECPK TLV with odd length value")
        elif T == Parameter.RN:
            if L == 0:
                log.warning("RN TLV with zero-length value")

        return (T, L, V)

    @staticmethod
    def encode(T, V):
        try:
            if T in (Parameter.VERSION, Parameter.LTO,
                     Parameter.RW, Parameter.OPT):
                return struct.pack('BBB', T, 1, V)
            if T in (Parameter.MIUX, Parameter.WKS):
                return struct.pack('>BBH', T, 2, V)
            if T in (Parameter.SN, Parameter.ECPK, Parameter.RN):
                if len(V) > 255:
                    raise EncodeError("can't encode TLV T=%d, V=%r" % (T, V))
                return struct.pack('BB', T, len(V)) + bytes(V)
            if T == Parameter.SDREQ:
                tid, sn = V[0], V[1]
                if len(sn) > 254:
                    raise EncodeError("can't encode TLV T=%d, V=%r" % (T, V))
                return struct.pack('>BBB', T, 1+len(sn), tid) + bytes(sn)
            if T == Parameter.SDRES:
                tid, sap = V[0], V[1]
                return struct.pack('>BBBB', T, 2, tid, sap)
            raise EncodeError("unknown TLV T=%d, V=%r" % (T, V))
        except struct.error as error:
            msg = " for TLV T=%d, V=%r" % (T, V)
            raise EncodeError(str(error) + msg)


# -----------------------------------------------------------------------------
#                                                   ProtocolDataUnit Base Class
# -----------------------------------------------------------------------------
class ProtocolDataUnit(object):
    header_size = 2

    def __init__(self, ptype, dsap, ssap):
        self.ptype = ptype
        self.dsap = dsap
        self.ssap = ssap

    @classmethod
    def decode_header(cls, data, offset=0, size=None):
        if size is None:
            size = len(data) - offset
        if size < cls.header_size:
            raise DecodeError("insufficient pdu header bytes")
        (dsap, ssap) = struct.unpack_from('!BB', data, offset)
        return (dsap >> 2, ssap & 63)

    def encode_header(self):
        if self.dsap is None or self.ssap is None:
            raise EncodeError("pdu dsap and ssap field can not be None")
        if self.dsap < 0 or self.ssap < 0:
            raise EncodeError("pdu dsap and ssap field can not be < 0")
        if self.dsap > 63 or self.ssap > 63:
            raise EncodeError("pdu dsap and ssap field can not be > 63")
        return struct.pack('!H', self.dsap << 10 | self.ptype << 6 | self.ssap)

    def __eq__(self, other):
        return self.encode() == other.encode()

    def __str__(self):
        string = "{pdu.ssap:2} -> {pdu.dsap:2} {pdu.name:4.4s}"
        return string.format(pdu=self)


# -----------------------------------------------------------------------------
#                                           NumberedProtocolDataUnit Base Class
# -----------------------------------------------------------------------------
class NumberedProtocolDataUnit(ProtocolDataUnit):
    header_size = 3

    def __init__(self, ptype, dsap, ssap, ns, nr):
        super(NumberedProtocolDataUnit, self).__init__(ptype, dsap, ssap)
        self.ns, self.nr = ns, nr

    @classmethod
    def decode_header(cls, data, offset=0, size=None):
        if size is None:
            size = len(data) - offset
        if size < cls.header_size:
            raise DecodeError("numbered pdu header length error")
        (dsap, ssap, sequence) = struct.unpack_from('!BBB', data, offset)
        return (dsap >> 2, ssap & 63, sequence >> 4, sequence & 15)

    def encode_header(self):
        data = super(NumberedProtocolDataUnit, self).encode_header()
        if self.ns is None or self.nr is None:
            raise EncodeError("pdu ns and nr field can not be None")
        if self.ns < 0 or self.nr < 0:
            raise EncodeError("pdu ns and nr field can not be < 0")
        if self.ns > 15 or self.nr > 15:
            raise EncodeError("pdu ns and nr field can not be > 15")
        return data + struct.pack('!B', self.ns << 4 | self.nr)

    def __len__(self):
        return 3

    def __str__(self):
        f = " N(R)={p.nr}" if self.ns is None else " N(S)={p.ns} N(R)={p.nr}"
        return super(NumberedProtocolDataUnit, self).__str__()+f.format(p=self)


# -----------------------------------------------------------------------------
#                                                                  Symmetry PDU
# -----------------------------------------------------------------------------
class Symmetry(ProtocolDataUnit):
    name = "SYMM"

    def __init__(self, dsap=0, ssap=0):
        super(Symmetry, self).__init__(0b0000, dsap, ssap)

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        if dsap != 0 or ssap != 0:
            raise DecodeError("SSAP and DSAP must be 0 in SYMM PDU")
        if size >= 3:
            raise DecodeError("SYMM PDU PAYLOAD must be empty")
        return Symmetry(dsap, ssap)

    def encode(self):
        if self.dsap != 0 or self.ssap != 0:
            raise EncodeError("SSAP and DSAP must be 0 in SYMM PDU")
        return self.encode_header()

    def __len__(self):
        return 2

    def __str__(self):
        return super(Symmetry, self).__str__()


# -----------------------------------------------------------------------------
#                                                        Parameter Exchange PDU
# -----------------------------------------------------------------------------
class ParameterExchange(ProtocolDataUnit):
    name = "PAX"

    def __init__(self, dsap=0, ssap=0, version=None, miux=None,
                 wks=None, lto=None, opt=None):
        super(ParameterExchange, self).__init__(0b0001, dsap, ssap)
        self._version = version
        self._miux = miux
        self._wks = wks
        self._lto = lto
        self._opt = opt

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        if dsap != 0 or ssap != 0:
            raise DecodeError("SSAP and DSAP must be 0 in PAX PDU")
        pax_pdu = ParameterExchange(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size >= 2:
            T, L, V = Parameter.decode(data, offset)
            if T == Parameter.VERSION:
                pax_pdu._version = V
            elif T == Parameter.MIUX:
                pax_pdu._miux = V
            elif T == Parameter.WKS:
                pax_pdu._wks = V
            elif T == Parameter.LTO:
                pax_pdu._lto = V
            elif T == Parameter.OPT:
                pax_pdu._opt = V
            else:
                log.warning("invalid TLV %r in PAX PDU", (T, L, V))
            offset, size = offset + 2 + L, size - 2 - L
        return pax_pdu

    def encode(self):
        if self.dsap != 0 or self.ssap != 0:
            raise EncodeError("SSAP and DSAP must be 0 in PAX PDU")
        data = self.encode_header()
        if self._version is not None:
            data += Parameter.encode(Parameter.VERSION, self._version)
        if self._miux is not None:
            data += Parameter.encode(Parameter.MIUX, self._miux)
        if self._wks is not None:
            data += Parameter.encode(Parameter.WKS, self._wks)
        if self._lto is not None:
            data += Parameter.encode(Parameter.LTO, self._lto)
        if self._opt is not None:
            data += Parameter.encode(Parameter.OPT, self._opt)
        return data

    def __len__(self):
        return (2 +
                (3 if self._version is not None else 0) +
                (4 if self._miux is not None else 0) +
                (4 if self._wks is not None else 0) +
                (3 if self._lto is not None else 0) +
                (3 if self._opt is not None else 0))

    @property
    def version(self):
        version = self._version
        return (version >> 4, version & 15) if version else (0, 0)

    @version.setter
    def version(self, value):
        self._version = (value[0] << 4 & 0xF0) | (value[1] & 0x0F)

    @property
    def version_text(self):
        return "{0}.{1}".format(*self.version)

    @property
    def miu(self):
        return self._miux + 128 if self._miux is not None else 128

    @miu.setter
    def miu(self, value):
        self._miux = max(value - 128, 0)

    @property
    def wks(self):
        return self._wks if self._wks is not None else 0

    @wks.setter
    def wks(self, value):
        self._wks = value & 0xFFFF

    @property
    def wks_text(self):
        t = {0: "LLC", 1: "SDP", 4: "SNEP"}
        return ', '.join([
            t.get(i, str(i)) for i in range(15, -1, -1) if self.wks >> i & 1])

    @property
    def lto(self):
        return (self._lto if self._lto is not None else 10) * 10

    @lto.setter
    def lto(self, value):
        self._lto = (value // 10) & 0xFF

    @property
    def lsc(self):
        return self._opt & 3 if self._opt is not None else 0

    @lsc.setter
    def lsc(self, value):
        self._opt = ((self._opt or 0) & 0b11111100) | (value & 0b00000011)

    @property
    def lsc_text(self):
        return ("link service class unknown at activation",
                "connection-less link service only",
                "connection-oriented link service only",
                "connection-less and connection-oriented")[self.lsc]

    @property
    def dpc(self):
        return self._opt >> 2 & 1 if self._opt is not None else 0

    @dpc.setter
    def dpc(self, value):
        self._opt = ((self._opt or 0) & 0b11111011) | (bool(value) << 2)

    @property
    def dpc_text(self):
        return ("secure data transfer mode not supported",
                "secure data transfer mode is supported")[self.dpc]

    def __str__(self):
        s = super(ParameterExchange, self).__str__()
        if self._version is not None:
            s += " VER={0}.{1}".format(*self.version)
        if self._wks is not None:
            s += " WKS={0:016b}".format(self._wks)
        if self._miux is not None:
            s += " MIUX={0}".format(self._miux)
        if self._lto is not None:
            s += " LTO={0}".format(self._lto)
        if self._opt is not None:
            s += " OPT={0:08b}".format(self._opt)
        return s


# -----------------------------------------------------------------------------
#                                                          Aggregated Frame PDU
# -----------------------------------------------------------------------------
class AggregatedFrame(ProtocolDataUnit):
    name = "AGF"

    def __init__(self, dsap=0, ssap=0, aggregate=[]):
        super(AggregatedFrame, self).__init__(0b0010, dsap, ssap)
        self._aggregate = aggregate[:]

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        if dsap != 0 or ssap != 0:
            raise DecodeError("SSAP and DSAP must be 0 in AGF PDU")
        agf_pdu = AggregatedFrame(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size > 0:
            try:
                (pdu_size,) = struct.unpack_from('!H', data, offset)
            except struct.error:
                raise DecodeError("aggregated PDU length field error in AGF")
            agf_pdu.append(decode(data, offset+2, pdu_size))
            offset, size = offset + 2 + pdu_size, size - 2 - pdu_size
        return agf_pdu

    def encode(self):
        if self.dsap != 0 or self.ssap != 0:
            raise EncodeError("SSAP and DSAP must be 0 in AGF PDU")
        data = self.encode_header()
        for encoded_pdu in [pdu.encode() for pdu in self._aggregate]:
            data += struct.pack('!H', len(encoded_pdu)) + encoded_pdu
        return data

    def append(self, pdu):
        self._aggregate.append(pdu)

    @property
    def count(self):
        return len(self._aggregate)

    @property
    def first(self):
        return self._aggregate[0]

    def __len__(self):
        return 2 + sum([2+len(pdu) for pdu in self._aggregate])

    def __str__(self):
        def s(p):
            return "LEN={0} '".format(len(p)) + \
                ProtocolDataUnit.__str__(p).rstrip() + "'"
        return super(AggregatedFrame, self).__str__() + \
            " LEN={0} [".format(len(self)-2) + \
            " ".join([s(p) for p in self._aggregate]) + "]"

    def __iter__(self):
        return AggregatedFrameIterator(self._aggregate)


class AggregatedFrameIterator(object):
    def __init__(self, aggregate):
        self._aggregate = aggregate
        self._current = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self._current == len(self._aggregate):
            raise StopIteration
        self._current += 1
        return self._aggregate[self._current-1]

    def next(self):
        return self.__next__()


# -----------------------------------------------------------------------------
#                                                    Unnumbered Information PDU
# -----------------------------------------------------------------------------
class UnnumberedInformation(ProtocolDataUnit):
    name = "UI"

    def __init__(self, dsap, ssap, data=None):
        super(UnnumberedInformation, self).__init__(0b0011, dsap, ssap)
        self.data = data if data else b''

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        payload = bytes(data[offset+2:offset+size])
        return UnnumberedInformation(dsap, ssap, payload)

    def encode(self):
        return self.encode_header() + bytes(self.data)

    def __len__(self):
        return 2 + len(self.data)

    def __str__(self):
        return super(UnnumberedInformation, self).__str__() + \
            " LEN={0} DATA={1}".format(len(self.data), hexlify(self.data))


# -----------------------------------------------------------------------------
#                                                                   Connect PDU
# -----------------------------------------------------------------------------
class Connect(ProtocolDataUnit):
    name = "CONNECT"

    def __init__(self, dsap, ssap, miu=128, rw=1, sn=None):
        super(Connect, self).__init__(0b0100, dsap, ssap)
        self.miu = miu
        self.rw = rw
        self.sn = sn

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        connect_pdu = Connect(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size >= 2:
            T, L, V = Parameter.decode(data, offset)
            if T == Parameter.MIUX:
                connect_pdu.miu = 128 + V
            elif T == Parameter.RW:
                connect_pdu.rw = V
            elif T == Parameter.SN:
                connect_pdu.sn = V
            else:
                log.warning("invalid TLV %r in CONNECT PDU", (T, L, V))
            offset, size = offset + 2 + L, size - 2 - L
        return connect_pdu

    def encode(self):
        data = self.encode_header()
        if self.miu and self.miu > 128:
            data += Parameter.encode(Parameter.MIUX, self.miu - 128)
        if self.rw and self.rw != 1:
            data += Parameter.encode(Parameter.RW, self.rw)
        if self.sn:
            data += Parameter.encode(Parameter.SN, self.sn)
        return data

    def __len__(self):
        return (2 +
                (4 if self.miu and self.miu > 128 else 0) +
                (3 if self.rw and self.rw != 1 else 0) +
                (2 + len(self.sn) if self.sn else 0))

    def __str__(self):
        s = " MIU={conn.miu} RW={conn.rw} SN={conn.sn}"
        return super(Connect, self).__str__() + s.format(conn=self)


# -----------------------------------------------------------------------------
#                                                                Disconnect PDU
# -----------------------------------------------------------------------------
class Disconnect(ProtocolDataUnit):
    name = "DISC"

    def __init__(self, dsap, ssap):
        super(Disconnect, self).__init__(0b0101, dsap, ssap)

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        return Disconnect(dsap, ssap)

    def encode(self):
        return self.encode_header()

    def __len__(self):
        return 2

    def __str__(self):
        return super(Disconnect, self).__str__()


# -----------------------------------------------------------------------------
#                                                       Connection Complete PDU
# -----------------------------------------------------------------------------
class ConnectionComplete(ProtocolDataUnit):
    name = "CC"

    def __init__(self, dsap, ssap, miu=128, rw=1):
        super(ConnectionComplete, self).__init__(0b0110, dsap, ssap)
        self.miu = miu
        self.rw = rw

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        cc_pdu = ConnectionComplete(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size >= 2:
            T, L, V = Parameter.decode(data, offset)
            if T == Parameter.MIUX:
                cc_pdu.miu = 128 + V
            elif T == Parameter.RW:
                cc_pdu.rw = V
            else:
                log.warning("invalid TLV %r in CC PDU", (T, L, V))
            offset, size = offset + 2 + L, size - 2 - L
        return cc_pdu

    def encode(self):
        data = self.encode_header()
        if self.miu and self.miu > 128:
            data += Parameter.encode(Parameter.MIUX, self.miu - 128)
        if self.rw and self.rw != 1:
            data += Parameter.encode(Parameter.RW, self.rw)
        return data

    def __len__(self):
        return (2 +
                (4 if self.miu and self.miu > 128 else 0) +
                (3 if self.rw and self.rw != 1 else 0))

    def __str__(self):
        return super(ConnectionComplete, self).__str__() + \
            " MIU={cc.miu} RW={cc.rw}".format(cc=self)


# -----------------------------------------------------------------------------
#                                                         Disconnected Mode PDU
# -----------------------------------------------------------------------------
class DisconnectedMode(ProtocolDataUnit):
    name = "DM"

    def __init__(self, dsap, ssap, reason=0):
        super(DisconnectedMode, self).__init__(0b0111, dsap, ssap)
        self.reason = reason

    @classmethod
    def decode(cls, data, offset, size):
        if size != 3:
            raise DecodeError("DM PDU length error")
        dsap, ssap = cls.decode_header(data, offset, size)
        (reason,) = struct.unpack_from('!B', data, offset+2)
        return DisconnectedMode(dsap, ssap, reason)

    def encode(self):
        return self.encode_header() + struct.pack('!B', self.reason)

    def __len__(self):
        return 3

    def __str__(self):
        return super(DisconnectedMode, self).__str__() + \
            " REASON={dm.reason:02x}h".format(dm=self)

    @property
    def reason_text(self):
        return {
            0x00: "disconnected",
            0x01: "inactive",
            0x02: "unbound",
            0x03: "rejected",
            0x10: "permanent reject for sap",
            0x11: "permanent reject for any",
            0x20: "temporary reject for sap",
            0x21: "temporary reject for any",
        }.get(self.reason, "{0:02x}h".format(self.reason))


# -----------------------------------------------------------------------------
#                                                              Frame Reject PDU
# -----------------------------------------------------------------------------
class FrameReject(ProtocolDataUnit):
    name = "FRMR"

    def __init__(self, dsap, ssap, flags=0, ptype=0,
                 ns=0, nr=0, vs=0, vr=0, vsa=0, vra=0):
        super(FrameReject, self).__init__(0b1000, dsap, ssap)
        self.rej_flags = flags
        self.rej_ptype = ptype
        self.ns = ns
        self.nr = nr
        self.vs = vs
        self.vr = vr
        self.vsa = vsa
        self.vra = vra

    @classmethod
    def decode(cls, data, offset, size):
        if size != 6:
            raise DecodeError("FRMR PDU length error")
        dsap, ssap = cls.decode_header(data, offset, size)
        (b0, b1, b2, b3) = struct.unpack_from('!BBBB', data, offset+2)
        flags, ptype = b0 >> 4, b0 & 15
        ns, nr = b1 >> 4, b1 & 15
        vs, vr = b2 >> 4, b2 & 15
        vsa, vra = b3 >> 4, b3 & 15
        return FrameReject(dsap, ssap, flags, ptype, ns, nr, vs, vr, vsa, vra)

    @staticmethod
    def from_pdu(pdu, flags, dlc):
        rej_ptype = pdu.ptype
        rej_flags = sum([1 << "SRIW".index(f) for f in flags])
        frmr = FrameReject(pdu.ssap, pdu.dsap, rej_flags, rej_ptype)
        if isinstance(pdu, Information):
            frmr.ns, frmr.nr = pdu.ns, pdu.nr
        if isinstance(pdu, ReceiveReady) or isinstance(pdu, ReceiveNotReady):
            frmr.nr = pdu.nr
        frmr.vs, frmr.vsa = dlc.send_cnt, dlc.send_ack
        frmr.vr, frmr.vra = dlc.recv_cnt, dlc.recv_ack
        return frmr

    def encode(self):
        return self.encode_header() + struct.pack(
            '!BBBB', self.rej_flags << 4 | self.rej_ptype,
            self.ns << 4 | self.nr, self.vs << 4 | self.vr,
            self.vsa << 4 | self.vra)

    def __len__(self):
        return 6

    def __str__(self):
        return super(FrameReject, self).__str__() +\
            " FLAGS={frmr.rej_flags:04b} PTYPE={frmr.rej_ptype:04b}"\
            " N(S)={frmr.ns} N(R)={frmr.nr}"\
            " V(S)={frmr.vs} V(R)={frmr.vr}"\
            " V(SA)={frmr.vsa} V(RA)={frmr.vra}"\
            .format(frmr=self)


# -----------------------------------------------------------------------------
#                                                       Service Name Lookup PDU
# -----------------------------------------------------------------------------
class ServiceNameLookup(ProtocolDataUnit):
    name = "SNL"

    def __init__(self, dsap, ssap, sdreq=None, sdres=None):
        super(ServiceNameLookup, self).__init__(0b1001, dsap, ssap)
        self.sdreq = sdreq if sdreq else list()
        self.sdres = sdres if sdres else list()

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        if dsap != 1 or ssap != 1:
            raise DecodeError("SSAP and DSAP must be 1 in SNL PDU")
        snl_pdu = ServiceNameLookup(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size >= 2:
            T, L, V = Parameter.decode(data, offset)
            if T == Parameter.SDREQ:
                snl_pdu.sdreq.append(V)
            elif T == Parameter.SDRES:
                snl_pdu.sdres.append(V)
            else:
                log.warning("invalid TLV %r in SNL PDU", (T, L, V))
            offset, size = offset + 2 + L, size - 2 - L
        return snl_pdu

    def encode(self):
        data = self.encode_header()
        for sdreq in self.sdreq:
            data += Parameter.encode(Parameter.SDREQ, sdreq)
        for sdres in self.sdres:
            data += Parameter.encode(Parameter.SDRES, sdres)
        return data

    def __len__(self):
        return 2 + (len(self.sdres) * 4) \
            + sum([3+len(sdreq[1]) for sdreq in self.sdreq])

    def __str__(self):
        return super(ServiceNameLookup, self).__str__() + \
            " SDRES={0} SDREQ={1}".format(str(self.sdres), str(self.sdreq))


# -----------------------------------------------------------------------------
#                                                     Data Protection Setup PDU
# -----------------------------------------------------------------------------
class DataProtectionSetup(ProtocolDataUnit):
    name = "DPS"

    def __init__(self, dsap, ssap, ecpk=None, rn=None):
        super(DataProtectionSetup, self).__init__(0b1010, dsap, ssap)
        self.ecpk = ecpk
        self.rn = rn

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        if dsap != 0 or ssap != 0:
            raise DecodeError("SSAP and DSAP must be 0 in DPS PDU")
        dps_pdu = DataProtectionSetup(dsap, ssap)
        offset, size = offset + 2, size - 2
        while size >= 2:
            T, L, V = Parameter.decode(data, offset)
            if T == Parameter.ECPK:
                dps_pdu.ecpk = V
            elif T == Parameter.RN:
                dps_pdu.rn = V
            else:
                log.debug("unknown TLV %r in DPS PDU", (T, L, V))
            offset, size = offset + 2 + L, size - 2 - L
        return dps_pdu

    def encode(self):
        if self.dsap != 0 or self.ssap != 0:
            raise EncodeError("SSAP and DSAP must be 0 in DPS PDU")
        data = self.encode_header()
        if self.ecpk:
            data += Parameter.encode(Parameter.ECPK, self.ecpk)
        if self.rn:
            data += Parameter.encode(Parameter.RN, self.rn)
        return data

    def __len__(self):
        return (2 +
                (2 + len(self.ecpk) if self.ecpk else 0) +
                (2 + len(self.rn) if self.rn else 0))

    def __str__(self):
        return super(DataProtectionSetup, self).__str__() + \
            " ECPK={0} RN={1}".format(
                'None' if self.ecpk is None else hexlify(self.ecpk).decode(),
                'None' if self.rn is None else hexlify(self.rn).decode())


# -----------------------------------------------------------------------------
#                                                               Information PDU
# -----------------------------------------------------------------------------
class Information(NumberedProtocolDataUnit):
    name = "I"

    def __init__(self, dsap, ssap, ns=None, nr=None, data=None):
        super(Information, self).__init__(0b1100, dsap, ssap, ns, nr)
        self.data = data if data else b''

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap, ns, nr = cls.decode_header(data, offset, size)
        payload = bytes(data[offset+3:offset+size])
        return cls(dsap, ssap, ns, nr, payload)

    def encode(self):
        return self.encode_header() + bytes(self.data)

    def __len__(self):
        return 3 + len(self.data)

    def __str__(self):
        return (super(Information, self).__str__() + " LEN={0} DATA={1}"
                .format(len(self.data), hexlify(self.data)))


# -----------------------------------------------------------------------------
#                                                             Receive Ready PDU
# -----------------------------------------------------------------------------
class ReceiveReady(NumberedProtocolDataUnit):
    name = "RR"

    def __init__(self, dsap, ssap, nr=None):
        super(ReceiveReady, self).__init__(0b1101, dsap, ssap, 0, nr)

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap, ns, nr = cls.decode_header(data, offset, size)
        if ns != 0:
            log.warning("reserved bits set in sequence field")
        return cls(dsap, ssap, nr)

    def encode(self):
        return self.encode_header()


# -----------------------------------------------------------------------------
#                                                         Receive Not Ready PDU
# -----------------------------------------------------------------------------
class ReceiveNotReady(NumberedProtocolDataUnit):
    name = "RNR"

    def __init__(self, dsap, ssap, nr):
        super(ReceiveNotReady, self).__init__(0b1110, dsap, ssap, 0, nr)

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap, ns, nr = cls.decode_header(data, offset, size)
        if ns != 0:
            log.warning("reserved bits set in sequence field")
        return cls(dsap, ssap, nr)

    def encode(self):
        return self.encode_header()


# -----------------------------------------------------------------------------
#                                                       UnknownProtocolDataUnit
# -----------------------------------------------------------------------------
class UnknownProtocolDataUnit(ProtocolDataUnit):
    def __init__(self, ptype, dsap, ssap, payload):
        super(UnknownProtocolDataUnit, self).__init__(ptype, dsap, ssap)
        self.name = "{0:04b}".format(ptype)
        self.payload = payload

    @classmethod
    def decode(cls, data, offset, size):
        dsap, ssap = cls.decode_header(data, offset, size)
        pdutype = (data[offset] << 2 | data[offset+1] >> 6) & 0x0F
        payload = data[offset+2:offset+size]
        return cls(pdutype, dsap, ssap, payload)

    def encode(self):
        return self.encode_header() + bytes(self.payload)

    def __len__(self):
        return 2 + len(self.payload)

    def __str__(self):
        return (super(UnknownProtocolDataUnit, self).__str__()
                + " PAYLOAD={}".format(hexlify(self.payload).decode()))


# -----------------------------------------------------------------------------
# pdu decode and encode functions
# -----------------------------------------------------------------------------
pdu_type_map = {
    0b0000: Symmetry,
    0b0001: ParameterExchange,
    0b0010: AggregatedFrame,
    0b0011: UnnumberedInformation,
    0b0100: Connect,
    0b0101: Disconnect,
    0b0110: ConnectionComplete,
    0b0111: DisconnectedMode,
    0b1000: FrameReject,
    0b1001: ServiceNameLookup,
    0b1010: DataProtectionSetup,
    0b1100: Information,
    0b1101: ReceiveReady,
    0b1110: ReceiveNotReady,
}


def decode(data, offset=0, size=None):
    size = len(data) if size is None else size

    if offset + size > len(data):
        raise DecodeError("size bytes from offset exceed the data length")
    if size < 2:
        raise DecodeError("less than two header bytes can't make a valid pdu")

    ptype = (struct.unpack_from('>H', data, offset)[0] >> 6) & 0b1111
    pdu_type = pdu_type_map.get(ptype, UnknownProtocolDataUnit)
    return pdu_type.decode(data, offset, size)


def encode(pdu):
    if not isinstance(pdu, ProtocolDataUnit):
        raise AttributeError("can't encode %s" % type(pdu))

    return pdu.encode()
