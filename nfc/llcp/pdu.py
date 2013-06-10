# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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

__all__ = ["ProtocolDataUnit", "Symmetry", "ParameterExchange",
           "AggregatedFrame", "UnnumberedInformation", "Connect",
           "Disconnect", "ConnectionComplete", "DisconnectedMode",
           "FrameReject", "ServiceNameLookup", "Information",
           "ReceiveReady", "ReceiveNotReady", "connection_mode_pdu_types"]

import struct
import logging
log = logging.getLogger(__name__)

connection_mode_pdu_types = (4, 5, 6, 7, 8, 12, 13, 14)

class Parameter:
    VERSION, MIUX, WKS, LTO, RW, SN, OPT, SDREQ, SDRES = range(1, 10)

class ProtocolDataUnit(object):
    Symmetry = 0b0000
    ParameterExchange = 0b0001
    AggregatedFrame = 0b0010
    UnnumberedInformation = 0b0011
    Connect = 0b0100
    Disconnect = 0b0101
    ConnectionComplete = 0b0110
    DisconnectedMode = 0b0111
    FrameReject = 0b1000
    ServiceNameLookup = 0b1001
    Information = 0b1100
    ReceiveReady = 0b1101
    ReceiveNotReady = 0b1110
    
    def __init__(self, ptype, dsap, ssap):
        self.type = ptype
        self.dsap = dsap
        self.ssap = ssap
        self.name = "{0:04b}".format(ptype)

    @staticmethod
    def from_string(s):
        h = struct.unpack("!H", s[0:2])[0]
        dsap, ptype, ssap = (h>>10, h>>6 & 0b1111, h & 0b111111)

        if ptype == 0b0000:
            return Symmetry(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0001:
            return ParameterExchange(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0010:
            return AggregatedFrame(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0011:
            return UnnumberedInformation(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0100:
            return Connect(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0101:
            return Disconnect(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0110:
            return ConnectionComplete(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b0111:
            return DisconnectedMode(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b1000:
            return FrameReject(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b1001:
            return ServiceNameLookup(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b1100:
            return Information(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b1101:
            return ReceiveReady(dsap=dsap, ssap=ssap).from_string(s)
        if ptype == 0b1110:
            return ReceiveNotReady(dsap=dsap, ssap=ssap).from_string(s)

        return ProtocolDataUnit(ptype, dsap=dsap, ssap=ssap)
        
    def to_string(self):
        s  = chr((self.dsap << 2) | (self.type >> 2))
        s += chr(((self.type & 0b11) << 6) | (self.ssap))
        if self.type >= 0b1100 and pdu._type <= 0b1110:
            s += chr(self._nr)
            if self.type == 0b1100:
                s[2] |= chr(self._ns << 4)
        if self._data:
            s += self._data
        return s

    def __eq__(self, other):
        return self.to_string() == other.to_string()

    def __str__(self):
        string = "{pdu.ssap:2} -> {pdu.dsap:2} {pdu.name:4.4s}"
        return string.format(pdu=self)



class Symmetry(ProtocolDataUnit):
    def __init__(self, dsap=0, ssap=0):
        ProtocolDataUnit.__init__(self, 0b0000, dsap, ssap)
        self.name = "SYMM"

    def from_string(self, s):
        return self

    def to_string(self):
        return "\x00\x00"

    def __len__(self):
        return 2

    def __str__(self):
        return ProtocolDataUnit.__str__(self)

class ParameterExchange(ProtocolDataUnit):
    def __init__(self, dsap=0, ssap=0, version=(1,0), miu=128, wks=3, lto=100):
        ProtocolDataUnit.__init__(self, 0b0001, dsap, ssap)
        self.name = "PAX"
        self.version = version
        self.miu = miu
        self.wks = wks
        self.lto = lto
        self.lsc = 3

    def from_string(self, s):
        offset = 2
        while offset < len(s):
            t, l = [ord(x) for x in s[offset:offset+2]]
            v = s[offset+2:offset+2+l]
            if t == Parameter.VERSION and l == 1:
                self.version = (ord(v)/16, ord(v)%16)
            elif t == Parameter.MIUX and l == 2:
                miux = struct.unpack("!H", v)[0]
                self.miu = 128 + (miux & 0x07FF)
            elif t == Parameter.WKS and l == 2:
                self.wks = struct.unpack("!H", v)[0]
            elif t == Parameter.LTO and l == 1:
                self.lto = ord(v[0]) * 10
            elif t == Parameter.OPT and l == 1:
                self.lsc = ord(v[0])
            offset += 2 + l
        return self

    def to_string(self):
        version = self.version[0]<<4 | self.version[1]
        s  = struct.pack("!BB", self.dsap<<2|0b00, 0b01<<6|self.ssap)
        s += struct.pack("!BBB", Parameter.VERSION, 1, version)
        if self.miu > 128:
            s += struct.pack("!BBH", Parameter.MIUX, 2, self.miu - 128)
        s += struct.pack("!BBH", Parameter.WKS, 2, self.wks)
        if self.lto != 100:
            s += struct.pack("!BBB", Parameter.LTO, 1, self.lto / 10)
        s += struct.pack("!BBB", Parameter.OPT, 1, self.lsc)
        return s

    def __len__(self):
        # we transmit all possible parameters
        # len(header) + len(ver) + len(miux) + len(wks) + len(lto) + len(lsc)
        return 2 + 3 + 4 + 4 + 3 + 3

    def __str__(self):
        return ProtocolDataUnit.__str__(self) + \
            " VER={pax.version} MIU={pax.miu} WKS={pax.wks:016b}"\
            " LTO={pax.lto}".format(pax=self)



class AggregatedFrame(ProtocolDataUnit):
    def __init__(self, dsap=0, ssap=0, aggregate=[]):
        ProtocolDataUnit.__init__(self, 0b0010, dsap, ssap)
        self.name = "AGF"
        self._aggregate = aggregate[:]

    def from_string(self, s):
        offset = 2
        while offset < len(s):
            pdu_len = struct.unpack("!H", s[offset:offset+2])[0]
            pdu = ProtocolDataUnit.from_string(s[offset+2:offset+2+pdu_len])
            self.append(pdu)
            offset += 2 + pdu_len
        return self

    def to_string(self):
        data = ""
        for pdu in self._aggregate:
            data += struct.pack("!H", len(pdu)) + pdu.to_string()
        return chr(self.dsap<<2|0b00) + chr(0b10<<6|self.ssap) + data
        
    def append(self, pdu):
        self._aggregate.append(pdu)

    def __len__(self):
        return 2 + sum([2+len(p) for p in self._aggregate])

    def __str__(self):
        def s(p):
            return "LEN={0} '".format(len(p)) + \
                ProtocolDataUnit.__str__(p).rstrip() + "'"
        return ProtocolDataUnit.__str__(self) + \
             " LEN={0} [".format(len(self)) + \
             " ".join([s(p) for p in self._aggregate]) + "]"

    def __iter__(self):
        return AggregatedFrameIterator(self._aggregate)

class AggregatedFrameIterator(object):
    def __init__(self, aggregate):
        self._aggregate = aggregate
        self._current = 0

    def next(self):
        if self._current == len(self._aggregate):
            raise StopIteration
        self._current += 1
        return self._aggregate[self._current-1]



class UnnumberedInformation(ProtocolDataUnit):
    def __init__(self, dsap, ssap, sdu=""):
        ProtocolDataUnit.__init__(self, 0b0011, dsap, ssap)
        self.name = "UI"
        self.sdu = sdu
        pass

    def from_string(self, s):
        self.sdu = s[2:]
        return self
        
    def to_string(self):
        return chr(self.dsap<<2|0b00) + chr(0b11<<6|self.ssap) + self.sdu

    def __len__(self):
        return 2 + len(self.sdu)

    def __str__(self):
        return ProtocolDataUnit.__str__(self) + " LEN={len} SDU={sdu}".\
            format(len=len(self.sdu), sdu=self.sdu.encode("hex"))



class Connect(ProtocolDataUnit):
    def __init__(self, dsap, ssap, miu=128, rw=1, sn=""):
        ProtocolDataUnit.__init__(self, 0b0100, dsap, ssap)
        self.name = "CONNECT"
        self.miu = miu
        self.rw = rw
        self.sn = sn
        pass

    def from_string(self, s):
        offset = 2
        while offset < len(s):
            t, l = [ord(x) for x in s[offset:offset+2]]
            if t == 2 and l == 2:
                miux = struct.unpack("!H", s[offset+2:offset+4])[0]
                self.miu = 128 + (miux & 0x07FF)
            if t == 5 and l == 1:
                self.rw = ord(s[offset+2]) & 0x0F
            if t == 6 and l > 0:
                self.sn = s[offset+2:offset+2+l]
            offset += 2 + l
        return self
        
    def to_string(self):
        data = ""
        if self.miu > 128:
            miux = self.miu - 128
            data += "\x02\x02" + chr(miux/256) + chr(miux%256)
        if self.rw != 1:
            data += "\x05\x01" + chr(self.rw)
        if self.sn:
            data += "\x06" + chr(len(self.sn)) + self.sn
        return chr(self.dsap<<2|0b01) + chr(0b00<<6|self.ssap) + data

    def __len__(self):
        return 2 + (0,4)[self.miu>128] + (0,3)[self.rw!=1] \
            + (0,2+len(self.sn))[bool(self.sn)]

    def __str__(self):
        s  = " MIU={conn.miu} RW={conn.rw}".format(conn=self)
        s += " SN={conn.sn}".format(conn=self) if self.sn else ""
        return ProtocolDataUnit.__str__(self) + s



class Disconnect(ProtocolDataUnit):
    def __init__(self, dsap, ssap):
        ProtocolDataUnit.__init__(self, 0b0101, dsap, ssap)
        self.name = "DISC"

    def from_string(self, s):
        return self
        
    def to_string(self):
        return chr(self.dsap<<2|0b01) + chr(0b01<<6|self.ssap)

    def __len__(self):
        return 2

    def __str__(self):
        return ProtocolDataUnit.__str__(self)


class ConnectionComplete(ProtocolDataUnit):
    def __init__(self, dsap, ssap, miu=128, rw=1):
        ProtocolDataUnit.__init__(self, 0b0110, dsap, ssap)
        self.name = "CC"
        self.miu = miu
        self.rw = rw

    def from_string(self, s):
        offset = 2
        while offset < len(s):
            t, l = [ord(x) for x in s[offset:offset+2]]
            if t == 2 and l == 2:
                miux = struct.unpack("!H", s[offset+2:offset+4])[0]
                self.miu = 128 + (miux & 0x07FF)
            if t == 5 and l == 1:
                self.rw = ord(s[offset+2]) & 0x0F
            offset += 2 + l
        return self

    def to_string(self):
        data = ""
        if self.miu > 128:
            miux = self.miu - 128
            data += "\x02\x02" + chr(miux/256) + chr(miux%256)
        if self.rw != 1:
            data += "\x05\x01" + chr(self.rw)
        return chr(self.dsap<<2|0b01) + chr(0b10<<6|self.ssap) + data

    def __len__(self):
        return 2 + (0,4)[self.miu>128] + (0,3)[self.rw!=1]

    def __str__(self):
        return ProtocolDataUnit.__str__(self) + \
            " MIU={cc.miu} RW={cc.rw}".format(cc=self)



class DisconnectedMode(ProtocolDataUnit):
    def __init__(self, dsap, ssap, reason=0):
        ProtocolDataUnit.__init__(self, 0b0111, dsap, ssap)
        self.name = "DM"
        self.reason = reason

    def from_string(self, s):
        self.reason = ord(s[2])
        return self

    def to_string(self):
        return chr(self.dsap<<2|0b01) + chr(0b11<<6|self.ssap)\
            + chr(self.reason)

    def __len__(self):
        return 3

    def __str__(self):
        return ProtocolDataUnit.__str__(self) + \
            " REASON={dm.reason}".format(dm=self)



class FrameReject(ProtocolDataUnit):
    def __init__(self, dsap, ssap, flags=0, ptype=0,
                 ns=0, nr=0, vs=0, vr=0, vsa=0, vra=0):
        ProtocolDataUnit.__init__(self, 0b1000, dsap, ssap)
        self.name = "FRMR"
        self.flags = flags
        self.ptype = ptype
        self.ns = ns
        self.nr = nr
        self.vs = vs
        self.vr = vr
        self.vsa = vsa
        self.vra = vra

    def from_string(self, s):
        b0, b1, b2, b3 = struct.unpack("BBBB", s[2:6])
        self.flags = b0 >> 4
        self.ptype = b0 & 15
        self.ns = b1 >> 4
        self.nr = b1 & 15
        self.vs = b2 >> 4
        self.vr = b2 & 15
        self.vsa = b3 >> 4
        self.vra = b3 & 15
        return self

    def to_string(self):
        return chr(self.dsap<<2|0b10) + chr(0b00<<6|self.ssap)\
            + chr(self.flags<<4|self.ptype)\
            + chr(self.ns<<4|self.nr)\
            + chr(self.vs<<4|self.vr)\
            + chr(self.vsa<<4|self.vra)

    @staticmethod
    def from_pdu(pdu, flags, dlc):
        frmr = FrameReject(pdu.ssap, pdu.dsap, ptype=pdu.type)
        if "W" in flags: frmr.flags |= 0b1000
        if "I" in flags: frmr.flags |= 0b0100
        if "R" in flags: frmr.flags |= 0b0010
        if "S" in flags: frmr.flags |= 0b0001
        if isinstance(pdu, Information):
            frmr.ns, frmr.nr = pdu.ns, pdu.nr
        if isinstance(pdu, ReceiveReady) or isinstance(pdu, ReceiveNotReady):
            frmr.nr = pdu.nr
        frmr.vs, frmr.vsa = dlc.send_cnt, dlc.send_ack
        frmr.vr, frmr.vra = dlc.recv_cnt, dlc.recv_ack
        return frmr

    def __len__(self):
        return 6

    def __str__(self):
        return ProtocolDataUnit.__str__(self) +\
            " FLAGS={frmr.flags:04b} N(S)={frmr.ns} N(R)={frmr.nr}"\
            " V(S)={frmr.vs} V(R)={frmr.vr}"\
            " V(SA)={frmr.vsa} V(RA)={frmr.vra}"\
            .format(frmr=self)



class ServiceNameLookup(ProtocolDataUnit):
    def __init__(self, dsap, ssap):
        ProtocolDataUnit.__init__(self, 0b1001, dsap, ssap)
        self.name = "SNL"
        self.sdreq = list()
        self.sdres = list()

    def from_string(self, s):
        offset = 2
        while offset < len(s):
            t, l = [ord(x) for x in s[offset:offset+2]]
            v = s[offset+2:offset+2+l]
            if t == Parameter.SDREQ and len >= 1:
                tid, sn = ord(v[0]), v[1:]
                self.sdreq.append((tid, sn))
            if t == Parameter.SDRES and l == 2:
                tid, sap = ord(v[0]), ord(v[1]) & 0x3F
                self.sdres.append((tid, sap))
            offset += 2 + l
        return self

    def to_string(self):
        s = chr(self.dsap<<2|0b10) + chr(0b01<<6|self.ssap)
        for sdres in self.sdres:
            s = s + chr(Parameter.SDRES) + chr(2) \
                + chr(sdres[0]) + chr(sdres[1])
        for sdreq in self.sdreq:
            s = s + chr(Parameter.SDREQ) \
                + chr(1 + len(sdreq[1])) \
                + chr(sdreq[0]) + sdreq[1]
        return s

    def __len__(self):
        return 2 + (len(self.sdres) * 4) \
            + sum([3+len(sdreq[1]) for sdreq in self.sdreq])

    def __str__(self):
        return ProtocolDataUnit.__str__(self) \
            + "SDRES={0} SDREQ={1}".format(str(self.sdres), str(self.sdreq))



class Information(ProtocolDataUnit):
    def __init__(self, dsap, ssap, ns=None, nr=None, sdu=""):
        ProtocolDataUnit.__init__(self, 0b1100, dsap, ssap)
        self.name = "I"
        self.ns = ns
        self.nr = nr
        self.sdu = sdu

    def from_string(self, s):
        self.ns = ord(s[2]) >> 4
        self.nr = ord(s[2]) & 15
        self.sdu = s[3:]
        return self

    def to_string(self):
        return chr(self.dsap<<2|0b11) + chr(0b00<<6|self.ssap)\
            + chr(self.ns<<4|self.nr) + self.sdu

    def __len__(self):
        return 3 + len(self.sdu)

    def __str__(self):
        return ProtocolDataUnit.__str__(self) + \
            " N(S)={inf.ns} N(R)={inf.nr} LEN={len} SDU={sdu}" \
            .format(inf=self, len=len(self.sdu), sdu=self.sdu.encode("hex"))



class ReceiveReady(ProtocolDataUnit):
    def __init__(self, dsap, ssap, nr=None):
        ProtocolDataUnit.__init__(self, 0b1101, dsap, ssap)
        self.name = "RR"
        self.nr = nr

    def from_string(self, s):
        self.nr = ord(s[2]) & 15
        return self

    def to_string(self):
        return chr(self.dsap<<2|0b11) + chr(0b01<<6|self.ssap) + chr(self.nr)

    def __len__(self):
        return 3

    def __str__(self):
        return ProtocolDataUnit.__str__(self) +\
            " N(R)={rr.nr}".format(rr=self)



class ReceiveNotReady(ProtocolDataUnit):
    def __init__(self, dsap, ssap, nr=None):
        ProtocolDataUnit.__init__(self, 0b1110, dsap, ssap)
        self.name = "RNR"
        self.nr = nr

    def from_string(self, s):
        self.nr = ord(s[2]) & 15
        return self

    def to_string(self):
        return chr(self.dsap<<2|0b11) + chr(0b10<<6|self.ssap) + chr(self.nr)

    def __len__(self):
        return 3

    def __str__(self):
        return ProtocolDataUnit.__str__(self) +\
            " N(R)={rnr.nr}".format(rnr=self)



if __name__ == '__main__':
    print "--------------------------"
    print "- running positive tests -"
    print "--------------------------"
    test = (
        ( Symmetry(), 
          "\x00\x00" ),
        ( ParameterExchange(version=(1,1), miu=1024, wks=0x100F, lto=1000),
          "\x00\x40\x01\x01\x11\x02\x02\x03\x80\x03\x02\x10\x0F\x04\x01\x64" ),
        ( AggregatedFrame(aggregate=[Symmetry(), Symmetry()]),
          "\x00\x80\x00\x02\x00\x00\x00\x02\x00\x00" ),
        ( UnnumberedInformation(0, 0, "\xAA\xBB"),
          "\x00\xC0\xAA\xBB" ),
        ( Connect(0, 0, miu=1024, rw=8, sn="urn:nfc:sn:snep"),
          "\x01\x00\x02\x02\x03\x80\x05\x01\x08\x06\x0Furn:nfc:sn:snep" ),
        ( Disconnect(0, 0),
          "\x01\x40" ),
        ( ConnectionComplete(0, 0, miu=1024, rw=8),
          "\x01\x80\x02\x02\x03\x80\x05\x01\x08" ),
        ( DisconnectedMode(0, 0, reason=1),
          "\x01\xC0\x01" ),
        ( FrameReject(0, 0, 0b1010, 0b1100, 2, 3, 2, 3, 2, 3),
          "\x02\x00\xAC\x23\x23\x23" ),
        ( Information(0, 0, ns=2, nr=3, sdu="\x01\x02\x03\x04"),
          "\x03\x00\x23\x01\x02\x03\x04" ),
        ( ReceiveReady(0, 0, nr=4),
          "\x03\x40\x04" ),
        ( ReceiveNotReady(0, 0, nr=5),
          "\x03\x80\x05" ),
        )

    for p, s in test:
        print ("failed", "passed")[p.to_string() == s and len(p) == len(s)],
        print ProtocolDataUnit.from_string(s)

    print 
    for p, s in test:
        b0, b1 = struct.unpack("!BB", s[0:2])
        b0 |= 0x80; b1 |= 0x01
        s = struct.pack("!BB", b0, b1) + s[2:]
        s = str(ProtocolDataUnit.from_string(s))
        print ("failed", "passed")[s.startswith(" 1 -> 32")], s

    print
    agf = AggregatedFrame()
    for p, s in test:
        agf.append(p)
    print agf
    for p in agf:
        print p

    pdu1 = Disconnect(0,0)
    pdu2 = Disconnect(0,0)
    print repr(pdu1), "==", repr(pdu2), "->", pdu1 == pdu2
