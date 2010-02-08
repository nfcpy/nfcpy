# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

import nfc.ndef
import struct
import re

class HandoverMessage(object):
    def __init__(self, scope, message):
        self.carriers = []
        if message is None:
            return
        handover_record = scope(message[0])
        record_map = dict([(record.name, record) for record in message[1:]])
        for ac_record in handover_record.alternative_carrier_list:
            carrier_record = record_map[ac_record.carrier_data_reference]
            if carrier_record.type == 'urn:nfc:wkt:Hc':
                hc_record = HandoverCarrierRecord(carrier_record)
                self.carriers.append({'carrier-type': hc_record.carrier_type})
                self.carriers[-1]['carrier-data'] = hc_record.carrier_data
            else:
                self.carriers.append({'carrier-type': carrier_record.type})
                self.carriers[-1]['config-data'] = carrier_record.data
            self.carriers[-1]['power-state'] = ac_record.carrier_power_state
            self.carriers[-1]['other-data'] = list()
            for aux_data_ref in ac_record.auxiliary_data_references:
                aux_data_record = record_map.get[aux_data_ref]
                self.carriers[-1]['other-data'].append(aux_data_record)

    def tostring(self, scope):
        message = nfc.ndef.Message( scope() )
        for reference, carrier in enumerate(self.carriers):
            ac_record = AlternativeCarrierRecord()
            ac_record.carrier_data_reference = "ac%d" % reference
            ac_record.power_state = carrier.get('power-state', 'unkonwn')
            message[0].alternative_carrier_list.append(ac_record)
            if "config-data" in carrier:
                record = nfc.ndef.Record()
                record.name = ac_record.carrier_data_reference
                record.type = carrier['carrier-type']
                record.data = carrier['config-data']
                message.append(record)
            else:
                record = HandoverSelectRecord()
                record.name = ac_record.carrier_data_reference
                record.carrier_type = carrier['carrier-type']
                if "carrier-data" in carrier:
                    record.carrier_data = carrier['carrier-data']
                message.append(record)
        return message.tostring()

class HandoverRequestMessage(HandoverMessage):
    def __init__(self, message=None):
        HandoverMessage.__init__(self, HandoverRequestRecord, message)
    def tostring(self):
        return HandoverMessage.tostring(self, HandoverRequestRecord)

class HandoverSelectMessage(HandoverMessage):
    def __init__(self, message=None):
        HandoverMessage.__init__(self, HandoverSelectRecord, message)
    def tostring(self):
        return HandoverMessage.tostring(self, HandoverSelectRecord)

class HandoverRequestRecord(nfc.ndef.Record):
    def __init__(self, record=None):
        self._version = 0x10
        self._ac_record_list = list()
        nfc.ndef.Record.__init__(self, record)

    @property
    def data(self):
        string = chr(self._version)
        for record in self._ac_record_list:
            string += record.tostring()
        return string

    @data.setter
    def data(self, string):
        if not string: return
        self._version = ord(string[0])
        string = string[1:]
        while len(string):
            record, string = nfc.ndef.Record.fromstring(string)
            if record.type == 'urn:nfc:wkt:ac':
                self._ac_record_list.append(AlternativeCarrierRecord(record))

    @property
    def type(self):
        return "urn:nfc:wkt:Hr"

    @type.setter
    def type(self, value):
        pass

    @property
    def version(self):
        return self._version >> 4, self._version & 0xF

    @property
    def alternative_carrier_list(self):
        return self._ac_record_list

class HandoverSelectRecord(HandoverRequestRecord):
    @property
    def type(self): 
        return "urn:nfc:wkt:Hs"

    @type.setter
    def type(self, value):
        pass

class HandoverCarrierRecord(nfc.ndef.Record):
    def __init__(self, record):
        nfc.ndef.Record.__init__(self, record)

    @property
    def data(self):
        carrier_type = self.carrier_type
        if carrier_type == '':
            type_format = 0
        elif carrier_type.startswith("urn:nfc:wkt:"):
            type_format = 1; carrier_type = carrier_type[12:]
        elif re.match(r'[a-zA-Z0-9-]+/[a-zA-Z0-9-+.]+', carrier_type):
            type_format = 2; carrier_type = carrier_type
        elif re.match(r'[a-zA-Z][a-zA-Z0-9+-.]*://', carrier_type):
            type_format = 3; carrier_type = carrier_type
        elif carrier_type.startswith("urn:nfc:ext:"):
            type_format = 4; carrier_type = carrier_type[12:]
        elif carrier_type.startswith("application/octet-stream"):
            type_format = 5; carrier_type = carrier_type[24:]
        return chr(len(carrier_type)) + carrier_type + self.carrier_data

    @data.setter
    def data(self, string):
        if not string: return
        type_format = ord(string[0]) & 0x7
        type_length = ord(string[1])
        self.carrier_type = nfc.ndef.type_prefix[type_format]
        self.carrier_type+= string[2:2+type_length]
        self.carrier_data = string[2+type_length:]

class AlternativeCarrierRecord(nfc.ndef.Record):
    def __init__(self, record=None):
        self._flags = 0x03
        self._cdr = ''
        self._adr_list = list()
        nfc.ndef.Record.__init__(self, record)

    @property
    def type(self):
        return "urn:nfc:wkt:ac"

    @type.setter
    def type(self, value):
        pass

    @property
    def data(self):
        string  = chr(self._flags)
        string += chr(len(self._cdr)) + self._cdr
        string += chr(len(self._adr_list))
        for aux_data_ref in self._adr_list:
            string += chr(len(aux_data)) + aux_data
        return string

    @data.setter
    def data(self, string):
        if not string: return
        self._flags = ord(string[0]); offset = 1
        self._cdr, offset = read_pascal_string(string, offset)
        aux_data_ref_count = ord(string[offset]); offset += 1
        self._adr_list = aux_data_ref_count * [None]
        for i in range(aux_data_ref_count):
            aux_data_ref, offset = read_pascal_string(string, offset)
            self._adr_list[i] = aux_data_ref

    power_state_string = ("inactive", "active", "activating", "unknown")

    @property
    def power_state(self):
        return self.carrier_power_state

    @power_state.setter
    def power_state(self, value):
        self.carrier_power_state = value

    @property
    def carrier_power_state(self):
        return AlternativeCarrierRecord.power_state_string[self._flags & 0x03]

    @carrier_power_state.setter
    def carrier_power_state(self, value):
        try: i = AlternativeCarrierRecord.power_state_string.index(value)
        except ValueError: raise ValueError("unknown power state value")
        self._flags = (self._flags & ~0x03) | i

    @property
    def carrier_data_reference(self):
        return self._cdr

    @carrier_data_reference.setter
    def carrier_data_reference(self, value):
        if type(value) == type(str()):
            self._cdr = value
        else: raise ValueError("value must be a string")

    @property
    def auxiliary_data_references(self):
        return self._adr_list

def read_pascal_string(string, offset):
    length = ord(string[offset]); offset += 1
    text = string[offset:offset+length]
    return text, offset+length


