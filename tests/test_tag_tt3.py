# -*- coding: latin-1 -*-
import nfc
import nfc.ndef
import nfc.tag.tt3
import ndef
import mock
import pytest
from pytest_mock import mocker  # noqa: F401
from struct import pack, unpack


def fromhex(s):
    return bytearray.fromhex(s)


@pytest.fixture()  # noqa: F811
def clf(mocker):
    clf = nfc.ContactlessFrontend()
    mocker.patch.object(clf, 'exchange', autospec=True)
    return clf


@pytest.fixture()
def target():
    target = nfc.clf.RemoteTarget("212F")
    #target.sensf_res = fromhex("000C")
    return target


class Type3TagSimulator(nfc.clf.ContactlessFrontend):
    pass
"""
    def __init__(self, tag_memory, sys="12 FC",
                 idm="02 FE 00 01 02 03 04 05",
                 pmm="03 01 4B 02 4F 49 93 FF"):
        self.dev = nfc.dev.Device()
        self.mem = tag_memory
        self.idm = bytearray.fromhex(idm)
        self.pmm = bytearray.fromhex(pmm)
        self.sys = [bytearray.fromhex(sys)]
        self.cmd_counter = 0
        self.tag_is_present = True
        self.expect_command = None
        self.expect_timeout = None
        self.return_response = None
        self.nbr, self.nbw = (None, None)

    def sense(self, targets):
        return nfc.clf.TTF(424, self.idm, self.pmm, self.sys[0])

    def exchange(self, data, timeout):
        self.cmd_counter += 1
        if self.tag_is_present is False:
            raise nfc.clf.TimeoutError("mute tag")
        if self.expect_command is not None:
            assert data == self.expect_command
        if self.expect_timeout is not None:
            assert timeout == self.expect_timeout
        if self.return_response is not None:
            return self.return_response

        data = bytearray(data)
        if data[1] == 0x00 and len(data) == 6: # POLLING
            if data[2:4] in ["\xFF\xFF"] + self.sys:
                if data[4] == 0x00:
                    return self.encode(0x00, self.idm, self.pmm, '')
                elif data[4] == 0x01:
                    sys = self.sys[0] if data[2:4] == "\xFF\xFF" else data[2:4]
                    return self.encode(0x00, self.idm, self.pmm +sys, '')
        if data[1] == 0x06 and data[2:10] == self.idm: # READ W/O ENC
            block_list = self.parse_service_and_block_list(data[10:])
            if self.nbr is not None and len(block_list) > self.nbr:
                return self.encode(0x06, self.idm, '', "\x01\xA2")
            maxt = self.calculate_timeout(self.pmm[5], len(block_list))
            assert timeout == maxt
            return self.read_blocks(block_list)

        if data[1] == 0x08 and data[2:10] == self.idm: # WRITE W/O ENC
            block_list = self.parse_service_and_block_list(data[10:])
            if self.nbw is not None and len(block_list) > self.nbw:
                return self.encode(0x08, self.idm, '', "\x01\xA2")
            maxt = self.calculate_timeout(self.pmm[6], len(block_list))
            assert timeout == maxt
            return self.write_blocks(data[-len(block_list)*16:], block_list)

        if data[1] == 0x02 and data[2:10] == self.idm: # REQUEST SERVICE
            return self.encode(0x02, self.idm, data[10:], status='')

        if data[1] == 0x04 and data[2:10] == self.idm: # REQUEST RESPONSE
            return self.encode(0x04, self.idm, chr(0), status='')

        if data[1] == 0x0A and data[2:10] == self.idm: # SEARCH SERVICE CODE
            index = unpack("<H", data[10:12])[0]
            if index == 0:
                data = '\x00\x00\xFE\xFF'
            else:
                try: data = pack("<H", sorted(self.mem.keys())[index-1])
                except IndexError: data = "\xFF\xFF"
            return self.encode(0x0A, self.idm, data, status='')

        if data[1] == 0x0C and data[2:10] == self.idm: # REQUEST SYSTEM CODE
            data = "\x02\x00\x00\x12\xFC"
            return self.encode(0x0C, self.idm, data, status='')

        raise nfc.clf.TimeoutError("unknown command")

    def read_blocks(self, block_list):
        data = bytearray()
        for service, block, i in block_list:
            try:
                data += self.mem[service][block]
            except (IndexError, TypeError):
                return self.encode(0x06, self.idm, '', "\x01\xA2")
        return self.encode(0x06, self.idm, chr(len(block_list)) + data)

    def write_blocks(self, data, block_list):
        for service, block, i in block_list:
            try:
                self.mem[service][block][:] = data[i*16:(i+1)*16]
            except IndexError:
                return self.encode(0x08, self.idm, '', "\x01\xA2")
        return self.encode(0x08, self.idm, '')

    @staticmethod
    def encode(cmd, idm, data, status='\x00\x00'):
        return chr(2+len(idm) + len(status) + len(data)) \
            + chr(cmd+1) + idm + status + data

    @staticmethod
    def calculate_timeout(pmm_byte, block_count):
        a, b, e = pmm_byte & 7, pmm_byte>>3 & 7, pmm_byte>>6
        return 302E-6 * ((b + 1) * block_count + a + 1) * 4**e

    @staticmethod
    def parse_service_and_block_list(data):
        service_list = [data[2*i+1] | (data[2*i+2]<<8) for i in range(data[0])]
        block_list_elements = data[1+data[0]*2]
        data = data[2+data[0]*2:]
        block_list = []
        for i in range(block_list_elements):
            if data[0] >> 7 == 1:
                service_index = data[0] & 0x0F
                block_number = data[1]
                del data[0:2]
            else:
                service_index = data[0] & 0x0F
                block_number = data[1] | (data[2] << 8)
                del data[0:3]
            block_list.append((service_list[service_index], block_number, i))
        return block_list
    
    def set_communication_mode(self, brm, **kwargs):
        pass
"""


#
# TEST TYPE 3 TAG CLASS
#
@pytest.mark.skip(reason="not yet converted")
class TestType3Tag:
    sys = "12 FC"
    idm = "01 02 03 04 05 06 07 08"
    pmm = "FF FF FF FF FF FF FF FF"

    def setup(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        ]]
        tag_memory = {
            0x000B: service_data, 0x004B: service_data[1:],
            0x0009: service_data, 0x0049: service_data[1:],
        }
        #self.clf = Type3TagSimulator(tag_memory, self.sys, self.idm, self.pmm)
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    #
    # NDEF DATA READ
    #
    def test_ndef_read_from_valid_data_area(self):
        assert self.tag.ndef is not None
        assert self.tag.ndef.capacity == 80
        assert self.tag.ndef.length == 16
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True

    def test_ndef_read_with_attribute_checksum_error(self):
        self.clf.mem[0x0009][0][15] = 0
        assert self.tag.ndef is None

    def test_ndef_read_with_invalid_major_version(self):
        self.clf.mem[0x0009][0][0] = 0x00
        self.clf.mem[0x0009][0][15] -= 0x10
        assert self.tag.ndef is None

    def test_ndef_read_from_non_ndef_tag(self):
        clf = Type3TagSimulator(None, "1234", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None

    def test_ndef_read_from_tag_without_memory(self):
        clf = Type3TagSimulator(None, "12FC", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is None

    def test_ndef_read_from_multi_system_tag(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 01 00  00 10 00 24",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        tag_memory = {0x000B: service_data, 0x0009: service_data}
        clf = Type3TagSimulator(tag_memory, "1234", self.idm, self.pmm)
        clf.sys.append(bytearray.fromhex("12FC"))
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.ndef is not None

    #
    # NDEF DATA WRITE
    #
    def test_ndef_write_to_readwrite_data_area(self):
        uri = 'http://cd.com'
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri))
        assert self.tag.ndef is not None
        self.tag.ndef.message = msg
        data = bytearray.fromhex("d1020b53 70d10107 55036364 2e636f6d")
        assert self.clf.mem[0x0009][1] == data

    #pytest.raises(AttributeError)
    def test_ndef_write_to_readonly_data_area(self):
        self.clf.mem[0x0009][0][10] -= 0x01
        self.clf.mem[0x0009][0][15] -= 0x01
        assert self.tag.ndef is not None
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.TextRecord(" "))

    #pytest.raises(ValueError)
    def test_ndef_write_to_smaller_data_area(self):
        assert self.tag.ndef is not None
        self.tag.ndef.message = nfc.ndef.Message(nfc.ndef.TextRecord(100*" "))

    #
    # TEST INIT, STR, IS_PRESENT
    #
    def test_init(self):
        assert self.tag.sys == 0x12FC
        assert self.tag.idm == bytearray.fromhex(self.idm)
        assert self.tag.pmm == bytearray.fromhex(self.pmm)
        assert self.tag._nbr == 1
        assert self.tag._nbw == 1
        
    def test_str(self):
        s = "Type3Tag ID=0102030405060708 PMM=FFFFFFFFFFFFFFFF SYS=12FC"
        assert str(self.tag) == s

    def test_is_present(self):
        assert self.tag.is_present == True
        self.clf.tag_is_present = False
        assert self.tag.is_present == False

    #
    # DUMP METHOD
    #
    def test_dump_ndef_data_area(self):
        lines = self.tag.dump()
        print("\n".join(lines))
        assert len(lines) == 8

    def test_dump_non_ndef_tag(self):
        clf = Type3TagSimulator(None, "1234", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.dump()[0] == "This is not an NFC Forum Tag."

    #
    # FORMAT METHOD
    #
    def test_format_default_arguments(self):
        assert self.tag.format() == True
        print("\n".join(self.tag.dump()))
        assert self.clf.mem[0x0009][0][0x00] == 0x10
        assert self.clf.mem[0x0009][0][0x01] == 0x0A
        assert self.clf.mem[0x0009][0][0x02] == 0x0A
        assert self.clf.mem[0x0009][0][0x03] == 0x00
        assert self.clf.mem[0x0009][0][0x04] == 0x09
        assert self.clf.mem[0x0009][0][0x05] == 0x00
        assert self.clf.mem[0x0009][0][0x06] == 0x00
        assert self.clf.mem[0x0009][0][0x07] == 0x00
        assert self.clf.mem[0x0009][0][0x08] == 0x00
        assert self.clf.mem[0x0009][0][0x09] == 0x00
        assert self.clf.mem[0x0009][0][0x0A] == 0x01
        assert self.clf.mem[0x0009][0][0x0B] == 0x00
        assert self.clf.mem[0x0009][0][0x0C] == 0x00
        assert self.clf.mem[0x0009][0][0x0D] == 0x00
        assert self.clf.mem[0x0009][0][0x0E] == 0x00
        assert self.clf.mem[0x0009][0][0x0F] == 0x2E

    def test_format_tag_with_nbr_6_and_nbw_4(self):
        self.clf.nbr, self.clf.nbw = (6, 4)
        assert self.tag.format() == True
        print("\n".join(self.tag.dump()))
        assert self.clf.mem[0x0009][0][0x00] == 0x10
        assert self.clf.mem[0x0009][0][0x01] == 0x06
        assert self.clf.mem[0x0009][0][0x02] == 0x04
        assert self.clf.mem[0x0009][0][0x03] == 0x00
        assert self.clf.mem[0x0009][0][0x04] == 0x09

    def test_format_tag_with_nbr_4_and_nbw_6(self):
        self.clf.nbr, self.clf.nbw = (4, 6)
        assert self.tag.format() == True
        print("\n".join(self.tag.dump()))
        assert self.clf.mem[0x0009][0][0x00] == 0x10
        assert self.clf.mem[0x0009][0][0x01] == 0x04
        assert self.clf.mem[0x0009][0][0x02] == 0x04
        assert self.clf.mem[0x0009][0][0x03] == 0x00
        assert self.clf.mem[0x0009][0][0x04] == 0x09

    def test_format_version_one_dot_one(self):
        assert self.tag.format(version=0x11) == False
        
    def test_format_version_two_dot_one(self):
        assert self.tag.format(version=0x21) == False

    def test_format_wipe_all_data_to_zero(self):
        assert self.tag.format(wipe=0) == True
        for block in self.clf.mem[0x0009][1:]:
            assert block == bytearray(16)
        
    def test_format_non_ndef_tag(self):
        clf = Type3TagSimulator(None, "1234", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.format() == False

    #
    # POLLING COMMAND
    #
    def test_polling_for_system_12fc(self):
        assert self.tag.polling(0x12FC) == (self.clf.idm, self.clf.pmm)
        
    def test_polling_for_system_ffff(self):
        assert self.tag.polling(0xFFFF) == (self.clf.idm, self.clf.pmm)
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_polling_for_system_fefe(self):
        try: self.tag.polling(0xFEFE)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.TIMEOUT_ERROR; raise
        
    def test_polling_with_request_system_code(self):
        rsp = self.tag.polling(0xFFFF, request_code=1)
        assert rsp == (self.clf.idm, self.clf.pmm, self.clf.sys[0])
    
    #pytest.raises(ValueError)
    def test_polling_with_invalid_request_code(self):
        self.tag.polling(0xFFFF, request_code=3)
        
    def __test_polling_with_time_slots_value(self):
        for v in (1, 3, 7, 15):
            yield self.check_polling_with_time_slots_value, v
        
    def check_polling_with_time_slots_value(self, v):
        self.clf.expect_command = bytearray("\x06\x00\xFF\xFF\x00" + chr(v))
        self.tag.polling(0xFFFF, time_slots=v)
        
    #pytest.raises(ValueError)
    def test_polling_with_invalid_time_slots(self):
        self.tag.polling(0xFFFF, time_slots=255)
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_polling_with_data_size_error(self):
        del self.clf.pmm[4:8]
        try: self.tag.polling(0x12FC)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    #
    # READ W/O ENCRYPTION COMMAND
    #
    def test_read_without_encryption(self):
        clf, tag = self.clf, self.tag
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        clf.mem = {0x000B:service_data, 0x004B:service_data[1:]}
        a, b, e = clf.pmm[5] & 7, clf.pmm[5]>>3 & 7, clf.pmm[5]>>6
        clf.expect_timeout = 302E-6 * ((b + 1) * 2 + a + 1) * 4**e
        
        sc_list = [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(1)]
        data = tag.read_without_encryption(sc_list, bc_list)
        assert data == service_data[0] + service_data[1]

        sc_list = 2 * [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(0, 0, 1)]
        data = tag.read_without_encryption(sc_list, bc_list)
        assert data == service_data[0] + service_data[0]
        
        sc_list = [nfc.tag.tt3.ServiceCode(1,11),nfc.tag.tt3.ServiceCode(0,11)]
        bc_list = [nfc.tag.tt3.BlockCode(0),nfc.tag.tt3.BlockCode(1, 0, 1)]
        data = tag.read_without_encryption(sc_list, bc_list)
        assert data == service_data[1] + service_data[1]
        
        del service_data[1][15]
        sc_list = [nfc.tag.tt3.ServiceCode(0, 11)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(1)]
        try: tag.read_without_encryption(sc_list, bc_list)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR
        else: assert 0, "expected data size error"

    #
    # READ FROM NDEF SERVICE METHOD
    #
    def test_read_from_ndef_service_with_system_12fc(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        self.clf.mem = {0x000B: service_data}
        data = self.tag.read_from_ndef_service(0, 1)
        assert data == service_data[0] + service_data[1]

    def test_read_from_ndef_service_with_system_1234(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        tag_memory = {0x000B: service_data}
        clf = Type3TagSimulator(tag_memory, "1234", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert tag.read_from_ndef_service(0, 1) == None

    #
    # WRITE W/O ENCRYPTION COMMAND
    #
    def test_write_without_encryption(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        self.clf.mem = {0x0009: service_data, 0x0049: service_data[1:]}
        a, b, e = self.clf.pmm[6]&7, self.clf.pmm[6]>>3&7, self.clf.pmm[6]>>6
        self.clf.expect_timeout = 302E-6 * ((b + 1) * 2 + a + 1) * 4**e
        data = service_data[0][:] + service_data[1][:]

        sc_list = [nfc.tag.tt3.ServiceCode(0, 9)]
        bc_list = [nfc.tag.tt3.BlockCode(1), nfc.tag.tt3.BlockCode(0)]
        self.tag.write_without_encryption(sc_list, bc_list, data)
        assert self.clf.mem[0x0009][1] + self.clf.mem[0x0009][0] == data

        sc_list = [nfc.tag.tt3.ServiceCode(0,9),nfc.tag.tt3.ServiceCode(1,9)]
        bc_list = [nfc.tag.tt3.BlockCode(0), nfc.tag.tt3.BlockCode(0, 0, 1)]
        self.tag.write_without_encryption(sc_list, bc_list, data)
        assert self.clf.mem[0x0009][0] + self.clf.mem[0x0049][0] == data

    #
    # WRITE TO NDEF SERVICE METHOD
    #
    def test_write_to_ndef_service_with_system_12fc(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        self.clf.mem = {0x0009: service_data}
        data = service_data[0][:] + service_data[1][:]
        self.tag.write_to_ndef_service(data, 1, 0)
        assert self.clf.mem[0x0009][1] + self.clf.mem[0x0009][0] == data

    def test_write_to_ndef_service_with_system_1234(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  01 00 00 00  00 00 00 00  00 10 00 23",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
        ]]
        tag_memory = {0x0009: service_data}
        clf = Type3TagSimulator(tag_memory, "1234", self.idm, self.pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        data = service_data[0][:] + service_data[1][:]
        tag.write_to_ndef_service(data, 1, 0)
        assert clf.mem[0x0009][0] + clf.mem[0x0009][1] == data

    #
    # SEND CMD RECV RSP METHOD
    #
    def test_send_cmd_recv_rsp_with_send_idm_false(self):
        self.clf.expect_command = bytearray("\x04\xF0\xA5\x5A")
        self.clf.return_response = bytearray("\x04\xF1\x5A\xA5")
        rsp = self.tag.send_cmd_recv_rsp(0xF0, "\xA5\x5A", 0.1, send_idm=False)
        assert rsp == "\x5A\xA5"
        
    def test_send_cmd_recv_rsp_with_check_status_true(self):
        self.clf.expect_command = "\x0B\xF0" + self.clf.idm + "\xA5"
        self.clf.return_response = "\x0D\xF1" + self.clf.idm + "\x00\x00\x5A"
        rsp = self.tag.send_cmd_recv_rsp(0xF0, "\xA5", 0.1, check_status=True)
        assert rsp == "\x5A"
        
    def test_send_cmd_recv_rsp_with_check_status_false(self):
        self.clf.expect_command = "\x0B\xF0" + self.clf.idm + "\xA5"
        self.clf.return_response = "\x0D\xF1" + self.clf.idm + "\x00\x00\x5A"
        rsp = self.tag.send_cmd_recv_rsp(0xF0, "\xA5", 0.1, check_status=False)
        assert rsp == "\x00\x00\x5A"
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_send_cmd_recv_rsp_with_timeout_error(self):
        try: self.tag.send_cmd_recv_rsp(0xF0, bytearray(), timeout=0.1)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.TIMEOUT_ERROR; raise
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_send_cmd_recv_rsp_with_rsp_length_error(self):
        self.clf.return_response = "\x0B\xF1" + self.clf.idm
        try: self.tag.send_cmd_recv_rsp(0xF0, bytearray(), timeout=0.1)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.RSP_LENGTH_ERROR; raise
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_send_cmd_recv_rsp_with_rsp_code_error(self):
        self.clf.return_response = "\x0A\xF0" + self.clf.idm
        try: self.tag.send_cmd_recv_rsp(0xF0, bytearray(), timeout=0.1)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.RSP_CODE_ERROR; raise
        
    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_send_cmd_recv_rsp_with_tag_idm_error(self):
        self.clf.return_response = "\x0A\xF1" + self.clf.idm[::-1]
        try: self.tag.send_cmd_recv_rsp(0xF0, bytearray(), timeout=0.1)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.TAG_IDM_ERROR; raise

    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_send_cmd_recv_rsp_with_tag_command_error(self):
        self.clf.expect_command = "\x0B\xF0" + self.clf.idm + "\xA5"
        self.clf.return_response = "\x0D\xF1" + self.clf.idm + "\x12\x34\x5A"
        try: self.tag.send_cmd_recv_rsp(0xF0, "\xA5", 0.1)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == 0x1234; raise

#
# TEST SERVICE CODE CLASS
#
@pytest.mark.skip(reason="not yet converted")
class TestServiceCode:
    def test_init(self):
        sc = nfc.tag.tt3.ServiceCode(1, 9)
        assert sc.number == 1
        assert sc.attribute == 9
        sc = nfc.tag.tt3.ServiceCode(number=1, attribute=9)
        assert sc.number == 1
        assert sc.attribute == 9
                
    def test_unpack(self):
        sc = nfc.tag.tt3.ServiceCode.unpack("\x0B\x01")
        assert sc.number == 4
        assert sc.attribute == 11

    def test_pack(self):
        assert nfc.tag.tt3.ServiceCode(4, 11).pack() == "\x0B\x01"

    def test_repr(self):
        sc = nfc.tag.tt3.ServiceCode(1, 8)
        assert repr(sc) == "ServiceCode(1, 8)"

    def test_str(self):
        sc = nfc.tag.tt3.ServiceCode(1, 8)
        assert str(sc) == "Service Code 0048h (Service 1 Random RW with key)"
        sc = nfc.tag.tt3.ServiceCode(1, 0b111111)
        assert str(sc) == "Service Code 007Fh (Service 1 Type 111111b)"

#
# TEST BLOCK CODE CLASS
#
@pytest.mark.skip(reason="not yet converted")
class TestBlockCode:
    def test_init(self):
        bc = nfc.tag.tt3.BlockCode(12)
        assert bc.number == 12
        assert bc.access == 0
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, 3)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, 3, 1)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 1
        bc = nfc.tag.tt3.BlockCode(12, access=3)
        assert bc.number == 12
        assert bc.access == 3
        assert bc.service == 0
        bc = nfc.tag.tt3.BlockCode(12, service=1)
        assert bc.number == 12
        assert bc.access == 0
        assert bc.service == 1

    def test_pack(self):
        assert nfc.tag.tt3.BlockCode(12).pack() == "\x80\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3).pack() == "\xB0\x0C"
        assert nfc.tag.tt3.BlockCode(12, 3, 1).pack() == "\xB1\x0C"
        assert nfc.tag.tt3.BlockCode(255).pack() == "\x80\xff"
        assert nfc.tag.tt3.BlockCode(256).pack() == "\x00\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3).pack() == "\x30\x00\x01"
        assert nfc.tag.tt3.BlockCode(256, 3, 1).pack() == "\x31\x00\x01"
        assert nfc.tag.tt3.BlockCode(0xffff).pack() == "\x00\xff\xff"

    def test_repr(self):
        sc = nfc.tag.tt3.BlockCode(1, 3, 7)
        assert repr(sc) == "BlockCode(1, 3, 7)"

    def test_str(self):
        sc = nfc.tag.tt3.BlockCode(1, 3)
        assert str(sc) == "BlockCode(number=1, access=011, service=0)"

@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaStandard:
    idm = "01 02 03 04 05 06 07 08"
    pmm = "00 01 FF FF FF FF FF FF"

    def setup(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        ]]
        tag_memory = {
            0x0009: service_data, 0x000B: service_data,
            0x0048: service_data[1:], 0x0049: service_data[1:],
            0x004A: service_data[1:], 0x004B: service_data[1:],
            0x010C: service_data[-1:], 0x010D: service_data[-1:],
            0x010E: service_data[-1:], 0x010F: service_data[-1:],
            0x0210: service_data[-1:], 0x0211: service_data[-1:],
            0x0312: service_data[-1:], 0x0313: service_data[-1:],
            0x0414: service_data[-1:], 0x0415: service_data[-1:],
            0x0516: service_data[-1:], 0x0517: service_data[-1:],
        }
        #self.clf = Type3TagSimulator(tag_memory, "0000", self.idm, self.pmm)
        #self.clf.sys.append(bytearray.fromhex("12FC"))
        #self.tag = self.clf.connect(rdwr={'on-connect': None})
    
    def __test_init_with_ic_code(self):
        for ic in (0, 1, 2, 8, 9, 11, 12, 13, 32, 50, 53):
            yield self.check_init_with_ic_code, ic

    def check_init_with_ic_code(self, ic):
        pmm = "00{0:02X}FFFF FFFFFFFF".format(ic)
        clf = Type3TagSimulator(None, "0000", self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaStandard)
        assert tag._product.startswith("FeliCa Standard")

    def test_request_service_success(self):
        sc_list = [nfc.tag.tt3.ServiceCode(0, 9), nfc.tag.tt3.ServiceCode(1, 9)]
        assert self.tag.request_service(sc_list) == [0x0009, 0x0049]

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_service_error(self):
        self.clf.return_response = "\x0B\x03" + self.clf.idm + '\x00'
        sc_list = [nfc.tag.tt3.ServiceCode(0, 9)]
        try: self.tag.request_service(sc_list)
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_request_response_success(self):
        assert self.tag.request_response() == 0

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_response_error(self):
        self.clf.return_response = "\x0C\x05" + self.clf.idm + "\0\0"
        try: self.tag.request_response()
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_search_service_code(self):
        assert self.tag.search_service_code(0) == (0x0000, 0xFFFE)
        assert self.tag.search_service_code(1) == (0x0009,)
        assert self.tag.search_service_code(2) == (0x000B,)
        assert self.tag.search_service_code(1000) == None

    def test_request_system_code(self):
        assert self.tag.request_system_code() == [0x0000, 0x12fc]

    #pytest.raises(nfc.tag.TagCommandError)
    def test_request_system_code_failure(self):
        self.clf.return_response = "\x0C\x0D" + self.clf.idm + '\x01\x02'
        try: self.tag.request_system_code()
        except nfc.tag.tt3.Type3TagCommandError as error:
            assert error.errno == nfc.tag.tt3.DATA_SIZE_ERROR; raise

    def test_is_present_if_present(self):
        assert self.tag.is_present is True

    def test_is_present_if_gone(self):
        self.clf.tag_is_present = False
        assert self.tag.is_present is False

    def test_dump(self):
        lines = self.tag.dump()
        assert len(lines) == 58

@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaMobile:
    idm = "01 02 03 04 05 06 07 08"
    
    def __test_init_with_ic_code(self):
        for ic in [6, 7] + range(16, 32):
            yield self.check_init_with_ic_code, ic

    def check_init_with_ic_code(self, ic):
        pmm = "00{0:02X}FFFF FFFFFFFF".format(ic)
        clf = Type3TagSimulator(None, "0000", self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaMobile)
        assert tag._product.startswith("FeliCa Mobile")

@pytest.mark.skip(reason="not yet converted")
class FelicaLiteTagSimulator(Type3TagSimulator):
    def read_blocks(self, block_list):
        data = bytearray()
        for service, block, i in block_list:
            try:
                data += self.mem[service][block]
            except (IndexError, TypeError):
                return self.encode(0x06, self.idm, '', "\x01\xA2")
        if len(block_list) > 1 and block_list[-1][1] == 0x81:
            ck = str(self.mem[9][0x87][7::-1] + self.mem[9][0x87][15:7:-1])
            rc = str(self.mem[9][0x80][7::-1] + self.mem[9][0x80][15:7:-1])
            sk = nfc.tag.pyDes.triple_des(ck, 1, 8 * '\0').encrypt(rc)
            mac = nfc.tag.tt3_sony.FelicaLite.generate_mac
            data[-16:-8] = mac(data[:-16], sk, rc[:8])
        return self.encode(0x06, self.idm, chr(len(block_list)) + data)

@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaLite:
    sys = "88 B4"
    idm = "01 02 03 04 05 06 07 08"
    pmm = "00 F0 FF FF FF FF FF FF"
    
    def setup(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  05 00 00 00  00 00 01 00  00 10 00 28",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF",
        ]] + 113 * [None] + [bytearray.fromhex(hexstr) for hexstr in [
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00",
        ]]
        tag_memory = {0x000B: service_data, 0x0009: service_data}
        #self.clf = FelicaLiteTagSimulator(
        #    tag_memory, self.sys, self.idm, self.pmm)
        #self.clf.sys.append(bytearray.fromhex("12FC"))
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_init(self):
        assert isinstance(self.tag, nfc.tag.tt3_sony.FelicaLite)
        assert self.tag._product == "FeliCa Lite (RC-S965)"
        assert self.tag._nbr == 4
        assert self.tag._nbw == 1

    def test_dump(self):
        lines = self.tag.dump()
        print "\n".join(lines)
        assert len(lines) == 15

    def test_read_ndef_without_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://ab.com"))
        assert self.tag.ndef is not None
        assert self.tag.ndef.capacity == 5 * 16
        assert self.tag.ndef.length == 16
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.message == msg

    def test_read_ndef_after_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://ab.com"))
        assert self.tag.authenticate('') is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.capacity == 5 * 16
        assert self.tag.ndef.length == 16
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.message == msg

    def test_write_ndef_without_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://cd.org"))
        self.tag.ndef.message = msg
        assert self.clf.mem[9][1][10:16] == "cd.org"

    def test_generate_mac_with_flip_key_false(self):
        data = str(bytearray(range(32)))
        key = str(bytearray(range(16)))
        iv = str(bytearray(range(8)))
        mac = nfc.tag.tt3_sony.FelicaLite.generate_mac(data, key, iv)
        assert mac == str(bytearray.fromhex("0b1268d7a4ac6932"))

    def test_generate_mac_with_flip_key_true(self):
        data = str(bytearray(range(32)))
        key = str(bytearray(range(16)))
        iv = str(bytearray(range(8)))
        mac = nfc.tag.tt3_sony.FelicaLite.generate_mac(data, key, iv, True)
        assert mac == str(bytearray.fromhex("18cdd33c0fb25dd7"))

    def test_authenticate_with_default_password(self):
        assert self.tag.authenticate("") is True

    def test_authenticate_with_wrong_password(self):
        self.tag.authenticate("0123456789abcdef") is False

    #pytest.raises(ValueError)
    def test_authenticate_with_short_password(self):
        self.tag.authenticate("abc")

    #pytest.raises(RuntimeError)
    def test_read_with_mac_before_authentication(self):
        self.tag.read_with_mac(0)

    def test_read_with_mac_fails_mac_verification(self):
        assert self.tag.authenticate("") is True
        self.clf.mem[9][0x80] = bytearray(16) # change rc
        assert self.tag.read_with_mac(0) == None

    #pytest.raises(ValueError)
    def test_protect_with_insufficient_password(self):
        self.tag.protect("abc")

    #pytest.raises(ValueError)
    def test_protect_with_negative_protect_from(self):
        self.tag.protect("0123456789abcdef", protect_from=-1)

    def test_protect_with_read_protect_set_true(self):
        assert self.tag.protect("0123456789abcdef", read_protect=True) is False

    def test_protect_when_system_block_is_protected(self):
        self.clf.mem[9][0x88][2] = 0
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert tag.protect("0123456789abcdef") is False

    def test_protect_all_blocks_and_set_card_key(self):
        assert self.tag.protect("0123456789abcdef") is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        assert self.clf.mem[9][0x88][0:3] == "\x00\x40\x00"
        assert self.tag.ndef.is_writeable is False

    def test_protect_all_blocks_and_set_default_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect("") is True
        assert self.clf.mem[9][0x87] == 16 * "\0"
        assert self.clf.mem[9][0x88][0:3] == "\x00\x40\x00"
        assert self.tag.ndef.is_writeable is False

    def test_protect_some_blocks_and_not_set_card_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect(protect_from=4) is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        assert self.clf.mem[9][0x88][0:3] == "\x0F\x40\x00"
        assert self.tag.ndef.is_writeable is True

    def test_protect_system_blocks_and_not_set_card_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect(protect_from=14) is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        assert self.clf.mem[9][0x88][0:3] == "\xFF\xFF\x00"
        assert self.tag.ndef.is_writeable is True

    def test_format_with_default_arguments(self):
        assert self.tag.format() is True
        attribute_data = "100401000d0000000000010000000023".decode("hex")
        assert self.clf.mem[9][0] == attribute_data

    def test_format_with_version_one_dot_zero(self):
        assert self.tag.format(0x10) is True
        attribute_data = "100401000d0000000000010000000023".decode("hex")
        assert self.clf.mem[9][0] == attribute_data

    def test_format_with_wipe_argument_zero(self):
        assert self.tag.format(wipe=0) is True
        attribute_data = "100401000d0000000000010000000023".decode("hex")
        assert self.clf.mem[9][0] == attribute_data
        for i in range(1, 14):
            assert self.clf.mem[9][i] == bytearray(16)

    #pytest.raises(AssertionError)
    def test_format_with_wrong_version_argument_type(self):
        self.tag.format(version="1.0")

    #pytest.raises(AssertionError)
    def test_format_with_wrong_wipe_argument_type(self):
        self.tag.format(wipe="1")

    def test_format_with_invalid_version_number(self):
        assert self.tag.format(version=0xFF) == False

    def test_format_with_tag_first_data_block_readonly(self):
        self.clf.mem[9][0x88][0] = 0xFE
        assert self.tag.format() is False

    def test_format_with_some_blocks_readonly(self):
        self.clf.mem[9][0x88][0] = 0x0F
        assert self.tag.format() is True
        attribute_data = "10040100030000000000010000000019".decode("hex")
        assert self.clf.mem[9][0] == attribute_data

    def test_format_with_tag_not_configurable_for_ndef(self):
        self.clf.mem[9][0x88][3] = 0
        self.clf.mem[9][0x88][2] = 0
        assert self.tag.format() is False

    def test_format_with_tag_not_configured_for_ndef(self):
        self.clf.mem[9][0x88][3] = 0
        assert self.tag.format() is True
        assert self.clf.mem[9][0x88][3] == 1

class FelicaLiteSTagSimulator(FelicaLiteTagSimulator):
    def write_blocks(self, data, block_list):
        if len(block_list) == 2 and block_list[-1][1] == 0x91:
            ck = str(self.mem[9][0x87][7::-1] + self.mem[9][0x87][15:7:-1])
            rc = str(self.mem[9][0x80][7::-1] + self.mem[9][0x80][15:7:-1])
            sk = nfc.tag.pyDes.triple_des(ck, 1, 8 * '\0').encrypt(rc)
            mac = nfc.tag.tt3_sony.FelicaLite.generate_mac
            wcnt = "\0\0\0\0" + chr(block_list[0][1]) + "\0\x91\0"
            maca = mac(wcnt + data[0:16], sk, rc[0:8], flip_key=True)
            if data[16:24] != maca:
                return self.encode(0x08, self.idm, '', '\x02\xB2')
        for service, block, i in block_list:
            try:
                self.mem[service][block][:] = data[i*16:(i+1)*16]
            except IndexError:
                return self.encode(0x08, self.idm, '', "\x01\xA2")
        return self.encode(0x08, self.idm, '')

@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaLiteS:
    sys = "88 B4"
    idm = "01 02 03 04 05 06 07 08"
    pmm = "00 F1 FF FF FF FF FF FF"
    
    def setup(self):
        service_data = [bytearray.fromhex(hexstr) for hexstr in [
            "10 01 01 00  05 00 00 00  00 00 00 00  00 10 00 27",
            "d1 02 0b 53  70 d1 01 07  55 03 61 62  2e 63 6f 6d",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF FF  FF FF FF FF  FF FF FF FF  FF FF FF FF",
        ]] + 113 * [None] + [bytearray.fromhex(hexstr) for hexstr in [
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "FF FF FF 01  07 00 00 00  00 00 00 00  00 00 00 00",
        ]] + 7 * [None] + [bytearray.fromhex(hexstr) for hexstr in [
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
            "00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00",
        ]]
        tag_memory = {0x000B: service_data, 0x0009: service_data}
        #self.clf = FelicaLiteSTagSimulator(
        #    tag_memory, self.sys, self.idm, self.pmm)
        #self.clf.sys.append(bytearray.fromhex("12FC"))
        #self.tag = self.clf.connect(rdwr={'on-connect': None})

    def test_init_with_ic_code_f1(self):
        assert isinstance(self.tag, nfc.tag.tt3_sony.FelicaLiteS)
        assert self.tag._product == "FeliCa Lite-S (RC-S966)"
        assert self.tag._nbr == 4
        assert self.tag._nbw == 1

    def test_init_with_ic_code_f2(self):
        pmm = "00F2FFFF FFFFFFFF"
        clf = Type3TagSimulator(self.clf.mem, self.sys, self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaLiteS)
        assert tag._product == "FeliCa Link (RC-S730) Lite-S Mode"
        assert tag._nbr == 4
        assert tag._nbw == 1

    def test_dump(self):
        lines = self.tag.dump()
        print "\n".join(lines)
        assert len(lines) == 18

    def test_read_ndef_without_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://ab.com"))
        assert self.tag.ndef is not None
        assert self.tag.ndef.capacity == 5 * 16
        assert self.tag.ndef.length == 16
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == False
        assert self.tag.ndef.message == msg

    def test_read_ndef_after_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://ab.com"))
        assert self.tag.authenticate('') is True
        assert self.tag.ndef is not None
        assert self.tag.ndef.capacity == 5 * 16
        assert self.tag.ndef.length == 16
        assert self.tag.ndef.is_readable == True
        assert self.tag.ndef.is_writeable == True
        assert self.tag.ndef.message == msg

    #pytest.raises(AttributeError)
    def test_write_ndef_without_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://cd.org"))
        self.tag.ndef.message = msg
        assert self.clf.mem[9][1][10:16] == "cd.org"

    def test_write_ndef_after_authentication(self):
        msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://cd.org"))
        assert self.clf.mem[9][0][10] == 0 # RWFlag
        assert self.tag.authenticate('') is True
        self.tag.ndef.message = msg
        assert self.clf.mem[9][1][10:16] == "cd.org"
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_authenticate_with_default_password(self):
        assert self.tag.authenticate("") is True

    def test_authenticate_with_wrong_password(self):
        self.tag.authenticate("0123456789abcdef") is False

    #pytest.raises(RuntimeError)
    def test_write_with_mac_before_authentication(self):
        self.tag.write_with_mac(bytearray(16), 0)

    #pytest.raises(nfc.tag.tt3.Type3TagCommandError)
    def test_write_with_mac_fails_mac_verification(self):
        assert self.tag.authenticate("") is True
        self.clf.mem[9][0x80] = bytearray(16) # change rc
        self.tag.write_with_mac(bytearray(16), 0)

    #pytest.raises(ValueError)
    def test_write_with_mac_with_insufficient_data(self):
        self.tag.write_with_mac(bytearray(15), 0)

    #pytest.raises(ValueError)
    def test_write_with_mac_with_block_not_a_number(self):
        self.tag.write_with_mac(bytearray(16), '0')

    #pytest.raises(ValueError)
    def test_protect_with_insufficient_password(self):
        self.tag.protect("abc")

    #pytest.raises(ValueError)
    def test_protect_with_negative_protect_from(self):
        self.tag.protect("0123456789abcdef", protect_from=-1)

    def test_protect_when_key_change_is_not_possible(self):
        self.clf.mem[9][0x88][2] = 0
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert tag.protect("0123456789abcdef") is False

    def test_protect_when_key_change_requires_authentication(self):
        self.clf.mem[9][0x88][2] = 0
        self.clf.mem[9][0x88][5] = 1
        tag = self.clf.connect(rdwr={'on-connect': None})
        assert tag.protect("0123456789abcdef") is False
        assert tag.authenticate("") is True
        assert tag.protect("0123456789abcdef") is True

    def test_protect_all_blocks_with_read_protect_set_true(self):
        assert self.tag.protect("0123456789abcdef", read_protect=True)
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        mc_block = "ffff00010701ff3fff3fff3f00000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_protect_some_blocks_with_read_protect_set_true(self):
        assert self.tag.protect("", protect_from=4, read_protect=True)
        mc_block = "ffff00010701f03ff03ff03f00000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_protect_all_blocks_and_set_card_key(self):
        self.clf.mem[9][0][10] = 1 # RWFlag
        self.clf.mem[9][0][15] += 1 # checksum
        assert self.tag.protect("0123456789abcdef") is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        mc_block = "ffff000107010000ff3fff3f00000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_protect_all_blocks_and_set_default_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect("") is True
        assert self.clf.mem[9][0x87] == 16 * "\0"
        mc_block = "ffff000107010000ff3fff3f00000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_protect_some_blocks_and_not_set_card_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect(protect_from=4) is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        mc_block = "ffff000107010000f03ff03f00000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

    def test_protect_system_blocks_and_not_set_card_key(self):
        self.clf.mem[9][0x87] = bytearray("76543210fedcba98")
        assert self.tag.protect(protect_from=14) is True
        assert self.clf.mem[9][0x87] == "76543210fedcba98"
        assert self.clf.mem[9][0x88][0:3] == "\xFF\xFF\x00"
        mc_block = "ffff0001070100000000000000000000".decode("hex")
        assert self.clf.mem[9][0x88] == mc_block
        assert self.clf.mem[9][0][10] == 0 # RWFlag

@pytest.mark.skip(reason="not yet converted")
class TestType3TagFelicaPlug:
    sys = "00 00"
    idm = "01 02 03 04 05 06 07 08"
    
    def test_init_with_ic_code_e0(self):
        pmm = "00E0FFFF FFFFFFFF"
        clf = Type3TagSimulator(None, self.sys, self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaPlug)
        assert tag._product == "FeliCa Plug (RC-S926)"
        assert tag._nbr == 12
        assert tag._nbw == 12

    def test_init_with_ic_code_e1(self):
        pmm = "00E1FFFF FFFFFFFF"
        clf = Type3TagSimulator(None, self.sys, self.idm, pmm)
        tag = clf.connect(rdwr={'on-connect': None})
        assert isinstance(tag, nfc.tag.tt3_sony.FelicaPlug)
        assert tag._product == "FeliCa Link (RC-S730) Plug Mode"
        assert tag._nbr == 12
        assert tag._nbw == 12
