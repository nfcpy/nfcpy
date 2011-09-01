#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011 Alexander Knaub <sanyok.og@googlemail.com>
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
log = logging.getLogger('debugger')

import sys
from datetime import datetime, timedelta

pn53x_cmd = {
    0x00: "Diagnose",
    0x02: "GetFirmwareVersion",
    0x04: "GetGeneralStatus",
    0x06: "ReadRegister",
    0x08: "WriteRegister",
    0x0C: "ReadGPIO",
    0x0E: "WriteGPIO",
    0x10: "SetSerialBaudrate",
    0x12: "SetParameters",
    0x16: "PowerDown",
    0x32: "RFConfiguration",
    0x58: "RFRegulationTest",
    0x18: "ResetMode",
    0x56: "InJumpForDEP",
    0x46: "InJumpForPSL",
    0x4A: "InListPassiveTarget",
    0x50: "InATR",
    0x4E: "InPSL",
    0x40: "InDataExchange",
    0x42: "InCommunicateThru",
    0x44: "InDeselect",
    0x52: "InRelease",
    0x54: "InSelect",
    0x8C: "TgInitAsTarget",
    0x92: "TgSetGeneralBytes",
    0x86: "TgGetData",
    0x8E: "TgSetData",
    0x94: "TgSetMetaData",
    0x88: "TgGetInitiatorCommand",
    0x90: "TgResponseToInitiator",
    0x8A: "TgGetTargetStatus",
    }

pn53x_err = {
    0x01: "time out, the target has not answered",
    0x02: "checksum error during rf communication",
    0x03: "parity error during rf communication",
    0x04: "erroneous bit count in anticollision",
    0x05: "framing error during mifare operation",
    0x06: "abnormal bit collision in 106 kbps anticollision",
    0x07: "insufficient communication buffer size",
    0x09: "rf buffer overflow detected by ciu",
    0x0a: "rf field not activated in time by active mode peer",
    0x0b: "protocol error during rf communication",
    0x0d: "overheated - antenna drivers deactivated",
    0x0e: "internal buffer overflow",
    0x10: "invalid command parameter",
    0x12: "unsupported command from initiator",
    0x13: "format error during rf communication",
    0x14: "mifare authentication error",
    0x23: "wrong uid check byte (14443-3)",
    0x25: "command invalid in current dep state",
    0x26: "operation not allowed in this configuration",
    0x29: "released by initiator while operating as target",
    0x2f: "deselected by initiator while operating as target",
    0x31: "initiator rf-off state detected in passive mode",
    0x7F: "pn53x application level error",
    }

def make_printable(data):
    import string
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02X" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += make_printable(data[i:i+16])
    return '\n'.join(s)

def decode_frame(frame, skip_data, prefix, extract_time):
    output = ''
    frame_type = ''
    # decode time
    if prefix and extract_time:
        datestr = prefix[:23]
        time = datetime.strptime(datestr, '%Y-%m-%d %H:%M:%S,%f')
    else: time = None 
    # decide frame type by looking on length field 
    if frame[3:5] == '\x00\xFF':
        frame_type = 'ACK'
    elif frame[3:5] == '\xFF\x00':
        frame_type = 'NAK'
    elif frame[3:5] == '\xFF\xFF': # extended frame
        frame_type = 'EXT'
        length = ord(frame[5])*256  + ord(frame[6])
        lcs = ord(frame[7])
        tfi = ord(frame[8])
        cmd = ord(frame[9])
        dcs = ord(frame[length+8])
        data = frame[9:length+8]
    else: # normal frame 
        frame_type = 'FRM'
        length = ord(frame[3])
        lcs = ord(frame[4])
        tfi = ord(frame[5])
        cmd = ord(frame[6])
        dcs = ord(frame[length+5])
        data = frame[6:length+5]
    
    if (frame_type in ('EXT', 'FRM')) and not (tfi in (0xd4, 0xd5)):
        frame_type = 'ERR'
        
    output += frame_type
    
    if frame_type in ('ACK', 'NAK'):
        return (output, time)
    if frame_type == 'ERR':
        output += " CODE=%0X (%s)" % (tfi, pn53x_err[tfi])
        return (output, time)

    output += " LEN=%03d," % length
    output += " LCS=%03d," % lcs
#   output += " TFI=0x%02X," % tfi
    output += " DCS=%03d," % dcs
    if tfi == 0xD4: # Command
        output += " CMD=0x%02X (%s)" % (cmd, pn53x_cmd[cmd])
        if not skip_data: output += "\n" + format_data(data)
    else: # Response
        output += " RSP=0x%02X (%s)" % (cmd, pn53x_cmd[cmd-1])
        if not skip_data: output += "\n" + format_data(data)
        output += "\n"
    return (output, time)

def main(file, print_acks, skip_data, print_time=True):
    last_time = None
    first_line = True
    while True:
        line = file.readline()
        if not len(line): break
        
        if '>>>' in line: 
            output = "APP > R/W: "
            (prefix, line) = (s for s in line.split('>>> ', 1))
        elif '<<<' in line: 
            output = "R/W > APP: "
            (prefix, line) = (s for s in line.split('<<< ', 1))
        else: 
            continue
        
        if (not prefix) and print_time and first_line:
            log.warning("No timestamps in the input file! \n" 
                   + "Excluding timestamps might produce nicer output " 
                   + "(option '-t')")
            first_line = False
        
        try:
            frame = line[:-1].decode('hex') # skip NL char
        except TypeError as e:
            output = ""
            log.debug("{0}\nWrong line: {1}".format(e.message, line)) 
            continue
        try:
            (decoded, time) = decode_frame(frame, skip_data, 
                                           prefix, print_time)
        except ValueError as e:
            log.error("Time parsing failed! " 
                   + "Expected line format: 'yyyy-mm-dd hh:mm:ss,sss'+message\n" 
                   + "Try without timestamp in the output (option '-t')")
            log.error(e.message)
            break
        if print_acks or (not decoded.endswith("ACKF")):
            if print_time:
                td = ((time - last_time) if last_time is not None 
                      else timedelta())
                output = "+{0:>04}ms: ".format(td.microseconds/1000) + output
                last_time = time
            log.info(output + decoded)

if __name__ == '__main__':
    from optparse import OptionParser
    opt_parser = OptionParser()
    opt_parser.add_option("-f", type="string",
                          action="store", dest="file",
                          help="Analyze specified FILE")
    opt_parser.add_option("-a", default=False,
                          action="store_true", dest="acks",
                          help="Show also acknowledgments")
    opt_parser.add_option("--nodata", default=False,
                          action="store_true", dest="nodata",
                          help="Skip payload print")
    opt_parser.add_option("-t", default=False,
                          action="store_true", dest="time",
                          help="Include time differences in output")
    opt_parser.add_option("-d", default=False,
                          action="store_true", dest="debug",
                          help="Include debug messages in output")
    opt_parser.add_option("--out-file", type="string",
                          action="store", dest="logfile",
                          help="write formatted messages to LOGFILE")   
    
    options, args = opt_parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(message)s')
    if options.debug:
        log.setLevel(logging.DEBUG)
    if options.logfile:
        file_handler = logging.FileHandler(options.logfile, 'w')
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        log.addHandler(file_handler)
    
    if options.file:
        with open(options.file, 'r') as f:
            main(f, options.acks, options.nodata, options.time)
    else:
        main(sys.stdin, options.acks, options.nodata, options.time)
