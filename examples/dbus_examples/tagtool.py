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
log = logging.getLogger()

import os
import sys
import time
import string
import pickle
import gobject
import dbus.mainloop.glib

sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef

BUS_NAME = "org.nfcpy.TagReader"

def make_printable(data):
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += make_printable(data[i:i+16])
    return '\n'.join(s)


class ReaderWriterClient:
    def __init__(self, mainloop, reader):
        self._loop = mainloop
        self._message = None
        self._reader = reader
        self._loopmode = False
        self._binary = False
        self._copying = False
        
        
    @property
    def loopmode(self):
        log.debug("returning loopmode = " + str(self._loopmode))
        return self._loopmode
    
    @loopmode.setter
    def loopmode(self, value):
        log.debug("set loopmode to " + str(value))
        self._loopmode = bool(value)
        
        
    def set_binary(self, value):
        self._binary = value

        
    def save_ndef(self, ndef_msg_string):
        if len(ndef_msg_string):
            self._message = nfc.ndef.Message(str(ndef_msg_string))
        else:
            log.info("Empty message received!")
            
    def show_ndef(self): # , ndef_msg_string
        print format_data(self._message.tostring())
        print "NDEF records:"
        for index, record in enumerate(self._message):
            record.data = make_printable(record.data)
            print "  [%d] type = %s" %(index, record.type)
            print "  [%d] name = %s" %(index, record.name)
            print "  [%d] data = %s" %(index, record.data)
    
    def show_tag(self, tag_str):
        self._tag_info = pickle.loads(tag_str)
        
        tt3_card_map = {
            "\x00\xF0": "FeliCa Lite RC-S965",
            "\x01\xE0": "FeliCa Plug RC-S801/RC-S802",
            "\x01\x20": "FeliCa Card RC-S976F [212/424kbps]",
            "\x03\x01": "FeliCa Card RC-S860 [212kbps, 4KB FEPROM]",
            }
        print "  " + tt3_card_map.get(self._tag_info.get('pmm')[0:2], 
                                      "unknown card type")
        if self._tag_info.get('capacity', 0):
            print "NDEF content"
            print "  version   = %s" % self._tag_info['version']
            print "  writeable = %s" % ("no", "yes")[self._tag_info['writeable']]
            print "  capacity  = %d byte" % self._tag_info['capacity']
            print "  data size = %d byte" % self._tag_info['size']
        print "NDEF container present"
        # show content:
        if self._tag_info['size']:
            if self._message:
                self.show_ndef()
            else:
                print "No message",
                time.sleep(0.5)
                if self._message:
                    print "received yet. Waiting..."
                    self.show_ndef()
                else:
                    print "could be received."
            
        else:
            print "No message available"
        if not self.loopmode:
            self._loop.quit()
    
    def copy_tag(self, ndef_msg_string):
            self._message = nfc.ndef.Message(str(ndef_msg_string))
            log.info("copied {0} byte <= tag".format(len(ndef_msg_string)))
            
            raw_input("Place the destination tag on the reader " 
                      + "and press ENTER.")
            msg_string = self._message.tostring()
            self._reader.WriteNDEF(dbus.ByteArray(msg_string))
            log.info("copied {0} byte => tag".format(len(msg_string)))
            if self.loopmode:
                time.sleep(1)
            else:
                self._loop.quit()
    
    def dump_tag(self, ndef_msg_string):
        data = ndef_msg_string
        if not self._binary:
            data = data.encode("hex")
        print data
        if not self.loopmode:
            self._loop.quit()
            
    def load_tag(self):
        print "Enter Data"
        if not self._binary:
            data = sys.stdin.readlines()
            data = ''.join([l.strip() for l in data])
            data = data.decode("hex")
        else:
            data = sys.stdin.read()
        print "You entered " + data
        self._reader.WriteNDEF(dbus.ByteArray(data))
        log.info("Data written to the tag")
        if not options.loopmode:
            self._loop.quit()
            
    def format_tag(self):
        cont = raw_input("This will delete all data on the tag. " 
                         + "Continue? Y/N ")

        if cont not in "yY":
            return
        # call method on reader object:
        self._format_running = True
        while True:
            success = self._reader.FormatTag()
                                # include this parameters for async. call:
                                # reply_handler=self.format_reply_handler,
                                # error_handler=self.format_error_handler
            if success:
                print "Formatting successful"
            else:
                print "Formatting failed"
            if not self.loopmode:
                print "No loop. exiting"
                break
            else:
                print "go on in 1 sec."
                time.sleep(1)
    
    # This method is needed if formatting method of the reader object is 
    # called asynchronous (non-blocking)   
    def format_reply_handler(self, success):
        if success:
            log.info("Formatting successful")
        else:
            log.info("Formatting failed")
        self._format_running = False
        if not self._loopmode:
            self._loop.quit()
    
    # This method is needed if formatting method of the reader object is 
    # called asynchronous (non-blocking)
    def format_error_handler(self, error):
        log.warning("Error occured: " + str(error))
        self._format_running = False
        self._loop.quit()
                

def main():
    log.debug("starting...")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    object = bus.get_object(BUS_NAME, "/nfcpy/tagreader")
    loop = gobject.MainLoop()
    client = ReaderWriterClient(mainloop=loop, reader=object)
    client.loopmode = options.loopmode
    log.debug("loopmode set to " + str(client.loopmode))
    if options.command == "show":
        # Connect reader's signals to the show methods
        object.connect_to_signal(signal_name="NDEFMessage", 
                                 handler_function=client.save_ndef, 
                                 dbus_interface='org.nfcpy.TagReader',
                                 byte_arrays=True)
        object.connect_to_signal(signal_name="TagInfo", 
                                 handler_function=client.show_tag, 
                                 dbus_interface='org.nfcpy.TagReader',
                                 byte_arrays=True)
        loop.run()
        
    elif options.command == "format":
        # Reader/writer method will be called by client
        client.format_tag()
    elif options.command == "copy":
        object.connect_to_signal(signal_name="NDEFMessage", 
                                 handler_function=client.copy_tag, 
                                 dbus_interface='org.nfcpy.TagReader',
                                 byte_arrays=True)
        loop.run()
    elif options.command == "dump":
        client.set_binary(options.binary)
        object.connect_to_signal(signal_name="NDEFMessage", 
                                 handler_function=client.dump_tag, 
                                 dbus_interface='org.nfcpy.TagReader',
                                 byte_arrays=True)
        loop.run()
    elif options.command == "load":
        client.set_binary(options.binary)
        client.load_tag()
    else:
        log.error("unknown command '{0}'".format(options.command))

if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup

    usage = ["Usage: %prog [options] command\n",
             "Commands:",
             "  show   - pretty print NDEF data",
             "  dump   - print NDEF data to stdout",
             "  load   - load NDEF data from stdin",
             "  copy   - copy NDEF data between tags",
             "  format - format NDEF partition on tag"]

    parser = OptionParser('\n'.join(usage), version="%prog 0.1")
    parser.add_option("-l", default=False,
                      action="store_true", dest="loopmode",
                      help="run command in loop mode")
    parser.add_option("-b", default=False,
                      action="store_true", dest="binary",
                      help="use binary format for dump/load")
    parser.add_option("-q", default=True,
                      action="store_false", dest="verbose",
                      help="be quiet, only print errors")
    parser.add_option("-d", default=False,
                      action="store_true", dest="debug",
                      help="print debug messages")
    parser.add_option("-f", type="string",
                      action="store", dest="logfile",
                      help="write log messages to LOGFILE")

    global options
    options, args = parser.parse_args()
    if len(args) > 0: options.command = args[0]
    else: options.command = "print"

    verbosity = logging.INFO if options.verbose else logging.ERROR
    verbosity = logging.DEBUG if options.debug else verbosity
    logging.basicConfig(level=verbosity, format='%(message)s')

    if options.logfile:
        logfile_format = '%(asctime)s %(levelname)-5s [%(name)s] %(message)s'
        logfile = logging.FileHandler(options.logfile, "w")
        logfile.setFormatter(logging.Formatter(logfile_format))
        logfile.setLevel(logging.DEBUG)
        logging.getLogger('').addHandler(logfile)

    main()

