#!/usr/bin/python
# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2010-2011 Alexander Knaub <sanyok.og@googlemail.com>
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


# Usage Notes start -----------------------------------------------------------
# This file implements the basic NFC Type3Tag-operations and offers an 
#     interface via D-Bus. 
# This interface includes methods to write NDEF-Data to a tag (WriteNDEF) and 
#     format a tag (FormatTag). 
#     Also it contains D-Bus-Signals to inform the listeners about newly read
#     tag (TagInfo) and the message contained in this tag (NDEFMessage) in form 
#     of byte arrays.
#
# Before starting to use this module, you have to configure your system D-Bus:
#  1) Create a file with the name like "org.nfcpy.Tagreader.conf" with 
#     following content:
#
#    <?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->
#    <!DOCTYPE busconfig PUBLIC
#    "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
#    "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
#    <busconfig>
#        <servicedir>/usr/share/dbus-1/system-services/</servicedir>
#        <policy context="default">
#            <!-- Root can connect to system bus -->
#            <allow user="root"/>
#    
#            <!-- Holes are punched here for
#             name ownership and sending method calls -->
#            <allow own="org.nfcpy.TagReader"/>
#            <allow send_type="method_call"/>
#        </policy>
#    </busconfig>
#
#  2) Place this file in the folder "/etc/dbus-1/system.d/". Note that you 
#     will need root rights for this. You can use the following command: 
#    sudo cp org.nfcpy.Tagreader.conf /etc/dbus-1/system.d/org.nfcpy.Tagreader.conf
#
#  3) Reboot your computer to start D-Bus with new configuration.
#
# Usage Notes end--------------------------------------------------------------
import logging
log = logging.getLogger("nfcpy.reader")
import time
import gobject
import pickle
from threading import Thread
import dbus.service
import dbus.mainloop.glib
#nfc package is 2 levels higher in the file system:
import sys, os
_above_folder = os.path.split(sys.path[0])[0]
sys.path.insert(1, os.path.split(_above_folder)[0])
import nfc.dev
from nfc.ndef.Message import Message
 
BUS_NAME = "org.nfcpy.TagReader"

def tt3_format(tag):
    log.debug("Formatting...")
    def determine_block_count(tag):
        block = 0
        try:
            while True:
                data = tag.read([block], 9)
                block += 1
        except Exception:
            if tag.pmm[0:2] == "\x00\xF0":
                block -= 1 # last block on FeliCa Lite is unusable
            return block

    def determine_block_read_count(tag, block_count):
        try:
            for i in range(block_count):
                tag.read(range(i+1))
        except Exception: return i

    def determine_block_write_count(tag, block_count):
        try:
            for i in range(block_count):
                data = ((i+1)*16) * "\x00"
                tag.write(data, range(i+1))
        except Exception: return i

    block_count = determine_block_count(tag)
    log.debug("tag has %d user data blocks" % block_count)

    nbr = determine_block_read_count(tag, block_count)
    log.debug("%d block(s) can be read at once" % nbr)

    nbw = determine_block_write_count(tag, block_count)
    log.debug("%d block(s) can be written at once" % nbw)

    nmaxb_msb = (block_count - 1) / 256
    nmaxb_lsb = (block_count - 1) % 256
    attr = [0x10, nbr, nbw, nmaxb_msb, nmaxb_lsb, 
            0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0]
    csum = sum(attr[0:14])
    attr[14] = csum / 256
    attr[15] = csum % 256

    log.debug("writing attribute data block:")
    print " ".join(["%02x" % x for x in attr])

    attr = ''.join([chr(b) for b in attr])
    tag.write(attr, [0])
    log.debug("Successful")

class TagReader(dbus.service.Object):
    def __init__(self, bus, mainloop, path="/nfcpy/tagreader"):
        log.debug("READER: Create Reader/Writer object...")
        self.running = False
        dbus.service.Object.__init__(self, conn=bus, object_path=path)
        if bus.name_has_owner(BUS_NAME):
            # Another instance exists. Inform user and exit.
            owner = bus.get_name_owner(BUS_NAME)
            log.warning("READER: Another instance is running. You can access " 
                     + "or exit it via DBus by the name 'org.nfcpy.TagReader'" 
                     + "or by the unique name " + owner + ".")
            return
        log.debug("READER: Request Service name")
        req_responce = bus.request_name(BUS_NAME,
                                        dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
        # debugging:
        if req_responce == dbus.bus.REQUEST_NAME_REPLY_EXISTS:
            log.debug("READER: reply: exists. %s" % req_responce)
        elif req_responce == dbus.bus.REQUEST_NAME_REPLY_PRIMARY_OWNER:
            log.debug("READER: reply: primary owner. %s" % req_responce)

        self._mainloop = mainloop
        self._message = None
        self._last_tag = dict()
        self._exit_reading = False
        self._pause_reading = False
        self._last_idm = None
        self._clf = None
        read_thread = Thread(target=self.read_loop, name="ReadThread")
        read_thread.start()
        self.running = True
        
    @property
    def running(self):
        return self._running
    
    @running.setter
    def running(self, value):
        self._running = value
        
    @dbus.service.signal(dbus_interface='org.nfcpy.TagReader',
                         signature='ay') # byte-array, subclass of str
    def NDEFMessage(self, new_message_string):
        log.debug("READER: Emit message!")
        if new_message_string:
            return new_message_string
        else:
            return ""
    
    @dbus.service.signal(dbus_interface='org.nfcpy.TagReader',
                         signature='ay') # byte-array, subclass of str
    def TagInfo(self, tag_str):
        log.debug("READER: Emit Tag Info!")
#        return new_message_string

    @dbus.service.method('org.nfcpy.TagReader', in_signature="", 
                         out_signature="")
    def Exit(self):
        log.info("READER: exiting...")
        self._exit_reading = True
        log.debug("READER: release connection to" + str(self.connection))
        self.connection.release_name(BUS_NAME)
        log.debug("READER: Stop the mainloop")
        self._mainloop.quit()
        log.debug("READER: End program")
        
    @dbus.service.method('org.nfcpy.TagReader', in_signature="ay", 
                         out_signature="", byte_arrays=True)
    def WriteNDEF(self, message_string):
        log.info("WRITER: Writting...")
        self._pause_reading = True
        self._message = Message(str(message_string))
        log.info("WRITER: Write message with type " + self._message.type)
        if not self._clf:
            try:
                self._clf = nfc.ContactlessFrontend(probe=nfc.dev.__all__)
            except LookupError:
                log.warning("WRITER: Reader/Writer not found. Exiting")
                self.Exit()
        tag = None
        while not tag:
            tag = self._clf.poll(general_bytes = None)
        
        if tag: 
            log.debug("WRITER: found tag with IDm " + tag.idm)
            tag.ndef.message = self._message.tostring()
            log.debug("WRITER: Writing successfully finished.")
        else:
            log.info("WRITER: No tag found...")
        self._pause_reading = False
        return
        
    @dbus.service.method('org.nfcpy.TagReader', in_signature="", 
                         out_signature="b")
    def FormatTag(self):
        self._pause_reading = True
        if not self._clf:
            try:
                self._clf = nfc.ContactlessFrontend(probe=nfc.dev.__all__)
            except LookupError:
                log.warning("WRITER: Reader/Writer not found. Exiting")
                self.Exit()
        
        tag = None
        while not tag:
            try:
                tag = self._clf.poll(general_bytes = None)
            except KeyboardInterrupt:
                log.warning("WRITER: Aborted by user. Exit formatting...")
                return False
        log.info("Tag found: " + str(tag))
        if tag:
            log.info(str(tag))
            if isinstance(tag, nfc.Type3Tag):
                tt3_format(tag)
                success = True
            else:
                print "unable to format {0}".format(str(tag))
                self._pause_reading = False
                success = False
        else:
            print "No tag"
        self._pause_reading = False
        return success

    def read_loop(self):
        log.debug("READER: start new reading loop...")
        if not self._clf:
            try:
                self._clf = nfc.ContactlessFrontend(probe=nfc.dev.__all__)
                log.debug("READER: CLF found: " + str(self._clf))
            except LookupError:
                log.warning("READER: Reader device not found. Exiting")
                self.Exit()
                return
        try:
            log.debug("READER: Now start reading")
            while not self._exit_reading:
                if not self._pause_reading:
                    tag = self._clf.poll(general_bytes = None)
                else:
                    tag = None
                if not tag:
                    time.sleep(0.5)
                    continue
                if isinstance(tag, nfc.Type3Tag):
                    log.debug("READER: New tag found: " + str(tag))
                    last_tag = {'idm': tag.idm,
                                'pmm': tag.pmm}
                    if tag.ndef is not None:
                        log.debug("READER: NDEF is present")
                        self._last_idm = tag.idm
                        last_tag['version'] = tag.ndef.version
                        last_tag['writeable'] = tag.ndef.writeable
                        last_tag['capacity'] = tag.ndef.capacity
                        last_tag['size'] = len(tag.ndef.message)

                        self._message = Message(tag.ndef.message)
                        log.debug("READER: NDEF Message detected: ")
                        log.debug("READER:     type=%s" 
                                  % self._message.type)
                        if last_tag['size']:
                            log.debug("READER: size: %d" % last_tag['size'])
                            self.NDEFMessage(tag.ndef.message) # emit
                        self.TagInfo(pickle.dumps(last_tag))
                
                while tag.is_present:
                    time.sleep(1)
                log.debug("READER: Tag removed")

        except IOError:
            log.warning("READER: IO Error occured. restarting...")
            read_thread = Thread(target=self.read_loop, name="ReadThread")
            read_thread.start()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    logging.getLogger("nfc").setLevel(logging.INFO)
    log.setLevel(logging.DEBUG)
    
    # enable threads besides the mainloop
    gobject.threads_init()
    dbus.mainloop.glib.threads_init()
    log.debug("Threading initialised")
    # initialise TagReader:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus() #SystemBus()
    loop = gobject.MainLoop()
    reader = TagReader(bus, loop)
    if reader.running:
        log.debug("Reader object created")
        try:
            log.debug("Starting...")
            loop.run()
        except KeyboardInterrupt:
            log.info("READER: Aborted by user!")
            reader.Exit()
    else:
        log.debug("READER: Initialisation failed. Exiting...")
        
    
