# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2013-2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

def activate(clf, target):
    import nfc.clf
    try:
        if type(target) is nfc.clf.TTA:
            if target.cfg[0] & 0x1F == 0 and target.cfg[1] & 0x0F == 0x0C:
                return activate_tt1(clf, target)
            if len(target.cfg) == 3:
                if target.cfg[2] & 0x64 == 0x00:
                    return activate_tt2(clf, target)
                if target.cfg[2] & 0x24 == 0x20:
                    return activate_tt4(clf, target)
        elif type(target) is nfc.clf.TTB:
            return activate_tt4(clf, target)
        elif type(target) is nfc.clf.TTF:
            return activate_tt3(clf, target)
    except nfc.clf.DigitalProtocolError:
        return None

def activate_tt1(clf, target):
    import nfc.tag.tt1
    return nfc.tag.tt1.Type1Tag(clf, target)
    
def activate_tt2(clf, target):
    import nfc.tag.tt2
    clf.set_communication_mode('', check_crc='OFF')
    if target.uid[0] == 0x04: # NXP
        import nfc.tag.tt2_nxp
        tag = nfc.tag.tt2_nxp.activate(clf, target)
        if tag is not None: return tag
    return nfc.tag.tt2.Type2Tag(clf, target)
    
def activate_tt3(clf, target):
    import nfc.tag.tt3, nfc.tag.tt3_sony
    tag = nfc.tag.tt3_sony.activate(clf, target)
    return tag if tag else nfc.tag.tt3.Type3Tag(clf, target)
    
def activate_tt4(clf, target):
    import nfc.tag.tt4
    return nfc.tag.tt4.Type4Tag(clf, target)
    
def emulate(clf, target):
    import nfc.clf
    if type(target) is nfc.clf.TTA:
        log.debug("can't emulate TTA target'")
    elif type(target) is nfc.clf.TTB:
        log.debug("can't emulate TTB target'")
    elif type(target) is nfc.clf.TTF:
        import nfc.tag.tt3
        return nfc.tag.tt3.Type3TagEmulation(clf, target)

class Tag(object):
    """The base class for all NFC Tags/Cards. The methods and attributes
    defined here are commonly available but some may, depending on the
    tag product, also return a :const:`None` value is support is not
    available.

    Direct subclasses are the NFC Forum tag types:
    :class:`~nfc.tag.tt1.Type1Tag`, :class:`~nfc.tag.tt2.Type2Tag`,
    :class:`~nfc.tag.tt3.Type3Tag`, :class:`~nfc.tag.tt4.Type4Tag`.
    Some of them are further specialized in vendor/product specific
    classes.

    """
    class NDEF(object):
        """The NDEF object type that may be read from :attr:`Tag.ndef`.

        This class presents the NDEF management information and the
        actual NDEF message by a couple of attributes. It is normally
        accessed from a :class:`Tag` instance through the
        :attr:`~Tag.ndef` attribute for reading or writing an NDEF
        message. ::

            if tag.ndef is not None:
                print(tag.ndef.message.pretty())
                if tag.ndef.writeable:
                    text_record = nfc.ndef.TextRecord("Hello World")
                    tag.ndef.message = nfc.ndef.Message(text_record)

        """
        def __init__(self, tag):
            self._tag = tag
            self._capacity = 0
            self._readable = False
            self._writeable = False
            self._data = self._read_ndef_data()
            if self._data is None:
                raise RuntimeError("failed to read ndef data")

        @property
        def length(self):
            """Length of the current NDEF message in bytes."""
            return len(self._data)
        
        @property
        def capacity(self):
            """Maximum number of bytes for an NDEF message."""
            return self._capacity

        @property
        def readable(self):
            """True if data can be read from the NDEF tag."""
            return self._readable

        @property
        def writeable(self):
            """True if data can be written to the NDEF tag."""
            return self._writeable

        @property
        def has_changed(self):
            """The boolean attribute :attr:`has_changed` allows to determine
            whether the NDEF message on the tag is different from the
            message that was read or written at an earlier time in the
            session. This may for example be the case if the tag is
            build to dynamically present different content depending
            on some state.

            Note that reading this attribute involves a complete
            update of the :class:`~Tag.NDEF` instance accessed through
            :attr:`Tag.ndef`. As a result, it is possible that the
            :attr:`Tag.ndef` attribute may have become :const:`None`
            if there was, for example, now invalid data on the tag. A
            robust implementation should thus verify the value of the
            :attr:`Tag.ndef` attribute. ::

                if tag.ndef.has_changed:
                    if tag.ndef is not None:
                        print(tag.ndef.message.pretty())

            The :attr:`has_changed` attribute can also be used to
            verify that an NDEF message that was written to the tag is
            identical to the NDEF message stored on the tag. ::

                tag.ndef.message = my_new_ndef_message
                if tag.ndef.has_changed:
                    print("the tag data differs from what was written")

            """
            old_data, self._data = self._data, self._read_ndef_data()
            if self._data is None: self._tag._ndef = None
            return self._data != old_data

        @property
        def message(self):
            """Read or write the :class:`nfc.ndef.Message` on the tag.
            
            If valid NDEF data was read from the tag, then
            :attr:`message` holds an :class:`nfc.ndef.Message` object
            representing that data. Otherwise it holds an empty
            message, i.e. an NDEF message that is composed of a single
            NDEF record with type zero, no name (identifier) and no
            data. Note that the :attr:`length` attribute always
            returns the true NDEF data length. ::
            
                empty_message = nfc.ndef.Message(nfc.ndef.Record())
            
                if tag.ndef is not None:
                    print(tag.ndef.message.pretty())
                    if tag.ndef.message == empty_message:
                        if tag.ndef.length == 0:
                            print("there's no data stored on the tag")
                        elif tag.ndef.length == 3:
                            print("looks like an empty message found")
                        else:
                            print("got a message that failed to parse")
            
            """
            import nfc.ndef
            try:
                return nfc.ndef.Message(str(self._data))
            except nfc.ndef.parser_error:
                return nfc.ndef.Message(nfc.ndef.Record())

        @message.setter
        def message(self, msg):
            if not self.writeable:
                raise nfc.tag.AccessError
            data = bytearray(str(msg))
            if len(data) > self.capacity:
                raise nfc.tag.CapacityError
            self._write_ndef_data(data)
            self._data = data

    def __init__(self, clf):
        self._clf = clf
        self._ndef = None
        self._authenticated = False

    def __str__(self):
        try: s = self.type + ' ' + repr(self._product)
        except AttributeError: s = self.type
        return s + ' ID=' + self.identifier.encode("hex").upper()

    @property
    def clf(self):
        return self._clf
        
    @property
    def type(self):
        return self.TYPE

    @property
    def product(self):
        return self._product if hasattr(self, "_product") else self.type

    @property
    def identifier(self):
        """The unique tag identifier."""
        return str(self.uid if hasattr(self, "uid") else self.idm)

    @property
    def ndef(self):
        """An :class:`NDEF` object if found, otherwise :const:`None`."""
        if self._ndef is None:
            self._ndef = self._read_ndef()
        return self._ndef

    @property
    def is_present(self):
        """True if the tag is within communication range."""
        return self._is_present()

    @property
    def is_authenticated(self):
        """True if the tag was successfully authenticated."""
        return self._authenticated
        
    def dump(self):
        """The dump() method returns a list of strings describing the memory
        structure of the tag, suitable for printing with join(). The
        list format makes custom indentation a bit easier. ::

            print("\\n".join(["\\t" + line for line in tag.dump]))
        
        """
        return []

    def format(self, version=None, wipe=None):
        """Format the tag to make it NDEF compatible or erase content.

        The :meth:`format` method is highly dependent on the tag type,
        product and present status, for example a tag that has been
        made read-only with lock bits can no longer be formatted or
        erased.

        :meth:`format` creates the management information defined by
        the NFC Forum to describes the NDEF data area on the tag, this
        is also called NDEF mapping. The mapping may differ between
        versions of the tag specifications, the mapping to apply can
        be specified with the *version* argument as an 8-bit integer
        composed of a major version number in the most significant 4
        bit and the minor version number in the least significant 4
        bit. If *version* is not specified then the highest possible
        mapping version is used.

        If formatting of the tag is possible, the default behavior of
        :meth:`format` is to update only the management information
        required to make the tag appear as NDEF compatible and empty,
        previously existing data could still be read. If existing data
        shall be overwritten, the *wipe* argument can be set to an
        8-bit integer that will be written to all available bytes.

        The :meth:`format` method returns :const:`True` if formatting
        was successful, :const:`False` if it failed for some reason,
        or :const:`None` if the present tag can not be formatted
        either because the tag does not support formatting or it is
        not implemented in nfcpy.

        """
        log.error("this tag can not be formatted with nfcpy")
        return None

    def authenticate(self, password=None):
        """Authenticate the tag using *password*. If the tag supports
        authentication the method returns True for success and
        otherwise False. If the tag does not support authentication,
        or it is not implemented, the return value is None.

        """
        log.error("this tag can not be authenticated with nfcpy")
        return None

    def protect(self, password=None, read_protect=False, protect_from=0):
        """Protect a tag against future write or read access.


        """
        log.error("this tag can not be protected with nfcpy")
        return None

class TagCommandError(Exception):
    """The base class for exceptions that are raised when a tag command
    has not returned the expected result. This may be for some generic
    reason such as when the tag moved out of communication range or
    did not recognize the command (most tags do not answer to unknown
    commands), this would most likely result in a timeout error
    indicated by :attr:`TagCommandError.errno` equal zero.

    All error numbers are betwen 0 and 0xffff, inclusively. Error
    numbers from 0 to 0x00ff indicate general errors, numbers from
    0x0100 to 0xffff indicate logical errors received in a tag
    response.

    """
    error_map = {
        0x0000: "timeout error, the tag has not answered",
        0x0001: "frame error, invalid response length",
        0x0002: "frame error, invalid response code",
        0x0004: "frame error, crc validation failed",
        0x0005: "frame error, answer from wrong tag",
        0x0010: "data error, insufficient data received",
    }
    
    def __init__(self, errno):
        default = "tag command error {0:04X}".format(errno)
        message = TagCommandError.error_map.get(errno, default)
        super(TagCommandError, self).__init__(message)
        self._errno = errno

    @property
    def errno(self):
        """The error number."""
        return self._errno

    def __int__(self):
        return self._errno

class Error: pass
class AccessError(Error): pass
class CapacityError(Error): pass
