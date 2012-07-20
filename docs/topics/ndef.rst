========================
NFC Data Exchange Format
========================

NDEF (NFC Data Exchange Format) is a binary message format to exchange
application-defined payloads between NFC Forum Devices or to store
payloads on an NFC Forum Tag. A payload is described by a type, a
length and an optional identifer encoded in an NDEF record
structure. An NDEF message is a sequence of NDEF records with a begin
marker in the first and an end marker in the last record.

::

  +------------+------------+--------+------------+
  |                   NDEF Message                |
  +------------+------------+--------+------------+
  |  Record 1  |  Record 2  |  ....  |  Record n  |
  | MB=1, ME=0 |            |        | MB=0, ME=1 |
  +------------+------------+--------+------------+

NDEF decoding and encoding is provided by the :mod:`nfc.ndef` module.

>>> import nfc.ndef

.. class:: Record([record_type , record_name , data])

   :param record_type: This is the record type.  It is assigned
                       to the :attr:`type` attribute and the same
                       limitations apply.
   :type record_type: str, bytearray
   :param record_name: This is the record identifier. It is assigned
                       to the :attr:`name` attribute and the same
                       conversion rules are applied.
   :type record_name: str, bytearray
   :param data: This is the record payload if any of `record_type` or
                `record_name` are present; if only `data` is present
                it must be the complete NDEF record data sequence.
   :type data: str, bytearray

   .. attribute:: type

      The record type. A string that matches either the empty string
      '', or 'unknown', or 'unchanged', or starts with 'urn:nfc:wkt:',
      or 'urn:nfc:ext:', or matches the mime-type format, or matches
      the absolute-URI format.

   .. attribute:: name

      The record identifier as an octet string. Any type that can be
      coverted into a sequence of characters in range(0,256) can be
      assigned.

   .. attribute:: data

      The record payload as an octet string. Any type that can be
      coverted into a sequence of characters in range(0,256) can be
      assigned.

.. class:: Message(record)
.. class:: Message(*args)

   The :class:`Message` class 
   :param data: The `args` parameter 
   :type data: str, bytearray, :class:`io.Bytes`,
               :class:`nfc.ndef.Record`, :class:`list`

   .. attribute:: type

      The message type. If the :obj:`message` has at least one record,
      this is the :attr:`Record.type` attribute of the first record,
      otherwise it is :const:`None`. This attribute can only be read.

   .. attribute:: name

      The message name. If the :obj:`message` has at least one record,
      this is the :attr:`Record.name` attribute of the first record,
      otherwise it is :const:`None`. This attribute can only be read.



Parsing NDEF
============

An :class:`nfc.ndef.Message` class can be initialized with an NDEF
message octet string to parse that data into the sequence of NDEF
records framed by the begin and end marker of the first and last
record. Each NDEF record is represented by an :class:`nfc.ndef.Record`
object accessible through indexing or iteration over the
:class:`nfc.ndef.Message` object.

>>> import nfc.ndef
>>> message = nfc.ndef.Message(b'\xD1\x01\x0ET\x02enHello World')
>>> message
nfc.ndef.Message([nfc.ndef.Record('urn:nfc:wkt:T', '', '\x02enHello World')])
>>> len(message)
1
>>> message[0]
nfc.ndef.Record('urn:nfc:wkt:T', '', '\x02enHello World')
>>> for record in message:
>>>     record.type, record.name, record.data
>>> 
('urn:nfc:wkt:T', '', '\x02enHello World')

An NDEF record carries three parameters for describing its payload:
the payload length, the payload type, and an optional payload
identifier. The :attr:`nfc.ndef.Record.data` attribute provides access
to the payload and the payload length is obtained by :func:`len`. The
:attr:`nfc.ndef.Record.name` attribute holds the payload identifier
and is an empty string if no identifer was present in the NDEF
date. The :attr:`nfc.ndef.Record.type` identifies the type of the
payload as a combination of the NDEF Type Name Format (TNF) field and
the type name itself.

*Empty (TNF 0)*

  An *Empty* record type (expressed as a zero-length string) indicates
  that there is no type or payload associated with this
  record. Encoding a record of this type will exclude the name
  (*payload identifier*) and data (*payload*) contents. This type can
  be used whenever an empty record is needed; for example, to
  terminate an NDEF message in cases where there is no payload defined
  by the user application.

*NFC Forum Well Known Type (TNF 1)*

  An *NFC Forum Well Known Type* is a URN as defined by :rfc:`2141`,
  with the namespace identifier (NID) "nfc". The Namespace Specific
  String (NSS) of the NFC Well Known Type URN is prefixed with
  "wkt:". When encoded in an NDEF message, the Well Known Type is
  written as a relative-URI construct (cf. :rfc:`3986`), omitting the NID
  and the “wkt:” -prefix. For example, the type “urn:nfc:wkt:T” will
  be encoded as TNF 1, TYPE "T".

*Media-type as defined in RFC 2046 (TNF 2)*

  A *media-type* follows the media-type BNF construct defined by
  :rfc:`2046`. Records that carry a payload with an existing,
  registered media type should use this record type. Note that the
  record type indicates the type of the payload; it does not refer to
  a MIME message that contains an entity of the given type. For
  example, the media type 'image/jpeg' indicates that the payload is
  an image in JPEG format using JFIF encoding as defined by
  :rfc:`2046`.

*Absolute URI as defined in RFC 3986 (TNF 3)*

  An *absolute-URI* follows the absolute-URI BNF construct defined by
  :rfc:`3986`. This type can be used for message types that are
  defined by URIs. For example, records that carry a payload with an
  XML-based message type may use the XML namespace identifier of the
  root element as the record type, like a SOAP/1.1 message may be
  represented by the URI 'http://schemas.xmlsoap.org/soap/envelope/'.

*NFC Forum External Type (TNF 4)*

  An *NFC Forum External Type* is a URN as defined by :rfc:`2141`,
  with the namespace identifier (NID) "nfc". The Namespace Specific
  String (NSS) of the NFC Well Known Type URN is prefixed with
  "ext:". When encoded in an NDEF message, the External Type is
  written as a relative-URI construct (cf. :rfc:`3986`), omitting the
  NID and the “ext:” -prefix. For example, the type
  “urn:nfc:ext:nfcpy.org:T” will be encoded as TNF 4, TYPE
  "nfcpy.org:T".

*Unknown (TNF 5)*

  An *Unknown* record type (expressed by the string "unknown")
  indicates that the type of the payload is unknown, similar to the
  “application/octet-stream” media type.

*Unchanged (TNF 6)*

  An *Unchanged* record type (expressed by the string "unchanged") is
  used in middle record chunks and the terminating record chunk used
  in chunked payloads. This type is not allowed in any other record.

>>> import nfc.ndef
>>> message = nfc.ndef.Message('\xD0\x00\x00')
>>> nfc.ndef.Message('\xD0\x00\x00')[0].type
''
>>> nfc.ndef.Message('\xD1\x01\x00T')[0].type
'urn:nfc:wkt:T'
>>> nfc.ndef.Message('\xD2\x0A\x00text/plain')[0].type
'text/plain'
>>> nfc.ndef.Message('\xD3\x16\x00http://example.org/dtd')[0].type
'http://example.org/dtd'
>>> nfc.ndef.Message('\xD4\x10\x00example.org:Text')[0].type
'urn:nfc:ext:example.org:Text'
>>> nfc.ndef.Message('\xD5\x00\x00')[0].type
'unknown'
>>> nfc.ndef.Message('\xD6\x00\x00')[0].type
'unchanged'


The type and name of the first record, by convention, provide the
processing context and identification not only for the first record
but for the whole NDEF message. The :attr:`nfc.ndef.Message.type` and
:attr:`nfc.ndef.Message.name` attributes map to the type and anme
attributes of the first record in the message.

>>> message = nfc.ndef.Message(b'\xD1\x01\x0ET\x02enHello World')
>>> message.type, message.name
('urn:nfc:wkt:T', '')

If invalid or insufficient data is provided to to the NDEF message parser, an :class:`nfc.ndef.FormatError` or :class:`nfc.ndef.LengthError` is raised.

>>> try: nfc.ndef.Message('\xD0\x01\x00')
... except nfc.ndef.LengthError as e: print e
... 
insufficient data to parse
>>> try: nfc.ndef.Message('\xD0\x01\x00T')
... except nfc.ndef.FormatError as e: print e
... 
ndef type name format 0 doesn't allow a type string

Creating NDEF
=============

Creating NDEF starts with creating records, which is done with the
:class:`nfc.ndef.Record` class. The three optional keyword arguments
`record_type`, `record_name` and `data` take the three three parts of
an NDEF record - type, identifier and payload.

>>> nfc.ndef.Record("urn:nfc:wkt:T", "id", "\x02enHello World")
nfc.ndef.Record('urn:nfc:wkt:T', 'id', '\x02enHello World')


Special Records
===============

Text Record
-----------

Uri Record
----------

>>> import nfc.ndef
>>> record = nfc.ndef.UriRecord("http://nfcpy.org")
>>> record.type, record.name, record.data
('urn:nfc:wkt:U', '', '\x03nfcpy.org')

Smart Poster Record
-------------------

