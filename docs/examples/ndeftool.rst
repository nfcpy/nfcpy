===========
ndeftool.py
===========

.. warning::

   The ndeftool example has become a separate `project
   <https://github.com/nfcpy/ndeftool>`_ with its own `documentation
   <https://ndeftool.readthedocs.io>`_. The example code documented
   here will be removed in a future *nfcpy* release.

The **ndeftool** intends to be a swiss army knife for working with
NDEF data. ::

  $ ndeftool.py [-h] [-v] [-d] {print,make,pack,split,cat} ...

.. contents::
   :local:

Options
=======

.. option:: -v

   Print informational messages.

.. option:: -d

   Print debug information.

Commands
========

print
-----

The **print** command decodes and prints the content of an NDEF
message. The message data may be in raw binary or hexadecimal string
format and is read from *message-file* or standard input if
*message-file* is not provided.::

  $ ndeftool.py print [-h|--help] [message]

make
----

The **make** command allows generating specific NDEF messages. The
type of message is determined by a further sub-command:

* **make smartposter** - creates a smartposter record
* **make wificfg** - creates a WiFi Configuration record
* **make wifipwd** - creates a WiFi Password record
* **make btcfg** - creates a Bluetooth out-of-band record

make smartposter
^^^^^^^^^^^^^^^^

The **make smartposter** command creates a smartposter message for the
uniform resource identifier *reference*::

  $ ndeftool.py make smartposter [-h|--help] [options] reference

Options:

.. program:: ndeftool.py make smartposter

.. option:: -t titlespec

   Add a smart poster title. The *titlespec* consists of an ISO/IANA
   language code, a ":" as separator, and the title string. The
   language code is optional and defaults to "en". The separator may
   then also be omitted unless the title string itself contains a
   colon. Multiple ``-t`` options may be present for different languages.

.. option:: -i iconfile

   Add a smart poster icon. The *iconfile* must be an existing and
   readable image file for which a mime type is registered. Multiple
   ``-i`` options may be present for different image types.

.. option:: -a actionstring

   Set the smart poster action. Valid action strings are "default"
   (default action of the receiving device), "exec" (send SMS, launch
   browser, call phone number), "save" (store SMS in INBOX, bookmark
   hyperlink, save phone number in contacts), and "edit".

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.
   
make wificfg
^^^^^^^^^^^^

The **make wificfg** command creates a configuration token for the WiFi network with SSID *network-name*. Without further options this command creates configuration data for an open network::

  $ ndeftool.py make wificfg [-h|--help] [options] network-name

Options:

.. program:: ndeftool.py make wificfg

.. option:: --key network-key

   Set the *network-key* for a secured WiFi network. The security
   method is set to WPA2-Personal.

.. option:: --mixed-mode

   With this option set the security method is set to also include the
   older WPA-Personal standard.

.. option:: --mac mac-address

   The MAC address of the device for which the credential was
   generated. Without the ``--mac`` option the broadcast MAC
   "ff:ff:ff:ff:ff:ff" is used to indicate that the credential is
   not device specific.

.. option:: --shareable

   Set this option if the network configuration may be shared with
   other devices.

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.
   
.. option:: --hs

   Encapsulate the Wifi Configuration record into a Handover Select
   Message. The carrier power state will set to 'unknown'.

.. option:: --active

   Generate a Handover Select message with the WiFi carrier power
   state set to 'active'. This option is mutually exclusive with the
   ``--inactive`` and ``--activating`` options.

.. option:: --inactive

   Generate a Handover Select message with the WiFi carrier power
   state set to 'inactive'. This option is mutually exclusive with the
   ``--active`` and ``--activating`` options.

.. option:: --activating

   Generate a Handover Select message with the WiFi carrier power
   state set to 'activating'. This option is mutually exclusive with
   the ``--active`` and ``--inactive`` options.

make wifipwd
^^^^^^^^^^^^

The **make wifipwd** command creates a password token for the WiFi Protected Setup registration protocol, signed with the first 160 bits of SHA-256 hash of the enrollee's public key in *public-key-file*.::

  $ ndeftool.py make wificfg [-h|--help] [options] public-key-file

Options:

.. program:: ndeftool.py make wifipwd

.. option:: -p device-password

   A 16 - 32 octet long device password. If the ``-p`` option is not
   given a 32 octet long random device password is generated.

.. option:: -i password-id

   An arbitrary value between 0x0010 and 0xFFFF that serves as an
   identifier for the device password. If the ``-i`` option is not
   given a random password identifier is generated.

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.
   
make btcfg
^^^^^^^^^^

The **make btcfg** command creates an out-of-band configuration record for a Bluetooth device.::

  $ ndeftool.py make btcfg [-h|--help] [options] device-address

Options:

.. program:: ndeftool.py make btcfg

.. option:: -c class-of-device

   The 24 class of device/service bits as a string of '0' and '1'
   characters, with the most significant bit left.

.. option:: -n name-of-device

   The user friendly name of the device.

.. option:: -s service-class

   A service class implemented by the device. A service class may be
   specified by description or as a 128-bit UUID string (for example,
   "00001108-0000-1000-8000-00805f9b34fb" would indicate
   "Printing"). Textual descriptions are evaluated case insensitive
   and must then match one of the following:

   'Handsfree Audio Gateway', 'PnP Information', 'Message Access
   Server', 'ESDP UPNP IP PAN', 'HDP Source', 'Generic Networking',
   'Message Notification Server', 'Browse Group Descriptor', 'NAP',
   'A/V Remote Control Target', 'Basic Imaging Profile', 'Generic File
   Transfer', 'Message Access Profile', 'Generic Telephony', 'Basic
   Printing', 'Intercom', 'HCR Print', 'Dialup Networking', 'Advanced
   Audio Distribution', 'Printing Status', 'OBEX File Transfer',
   'Handsfree', 'Hardcopy Cable Replacement', 'Imaging Responder',
   'Phonebook Access - PSE', 'ESDP UPNP IP LAP', 'IrMC Sync',
   'Cordless Telephony', 'LAN Access Using PPP', 'OBEX Object Push',
   'Video Source', 'Audio Source', 'Human Interface Device', 'Video
   Sink', 'Reflected UI', 'ESDP UPNP L2CAP', 'Service Discovery
   Server', 'HDP Sink', 'Direct Printing Reference', 'Serial Port',
   'SIM Access', 'Imaging Referenced Objects', 'UPNP Service', 'A/V
   Remote Control Controller', 'HCR Scan', 'Headset - HS', 'UPNP IP
   Service', 'IrMC Sync Command', 'GNSS', 'Headset', 'WAP Client',
   'Imaging Automatic Archive', 'Phonebook Access', 'Fax', 'Generic
   Audio', 'Audio Sink', 'GNSS Server', 'A/V Remote Control', 'Video
   Distribution', 'WAP', 'Common ISDN Access', 'Direct Printing',
   'GN', 'PANU', 'Phonebook Access - PCE', 'Headset - Audio Gateway
   (AG)', 'Reference Printing', 'HDP'

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.
   
.. option:: --hs

   Encapsulate the Bluetooth Configuration record into a Handover
   Select Message. The carrier power state will set to 'unknown'
   unless one of the options `--active`, `--inactive` or
   `--activating` is given.

.. option:: --active

   Generate a Handover Select message with the Bluetooth carrier power
   state set to 'active'. This option is mutually exclusive with the
   ``--inactive`` and ``--activating`` options.

.. option:: --inactive

   Generate a Handover Select message with the Bluetooth carrier power
   state set to 'inactive'. This option is mutually exclusive with the
   ``--active`` and ``--activating`` options.

.. option:: --activating

   Generate a Handover Select message with the Bluetooth carrier power
   state set to 'activating'. This option is mutually exclusive with
   the ``--active`` and ``--inactive`` options.

pack
----

The **pack** command converts a file into an NDEF record with both
message begin and end flag set to 1. If the ``-t`` option is not given
the record type is guessed from the file content using the mimetypes
module. The record name is by default set to the name of the file
being converted, unless data is read from stdin in which case the
record name is not encoded.

If a file mime type is ``text/plain`` it will be encoded as an NDEF
Text Record (type ``urn:nfc:wkt:T``) if ``-t`` is not set. The text
record language is guessed from the file content if the Python module
``guess_language`` is installed, otherwise set to English. ::

  $ ndeftool.py pack [-h|--help] [options] FILE

Options:

.. program:: ndeftool.py pack

.. option:: -t record-type

   Set the record type to *record-type* (the default is to guess it from
   the file mime type).

.. option:: -n record-name

   Set the record identifier to *record-name* (the default is to use
   the file path name).

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.
   
split
-----

The **split** command separates an an NDEF message into individual
records. If data is read from a file, records are written as binary
data into individual files with file names constructed from the input
file base name, a hyphen followed by a three digit number and the
input file name extension. If data is read from stdin, records are
written to stdout as individual lines of hexadecimal strings. ::

  $ ndeftool.py split [-h|--help] [options] message-file

Options:

.. program:: ndeftool.py split

.. option:: --keep-message-flags

   Do not reset the record's message begin and end flags but leave tem
   as found in the input message data.

cat
---

The **cat** command concatenates records into a single message. ::

  $ ndeftool.py cat [-h|--help] record-file [record-file ...]

Options:

.. program:: ndeftool.py cat

.. option:: -o output-file

   Write message data to *output-file* (default is write to standard
   output). The ``-o`` option also switches the output format to raw
   bytes versus the hexadecimal string written to stdout.


Examples
========

To build a smartposter that points to the nfcpy documentation page: ::

  $ ndeftool.py make smartposter http://nfcpy.org/docs
  d102135370d1010f55036e666370792e6f72672f646f6373

The output can be made readable with the ndeftool print command: ::

  $ ndeftool.py make smartposter http://nfcpy.org/docs | ndeftool.py print
  Smartposter Record
    resource = http://nfcpy.org/docs
    action   = default

To get the smartposter as raw bytes specify an output file: ::

  $ ndeftool.py make smartposter http://nfcpy.org/docs -o sp_nfcpy_docs.ndef

Here's a more complex example setting multi-language smartposter title, icons and a non-default action: ::

  $ ndeftool.py make smartposter http://nfcpy.org/docs -t "nfcpy documentation" -t "de:nfcpy Dokumentation" -i logo.gif -i logo.png -a save -o sp_nfcpy_docs.ndef

It is sometimes helpful to have an NDEF message of specific length where the payload consists of monotonically increasing byte values::

  $ python -c "import sys; sys.stdout.write(bytearray([x % 256 for x in xrange(1024-6)]))" | ndeftool.py pack - -o message-1k.ndef
