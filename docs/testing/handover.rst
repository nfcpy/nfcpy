===================
Connection Handover
===================

The **handover-test-server.py** and **handover-test-client.py**
programs provide a test facility for the NFC Forum Connection Handover
1.2 specification.

handover-test-server.py
=======================

Usage::

  $ handover-test-server.py [-h|--help] [OPTION]... [CARRIER]...

The handover test server implements the handover selector role. A
handover client can connect to the server with the well-known service
name ``urn:nfc:sn:handover`` and send handover request messages. The
server replies with handover select messages populated with carriers
provided through *CARRIER* arguments and matching the a carrier in the
received handover request carrier list.

Each *CARRIER* argument must provide an NDEF message file, which may
be a handover select message with one or more alternative carriers
(including auxiliary data) or an alternative carrier record optionally
followed by one or more auxiliary data records. Note that only the
handover select message format allows to specify the carrier power
state. All carriers including power state information and auxiliary
data records are accumulated into a list of selectable carriers,
ordered by argument position and carrier sequence within a handover
select message.

Unless the ``--skip-local`` option is given, the server attempts to
include carriers that are locally available on the host device. Local
carriers are always added after all *CARRIER* arguments.

.. note:: Local carrier detection currently requires a Linux OS with
          the bluez Bluetooth stack and D-Bus. This is true for many
          Linux distributions, but has so far only be tested on
          Ubuntu.

Options:

.. program:: handover-test-server.py

.. option:: --skip-local

   Skip the local carrier detection. Without this option the handover
   test server tries to discover locally available carriers and
   consider them in the selection process. Local carriers are
   considered after all carriers provided manually.

.. option:: --select NUM

   Return at most *NUM* carriers with the handover select message. The
   default is to return all matching carriers.

.. option:: --delay INT

   Delay the handover response for the number of milliseconds
   specified as INT. The handover specification says that the server
   should answer within 1 second and if it doesn't the client may
   assume a processing error.

.. option:: --recv-miu INT

   Set the maximum information unit size for inbound LLCP packets on
   the data link connection between the server and the remote client.
   This value is transmitted with the CC PDU to the remote client.

.. option:: --recv-buf INT

   Set the receive window size for inbound LLCP packets on the data
   link connection between the server and the remote client. This
   value is transmitted with the CC PDU to the remote client.

.. option:: --quirks

   This option causes the handover test server to try support
   non-compliant implementations if possible and as known. Currently
   implemented work-arounds are:

   * a 'urn:nfc:sn:snep' server is enabled and accepts the GET request
     with a handover request message that was implemented in Android
     Jelly Bean
   * the version of the handover request message sent by Android Jelly
     Bean is changed to 1.1 to accomodate the missing collision
     resolution record that is required for version 1.2.
   * the incorrect type-name-format encoding in handover carrier
     records sent by some Sony Xperia phones is corrected to
     mime-type.

Test Scenarios
--------------

Empty handover select response
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-server.py --select 0

Verify that the remote handover client accepts a handover select message that has no alternative carriers.

A carrier that is being activated
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ ndeftool.py make btcfg 01:02:03:04:05:06 --activating | handover-test-server --skip-local -

Verify that the remote handover client understands and tries to
connect to a Bluetooth carrier that is in the process of activation.

Delayed handover select response
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

  $ examples/handover-test-server.py --delay 10000

Check hot the remote handover implementation behaves if the handover
select response is delayed for about 10 seconds. This test intends to
help identify user interface issues.


handover-test-client.py
=======================

**Usage** ::

  $ handover-test-client.py [-h|--help] [OPTION]... [CARRIER]...

The handover test client implements the handover requester role. The
handover client connects to the remote server with well-known service
name ``urn:nfc:sn:handover`` and sends handover request messages
populated with carriers provided through one or more *CARRIER*
arguments or implicitly if tests from the test suite are executed. The
client expects the server to reply with handover select messages that
list carriers matching one or more of the carriers sent with the
handover request carrier list.

Each *CARRIER* argument must provide an NDEF message file which may be
a handover message with one or more alternative carriers (including
auxiliary data) or an alternative carrier record followed by zero or
more auxiliary data records. Note that only the handover message
format allows to specify the carrier power state. All carriers,
including power state information and auxiliary data records, are
accumulated into a list of requestable carriers ordered by argument
position and carrier sequence within a handover message.

**Options**

.. program:: handover-test-client.py

.. option:: -t N, --test N

   Run test number *N* from the test suite. Multiple tests can be
   specified.

.. option:: --relax

   The ``--relax`` option affects how missing optional, but highly
   recommended, handover data is handled when running test
   scenarios. Without ``--relax`` any missing data is regarded as a
   test error that terminates test execution. With the ``--relax``
   option set only a warning message is logged.

.. option:: --recv-miu INT

   Set the maximum information unit size for inbound LLCP packets on
   the data link connection between the client and the remote server.
   This value is transmitted with the CONNECT PDU to the remote
   server.

.. option:: --recv-buf INT

   Set the receive window size for inbound LLCP packets on the data
   link connection between the client and the remote server. This
   value is transmitted with the CONNECT PDU to the remote server.

.. option:: --quirks

   This option causes the handover test client to try support
   non-compliant implementations as much as possible, including and
   beyond the ``--relax`` behavor. The modifications activated with
   ``--quirks`` are:

   * After test procedures are completed the client does not terminate
     the LLCP link but waits until the link is disrupted to prevent
     the NFC stack segfault and recovery on pre 4.1 Android devices.
   * Try sending the handover request message with a SNEP GET request
     to the remote default SNEP server if the `urn:nfc:sn:handover`
     service is not available.

Test Scenarios
--------------

Presence and connectivity
^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 1

Verify that the remote device has the connection handover service
active and that the client can open, close and re-open a connection
with the server.

1. Connect to the remote handover service.

2. Close the data link conection.

3. Connect to the remote handover service.

4. Close the data link conection.

Empty carrier list
^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 2

Verify that the handover server responds to a handover request without
alternative carriers with a handover select message that also has no
alternative carriers.

1. Connect to the remote handover service.

2. Send a handover request message containing zero alternative
   carriers.

3. Verify that the server returns a handover select message within
   no more than 3 seconds; and that the message contains zero
   alternative carriers.

4. Close the data link conection.

Version handling
^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 3

Verify that the remote handover server handles historic and future
handover request version numbers. This test is run as a series of
steps where for each step the connection to the server is established
and closed after completion. For all steps the configuration sent is a
Bluetooth carrier for device address ``01:02:03:04:05:06``.

#. Connect to the remote handover service.
#. Send a handover request message with version ``1.2``.
#. Verify that the server replies with version ``1.2``. 
#. Close the data link conection.

#. Connect to the remote handover service.
#. Send a handover request message with version ``1.1``.
#. Verify that the server replies with version ``1.2``. 
#. Close the data link conection.

#. Connect to the remote handover service.
#. Send a handover request message with version ``1.15``.
#. Verify that the server replies with version ``1.2``. 
#. Close the data link conection.

#. Connect to the remote handover service.
#. Send a handover request message with version ``15.0``.
#. Verify that the server replies with version ``1.2``. 
#. Close the data link conection.

Bluetooth just-works pairing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 4

Verify that the ``application/vnd.bluetooth.ep.oob`` alternative
carrier is correctly evaluated and replied. This test is only
applicable if the peer device does have Bluetooth connectivity.

#. Connect to the remote handover service.

#. Send a handover request message with a single alternative carrier
   of type ``application/vnd.bluetooth.ep.oob`` and power state
   ``active``. Secure pairing hash and randomizer are not provided
   with the Bluetooth configuration.

#. Verify that the server returns a handover select message within no
   more than 3 seconds; that the message contains exactly one
   alternative carrier with type ``application/vnd.bluetooth.ep.oob``
   and power state ``active`` or ``activating``; that the Bluetooth
   local device name is transmitted; and that secure simple pairing
   hash and randomizer are not transmitted. Issues a warning if class
   of device/service or service class UUID attributes are not
   transmitted.

#. Close the data link conection.

Bluetooth secure pairing
^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 5

Verify that the ``application/vnd.bluetooth.ep.oob`` alternative
carrier is correctly evaluated and replied. This test is only
applicable if the peer device does have Bluetooth connectivity.

#. Connect to the remote handover service.

#. Send a handover request message with a single alternative carrier
   of type ``application/vnd.bluetooth.ep.oob`` and power state
   ``active``. Secure pairing hash and randomizer are transmitted with
   the Bluetooth configuration.

#. Verify that the server returns a handover select message within no
   more than 3 seconds; that the message contains exactly one
   alternative carrier with type ``application/vnd.bluetooth.ep.oob``
   and power state ``active`` or ``activating``; that the Bluetooth
   local device name is transmitted; and that secure simple pairing
   hash and randomizer are transmitted. Issues a warning if class of
   device/service or service class UUID attributes are not
   transmitted.

#. Close the data link conection.

Unknown carrier type
^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 6

Verify that the remote handover server returns a select message
without alternative carriers if a single carrier of unknown type was
sent with the handover request.

#. Connect to the remote handover service.

#. Send a handover request message with a single alternative carrier
   of type ``urn:nfc:ext:nfcpy.org:unknown-carrier-type``.

#. Verify that the server returns a handover select message with an
   empty alternative carrier selection.

#. Close the data link conection.

Two handover requests
^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 7

Verify that the remote handover server does not close the data link
connection after the first handover request message.

#. Connect to the remote handover service.

#. Send a handover request with a single carrier of unknown type

#. Send a handover request with a single Bluetooth carrier

#. Close the data link conection.

Reserved-future-use check
^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 8

Verify that reserved bits are set to zero and optional reserved bytes
are not present in the payload of the alternative carrier record. This
test requires that the remote server selects a Bluetooth alternative
carrier if present in the request.

#. Connect to the remote handover service.

#. Send a handover request with a single Bluetooth carrier

#. Verify that an alternative carrier record is present; that
   reserved bits in the first octet are zero; and that the record
   payload ends with the last auxiliary data reference.

#. Close the data link conection.

Skip meaningless records
^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ handover-test-client.py -t 9

Verify that records that have no defined meaning in the payload of a
handover request record are ignored. This test assumes that the remote
server selects a Bluetooth alternative carrier if present in the
request.

#. Connect to the remote handover service.

#. Send a handover request with a single Bluetooth carrier and a
   meaningless text record as the first record of the handover
   request record payload.

#. Verify that an Bluetooth alternative carrier record is returned.

#. Close the data link conection.

