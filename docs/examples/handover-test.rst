==================
Handover Test Tool
==================

The scripts **handover-test-server.py** and **handover-test-client.py** provide a test facility for the NFC Forum Connection Handover Protocol.

Handover Test Server
====================

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

Handover Test Client
====================

Usage::

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

Options:

.. program:: handover-test-client.py

.. option:: -t N, --test N

   Run test number *N* from the test suite. Multiple tests can be
   specified.

.. option:: --relax

   The ``--relax`` option affects how missing optional, but highly
   recommended, handover date is handled when running test
   scenarios. Without ``--relax`` any missing data is regarded as a
   test error that terminates test execution. With the ``--relax``
   option set only a warning message is logged.

.. option:: --quirks

   This option causes the handover test client to try support
   non-compliant implementations if possible and as known. The
   behavioral modifications activated with `--quirks` are:

   * after test procedures are completed the client does not terminate
     the LLCP link but waits until the link is disrupted to prevent
     the NFC stack segfault and recovery on pre 4.1 Android devices.

Test Suite
----------

**1 - Presence and connectivity**

   Verify that the remote device has the connection handover service
   active and that the client can open, close and re-open a connection
   with the server.

   #. Connect to the remote handover service.
   #. Close the data link conection.
   #. Connect to the remote handover service.
   #. Close the data link conection.

**2 - Empty carrier list**

   Verify that the handover server responds to a handover request
   without alternative carriers with a handover select message that
   also has no alternative carriers.

   #. Connect to the remote handover service.
   #. Send a handover request message containing zero alternative
      carriers.
   #. Verify that the server returns a handover select message within
      no more than 3 seconds; and that the message contains zero
      alternative carriers.
   #. Close the data link conection.

**3 - Version handling**

   Verify that the remote handover server handles historic and future
   handover request version numbers.

   #. Connect to the remote handover service.
   #. Send a handover request message with version ``1.2``.
   #. Verify that the server replies with version ``1.2``. 
   #. Send a handover request message with version ``1.1``.
   #. Verify that the server replies with version ``1.2``. 
   #. Send a handover request message with version ``1.15``.
   #. Verify that the server replies with version ``1.2``. 
   #. Send a handover request message with version ``15.0``.
   #. Verify that the server replies with version ``1.2``. 
   #. Close the data link conection.

**4 - Single Bluetooth carrier**

   Verify that the `application/vnd.bluetooth.ep.oob` alternative
   carrier is correctly evaluated and replied with a all mandatory and
   recommended information. This test is only applicable if the peer
   device does have Bluetooth connectivity.

   #. Connect to the remote handover service.
   #. Send a handover request message containing a single alternative
      carrier with type `application/vnd.bluetooth.ep.oob` and power
      state `active`.
   #. Verify that the server returns a handover select message within
      no more than 3 seconds; that the message contains exactly one
      alternative carrier with type `application/vnd.bluetooth.ep.oob`
      and power state `active` or `activating`; and that the Bluetooth
      local name, secure simple pairing hash and randomizer, class of
      device/service, and one or more service class UUID attributes
      are provided.
   #. Close the data link conection.

Recipes
=======

Return a handover select message with no alternative carriers. ::

  $ examples/handover-test-server.py --select 0

Generate a Bluetooth configuration piped to the handover test server
as the only alternative carrier (locally available carriers are
excluded with ``--skip-local``. ::

  $ examples/ndeftool.py make btcfg 01:02:03:04:05:06 --activating | examples/handover-test-server --skip-local -

Delay the handover select response for 10 seconds to check the other
implementation's idea of user experience. ::

  $ examples/handover-test-server.py --delay 10000

