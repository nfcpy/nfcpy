==================
handover test tool
==================

The scripts **handover-test-server.py** and **handover-test-client.py** provide a test facility for the NFC Forum Connection Handover Protocol.

handover test server
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


handover test client
====================

.. note:: The handover-test-client is not yet available.

..
  Usage::

  $ handover-test-client.py [-h|--help] [OPTION]... [CARRIER]...

  Options:

  .. program:: handover-test-client.py


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
