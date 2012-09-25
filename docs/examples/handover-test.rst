==================
handover test tool
==================

The **ndeftool** intends to be a swiss army knife for working with
NDEF data.

handover test server
====================

Usage::

  $ handover-test-server.py [-h|--help] [OPTION]... [CARRIER]...

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

Usage::

  $ handover-test-client.py [-h|--help] [OPTION]... [CARRIER]...

Options:

.. program:: handover-test-client.py


Recipes
=======

