=============================
Simple NDEF Exchange Protocol
=============================

snep-test-server.py
===================

The SNEP test server program implements an NFC device that provides
two SNEP servers:

#. A **Default SNEP Server** that is compliant with the NFC Forum
   Default SNEP Server defined in section 6 of the SNEP specification.

#. A **Validation SNEP Server** that accepts SNEP Put and Get
   requests. A Put request causes the server to store the NDEF message
   transmitted with the request. A Get request causes the server to
   attempt to return a previously stored NDEF message of the same NDEF
   message type and identifier as transmitted with the request. The
   server will keep any number of distinct NDEF messages received with
   Put request until the client terminates the data link connection.

   The Validation SNEP Server uses the service name
   ``urn:nfc:xsn:nfc-forum.org:snep-validation``, assigned for the
   purpose of validating the SNEP candidate specification prior to
   adoption.

**Usage** ::

  $ snep-test-server.py [-h|--help] [OPTION]...

.. program:: snep-test-server.py

**Options**

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-peermode-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt


snep-test-client.py
===================

**Usage** ::

  $ snep-test-client.py [-h|--help] [OPTION]...

.. program:: snep-test-client.py

**Options**

.. option:: -t N, --test N

   Run test number *N*. May be set more than once.

.. option:: -T, --test-all

   Run all tests.

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-peermode-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt

Test Scenarios
--------------

Connect and terminate
^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 1

Verify that a data link connection with the remote validation server
can be established and terminated gracefully and that the server
returns to a connectable state.

1. Establish a data link connection with the Validation Server.

2. Verify that the data link connection was established successfully.

3. Close the data link connection with the Validation Server.

4. Establish a new data link connection with the Validation Server.

5. Verify that the data link connection was established successfully.

6. Close the data link connection with the Validation Server.

Unfragmented message exchange
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 2

Verify that the remote validation server is able to receive
unfragmented SNEP messages.

1. Establish a data link connection with the Validation Server.

2. Send a Put request with an NDEF message of no more than 122 octets
   total length.

3. Verify that the Validation Server accepted the Put request.

4. Send a Get request that identifies the NDEF message sent in step 2
   to be retrieved.

5. Verify that the retrieved NDEF message is identical to the one
   transmitted in step 2.

6. Close the data link connection.

Fragmented message exchange
^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 3

Verify that the remote validation server is able to receive fragmented
SNEP messages.

1. Establish a data link connection with the Validation Server.

2. Send a Put request with an NDEF message of more than 2170 octets
   total length.

3. Verify that the Validation Server accepted the Put request.

4. Send a Get request that identifies the NDEF message sent in step 2
   to be retrieved.

5. Verify that the retrieved NDEF message is identical to the one
   transmitted in step 2.

6. Close the data link connection.

Multiple ndef messages
^^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 4

Verify that the remote validation server accepts more than a single
NDEF message on the same data link connection.

1. Establish a data link connection with the Validation Server.

2. Send a Put request with an NDEF message that differs from the NDEF
   message to be send in step 3.

3. Send a Put request with an NDEF message that differs from the NDEF
   message that has been send send in step 2.

4. Send a Get request that identifies the NDEF message sent in step 2
   to be retrieved.

5. Send a Get request that identifies the NDEF message sent in step 3
   to be retrieved.

6. Verify that the retrieved NDEF messages are identical to the NDEF
   messages transmitted in steps 2 and 3.

7. Close the data link connection.

Undeliverable resource
^^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 5

Verify verify that the remote validation server responds appropriately
if the client requests an NDEF message that exceeds the maximum
acceptable length specified by the request.

1. Establish a data link connection with the Validation Server.

2. Send a Put request with an NDEF message of total lenght N.

3. Verify that the Validation Server accepted the Put request.

4. Send a Get request with the maximum acceptable lenght field set to
   *N − 1* and an NDEF message that identifies the NDEF message sent
   in step 2 to be retrieved.

5. Verify that the server replies with the appropriate response message.

6. Close the data link connection.

Unavailable resource
^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 6

Verify that the remote validation server responds appropriately if the
client requests an NDEF message that is not available.

1. Establish a data link connection with the Validation Server.

2. Send a Get request that identifies an arbitrary NDEF message to be
   retrieved.

3. Verify that the server replies with the appropriate response
   message.

4. Close the data link connection.

Default server limits
^^^^^^^^^^^^^^^^^^^^^
::

   $ snep-test-client.py -t 7

Verify verify that the remote default server accepts a Put request
with an information field of up to 1024 octets, and that it rejects a
Get request.

1. Establish a data link connection with the Default Server.

2. Send a Put request with an NDEF message of up to 1024 octets total
   length.

3. Verify that the Default Server replies with a Success response
   message.

4. Send a Get request with an NDEF message of arbitrary type and
   identifier.

5. Verify that the Default Server replies with a Not Implemented
   response message.

6. Close the data link connection.
