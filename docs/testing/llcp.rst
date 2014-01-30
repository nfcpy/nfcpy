=============================
Logical Link Control Protocol
=============================

llcp-test-server.py
===================

The LLCP test server program implements an NFC device that provides
three distinct server applications:

#. A **connection-less echo server** that accepts connection-less
   transport mode PDUs. Service data units may have any size between
   zero and the maximum information unit size announced with the LLCP
   Link MIU parameter. Inbound service data units enter a linear
   buffer of service data units. The buffer has a capacity of two
   service data units. The first service data unit entering the buffer
   starts a delay timer of 2 seconds (echo delay). Expiration of the
   delay timer causes service data units in the buffer to be sent back
   to the original sender, which may be different for each service
   data unit, until the buffer is completely emptied. The buffer empty
   condition then re-enables the delay timer start event for the next
   service data unit.

#. A **connection-mode echo server** that waits for a connect
   request and then accepts and processes connection-oriented
   transport mode PDUs. Further connect requests will be rejected
   until termination of the data link connection. When accepting the
   connect request, the receive window parameter is transmitted with a
   value of 2.
   
   The connection-oriented mode echo service stores inbound service
   data units in a linear buffer of service data units. The buffer has
   a capacity of three service data units. The first service data unit
   entering the buffer starts a delay timer of 2 seconds (echo
   delay). Expiration of the delay timer causes service data units in
   the buffer to be sent back to the orignal sender until the buffer
   is completely emptied. The buffer empty condition then re-enables
   the delay timer start event for the next service data unit.
   
   The echo service determines itself as busy if it is unable to
   accept further incoming service data units.

#. A **connection-mode dump server** that accepts connections and then
   accepts and forgets all data received on a data link connection.
   This is mostly useful to measure transfer speed under load
   conditions.

**Usage** ::

  $ llcp-test-server.py [-h|--help] [OPTION]...

.. program:: llcp-test-server.py

**Options**

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-peermode-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt


llcp-test-client.py
===================

**Usage** ::

  $ llcp-test-client.py [-h|--help] [OPTION]... 

.. program:: llcp-test-client.py

**Options**

.. option:: -t N, --test N

   Run test number *N*. May be set more than once.

.. option:: -T, --test-all

   Run all tests.

.. option:: --cl-echo SAP

   Service access point address of the connection-less mode echo
   server.

.. option:: --co-echo SAP

   Service access point address of the connection-oriented mode echo
   server.

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-peermode-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt

Test Scenarios
--------------

Link activation, symmetry and deactivation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 1

Verify that the LLCP Link can be activated successfully, that the
symmetry procedure is performed and the link can be intentionally
deactivated.

1. Start the MAC link activation procedure on two implementations
   and verify that the version number parameter is received and
   version number agreement is achieved.

2. Verify for a duration of 5 seconds that SYMM PDUs are exchanged
   within the Link Timout values provided by the implementations.

3. Perform intentional link deactivation by sending a DISC PDU to
   the remote Link Management component. Verify that SYMM PDUs
   are no longer exchanged.

Connection-less information transfer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 2

Verify that the source and destination access point address fields are
correctly interpreted, the content of the information field is
extracted as the service data unit and the service data unit can take
any length between zero and the announced Link MIU. The LLCP Link must
be activated prior to running this scenario and the Link MIU of the
peer implementation must have been determined. In this scenario,
sending of a service data unit (SDU) means that the SDU is carried
within the information field of a UI PDU.

1. Send a service data unit of 128 octets length to the
   connection-less mode echo service and verify that the same SDU is
   sent back after the echo delay time.

2. Send within echo delay time with a time interval of at least 0.5
   second two consecutive service data units of 128 octets length to
   the connection-less mode echo service and verify that both SDUs are
   sent back correctly.

3. Send within echo delay time with a time interval of at least 0.5
   second three consecutive service data units of 128 octets length to
   the connection-less mode echo service and verify that the first two
   SDUs are sent back correctly and the third SDU is discarded.

4. Send a service data unit of zero octets length to the
   connection-less mode echo service and verify that the same zero
   length SDU is sent back after the echo delay time.

5. Send a service data unit of maximum octets length to the
   connection-less mode echo service and verify that the same SDU is
   sent back after the echo delay time. Note that the maximum length
   here must be the smaller value of both implementations Link MIU.

Connection-oriented information transfer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 3

Verify that a data link connection can be established, a service data
unit is received and sent back correctly and the data link connection
can be terminated. The LLCP Link must be activated prior to running
this scenario and the connection-oriented mode echo service must be in
the unconnected state.  In this scenario, sending of a service data
unit (SDU) means that the SDU is carried within the information field
of an I PDU.

1. Send a CONNECT PDU to the connection-oriented mode echo service and
   verify that the connection request is acknowledged with a CC
   PDU. The CONNECT PDU shall encode the RW parameter with a value
   of 2. Verify that the CC PDU encodes the RW parameter with a value
   of 2 (as specified for the echo server).

2. Send a single service data unit of 128 octets length over the data
   link connection and verify that the echo service sends an RR PDU
   before returning the same SDU after the echo delay time.

3. Send a DISC PDU to terminate the data link connection and verify
   that the echo service responds with a correct DM PDU.

Send and receive sequence number handling
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 4

Verify that a sequence of service data units that causes the send and
receive sequence numbers to take all possible values is received and
sent back correctly. The LLCP Link must be activated prior to running
this scenario and the connection-oriented mode echo service must be in
the unconnected state. In this scenario, sending of a service data
unit (SDU) means that the SDU is carried within the information field
of an I PDU.

1. Send a CONNECT PDU to the connection-oriented mode echo service and
   verify that the connection request is acknowledged with a CC
   PDU. The CONNECT PDU shall encode the RW parameter with a value
   of 2. Verify that the CC PDU encodes the RW parameter with a value
   of 2 (as specified for the echo server).

2. Send a sequence of at least 16 data units of each 128 octets length
   over the data link connection and verify that all SDUs are sent
   back correctly.

3. Send a DISC PDU to terminate the data link connection and verify
   that the echo service responds with a correct DM PDU.

Handling of receiver busy condition
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 5

Verify the handling of a busy condition. The LLCP Link must be
activated prior to running this scenario and the connection-oriented
mode echo service must be in the unconnected state.  In this scenario,
sending of a service data unit (SDU) shall mean that the SDU is
carried within the information field of an I PDU.

1. Send a CONNECT PDU to the connection-oriented mode echo service and
   verify that the connect request is acknowledged with a CC PDU. The
   CONNECT PDU shall encode the RW parameter with a value of 0. Verify
   that the CC PDU encodes the RW parameter with a value of 2 (as
   specified for the echo server).

2. Send four service data units of 128 octets length over the data
   link connection and verify that the echo service enters the busy
   state when acknowledging the last packet.

3. Send a DISC PDU to terminate the data link connection and verify
   that the echo service responds with a correct DM PDU.

Rejection of connect request
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 6

Verify that an attempt to establish a second connection with the
connection-oriented mode echo service is rejected. The LLCP Link must
be activated prior to running this scenario.

1. Send a first CONNECT PDU to the connection-oriented mode echo
   service and verify that the connect request is acknowledged with a
   CC PDU.

2. Send a second CONNECT PDU to the connection-oriented mode echo
   service and verify that the connect request is rejected with a DM
   PDU and appropriate reason code.

3. Send a service data unit of 128 octets length over the data link
   connection and verify that the echo service returns the same SDU
   after the echo delay time.

4. Send a DISC PDU to terminate the data link connection and verify
   that the echo service responds with a correct DM PDU.

Connect by service name
^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 7

Verify that a data link connection can be established by specifying a
service name. The LLCP Link must be activated prior to running this
scenario and the connection-oriented mode echo service must be in the
unconnected state.

1. Send a CONNECT PDU with an SN parameter that encodes the value
   "urn:nfc:sn:co-echo" to the service discovery service access point
   address and verify that the connect request is acknowledged with a
   CC PDU.

2. Send a service data unit over the data link connection and verify
   that it is sent back correctly.

3. Send a DISC PDU to terminate the data link connection and verify
   that the echo service responds with a correct DM PDU.

Aggregation and disaggregation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 8

Verify that the aggregation procedure is performed correctly. The LLCP
Link must be activated prior to running this scenario.  In this
scenario, sending of a service data unit (SDU) shall mean that the SDU
is carried within the information field of a UI PDU.

1. Send two service data units of 50 octets length to the
   connection-less mode echo service such that the two resulting UI
   PDUs will be aggregated into a single AGF PDU by the LLC
   sublayer. Verify that both SDUs are sent back correctly and in the
   same order.

2. Send three service data units of 50 octets length to the
   connection-less mode echo service such that the three resulting UI
   PDUs will be aggregated into a single AGF PDU by the LLC
   sublayer. Verify that the two first SDUs are sent back correctly
   and the third SDU is discarded.

Service name lookup
^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 9

Verify that a service name is correctly resolved into a service access
point address by the remote LLC. The LLCP Link must be activated prior
to running this scenario.  In this scenario, sending of a service data
unit (SDU) shall mean that the SDU is carried within the information
field of a UI PDU.

1. Send an SNL PDU with an SDREQ parameter in the information field
   that encodes the value "urn:nfc:sn:sdp" to the service discovery
   service access point address and verify that the request is
   responded with an SNL PDU that contains an SDRES parameter with the
   SAP value '1' and a TID value that is the same as the value encoded
   in the antecedently transmitted SDREQ parameter.

2. Send an SNL PDU with an SDREQ parameter in the information field
   that encodes the value "urn:nfc:sn:cl-echo" to the service
   discovery service access point address and verify that the request
   is responded with an SNL PDU that contains an SDRES parameter with
   a SAP value other than '0' and a TID value that is the same as the
   value encoded in the antecedently transmitted SDREQ parameter.

3. Send a service data unit of 128 octets length to the service access
   point address received in step 2 and verify that the same SDU is
   sent back after the echo delay time.

4. Send an SNL PDU with an SDREQ parameter in the information field
   that encodes the value "urn:nfc:sn:sdp-test" to the service
   discovery service access point address and verify that the request
   is responded with an SNL PDU that contains an SDRES parameter with
   the SAP value '0' and a TID value that is the same as the value
   encoded in the antecedently transmitted SDREQ parameter.

Send more data than allowed
^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 10

Use invalid send sequence number
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 11

Use maximum data size on data link connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 12

Connect, release and connect again
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 13

Connect to unknown service name
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ llcp-test-client.py -t 14

Verify that a data link connection can be established by specifying a
service name. The LLCP Link must be activated prior to running this
scenario and the connection-oriented mode echo service must be in the
unconnected state.

1. Send a CONNECT PDU with an SN parameter that encodes the value
   "urn:nfc:sn:co-echo-unknown" to the service discovery service
   access point address and verify that the connect request is
   rejected.
