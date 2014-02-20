====================================
Personal Health Device Communication
====================================

phdc-test-manager.py
====================

This program implements an NFC device that provides a PHDC manager
with the well-known service name ``urn:nfc:sn:phdc`` and a
non-standard PHDC manager with the experimental service name
``urn:nfc:xsn:nfc-forum.org:phdc-validation``.

**Usage** ::

  $ phdc-test-manager.py [-h|--help] [OPTION]...

.. program:: phdc-test-manager.py

**Options**

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-peermode-options.txt
.. include:: ../examples/cli-reader-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt


phdc-test-agent.py p2p
======================

**Usage** ::

  $ phdc-test-agent.py p2p [-h|--help] [OPTION]...

.. program:: phdc-test-agent.py p2p

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

Connect, Associate and Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py p2p -t 1

Verify that the Agent can connect to the PHDC Manager, associate with
the IEEE Manager and finally release the association.

1. Establish communication distance between the Thermometer Peer Agent
   and the Manager device.

2. Connect to the ``urn:nfc:sn:phdc`` service.

3. Send a Thermometer Association Request.

4. Verify that the Manager sends a Thermometer Association Response.

5. Wait 3 seconds not sending any IEEE APDU, then send an Association
   Release Request.

6. Verify that the Manager sends an Association Release Response

7. Disconnect from the ``urn:nfc:sn:phdc`` service.

8. Move Agent and Manager device out of communication range.

Association after Release
^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py p2p -t 2

Verify that the Agent can again associate with the Manager after a
first association has been established and released.

1. Establish communication distance between the Thermometer Peer Agent
   and the Manager device.

2. Connect to the ``urn:nfc:sn:phdc`` service.

3. Send a Thermometer Association Request.

4. Verify that the Manager sends a Thermometer Association Response.

5. Disconnect from the ``urn:nfc:sn:phdc`` service.

6. Connect to the ``urn:nfc:sn:phdc`` service.

7. Send a Thermometer Association Request.

8. Verify that the Manager sends a Thermometer Association Response.

9. Send a Association Release Request.

10. Verify that the Manager sends a Association Release Response.

11. Disconnect from the ``urn:nfc:sn:phdc`` service.

12. Move Agent and Manager device out of communication range.

PHDC PDU Fragmentation and Reassembly
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py p2p -t 3

Verify that large PHDC PDUs are correctly fragmented and reassembled.

1. Establish communication distance between the Validation Agent and
   the Manager device.

2. Connect to the ``urn:nfc:xsn:nfc-forum.org:phdc-validation``
   service.

3. Send a PHDC PDU with an Information field of 2176 random octets.

4. Verify to receive an PHDC PDU that contains the same random octets
   in reversed order.

5. Disconnect from the ``urn:nfc:xsn:nfc-forum.org:phdc-validation``
   service.

6. Move Agent and Manager device out of communication range.

phdc-test-agent.py tag
======================

**Usage** ::

  $ phdc-test-agent.py tag [-h|--help] [OPTION]...

.. program:: phdc-test-agent.py tag

**Options**

.. option:: -t N, --test N

   Run test number *N*. May be set more than once.

.. option:: -T, --test-all

   Run all tests.

.. include:: ../examples/cli-general-options.txt
.. include:: ../examples/cli-debug-options.txt
.. include:: ../examples/cli-device-options.txt

Test Scenarios
--------------

Discovery, Association and Release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py tag -t 1

Verify that a PHDC Tag Agent is discovered by a PHDC Manager and IEEE
APDU exchange is successful.

1. Establish communication distance between the Thermometer Tag Agent
   and the Manager.

2. Send a Thermometer Association Request.

3. Verify that the Manager sends a Thermometer Association Response.

4. Wait 3 seconds not sending any IEEE APDU, then send an Association
   Release Request.

5. Verify that the Manager sends a Association Release Response.

6. Move Thermometer Tag Agent and Manager out of communication range.

Association after Release
^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py tag -t 2

Verify that a Tag Agent can again associate with the Manager after a
first association has been established and released.

1. Establish communication distance between the Thermometer Tag Agent
   and the Manager.

2. Send a Thermometer Association Request.

3. Verify that the Manager sends a Thermometer Association Response.

4. Send an Association Release Request.

5. Verify that the Manager sends a Association Release Response.

6. Wait 3 seconds not sending any IEEE APDU, then send a Thermometer
   Association Request.

7. Verify that the Manager sends a Thermometer Association Response.

8. Move Thermometer Tag Agent and Manager out of communication range.

Activation with invalid settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py tag -t 3

Verify that a PHDC Manager refuses communication with a Tag Agent that
presents an invalid PHDC record payload during activation.

1. Establish communication distance between the Tag Agent and the
   Manager.

2. Send the first PHDC PDU with invalid settings in one or any of the
   MC, LC or MD fields.

3. Verify that the Manager stops further PHDC communication with the
   Tag Agent.

Activation with invalid RFU value
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
::

   $ phdc-test-agent.py tag -t 4

Verify that a PHDC Manager communicates with a Tag Agent that presents
a PHDC record payload with an invalid RFU value during activation.

1. Establish communication distance between the Tag Agent and the
   Manager.

2. Send the first PHDC PDU with an invalid value in the RFU field.

3. Verify that the Manager continues PHDC communication with the Tag
   Agent.
