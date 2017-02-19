=======
beam.py
=======

The **beam.py** example program uses the Simple NDEF Exchange Protocol
(SNEP) to send or receive NDEF messages to or from a peer device, in
most cases this will be a smartphone. The name *beam* is inspired by
*Android Beam* and thus **beam.py** will be able to receive most
content sent through *Android Beam*. It will not work for data that
*Android Beam* sends with connection handover to Bluetooth or Wi-Fi,
this may become a feature in a later version. Despite it's name,
**beam.py** works not only with Android phones but any NFC enabled
phone that implements the NFC Forum Default SNEP Server, such as
Blackberry and Windows Phone 8. ::

  $ beam.py [-h|--help] [OPTIONS] {send|recv} [-h] [OPTIONS]

.. program:: beam.py

.. contents::
   :local:

Options
=======

.. include:: cli-general-options.txt
.. include:: cli-peermode-options.txt
.. include:: cli-debug-options.txt
.. include:: cli-device-options.txt

Commands
========

send
----

Send an NDEF message to the peer device. The message depends on the
positional argument that follows the *send* command and additional
data. ::

  $ beam.py send [--timeit] {link,text,file,ndef} [-h] [OPTIONS]

.. program:: beam.py send

.. option:: --timeit

   Measure and print the time that was needed to send the message.

send link
^^^^^^^^^

Send a hyperlink embedded into a smartposter record. ::

  $ beam.py send link URI [TITLE]

.. program:: beam.py send link

.. option:: URI

   The resource identifier, for example ``http://nfcpy.org``.

.. option:: TITLE

   The smartposter title, for example ``"nfcpy project home"``.

send text
^^^^^^^^^

Send plain text embedded into an NDEF Text Record. The default
language identifier ``en`` can be changed with the ``--lang`` flag. ::

  $ beam.py send text TEXT [OPTIONS]

.. program:: beam.py send text

.. option:: TEXT

   The text string to send.

.. option:: --lang STRING

   The language code to use when constructing the NDEF Text Record.

send file
^^^^^^^^^

Send a data file. This will construct a single NDEF record with *type*
and *name* set to the file's mime type and path name, and the payload
containing the file content. Both record type and name can also be
explicitly set with the options ``-t`` and ``-n``, respectively. ::

  $ beam.py send file FILE [OPTIONS]

.. program:: beam.py send file

.. option:: FILE

   The file to send.

.. option:: -t STRING

   Set the record type. See :doc:`/topics/ndef` for how to specify record
   types in *nfcpy*.

.. option:: -n STRING

   Set the record name (identifier).

send ndef
^^^^^^^^^

Send an NDEF message read from file. The file may contain multiple
messages and if it does, then the strategy to select a specific
message for sending can be specified with the ``--select STRATEGY``
option. For strategies that select a different message per touch
beam.py must be called with the ``--loop`` flag. The strategies
``first``, ``last`` and ``random`` select the first, or last, or a
random message from FILE. The strategies ``next`` and ``cycle`` start
with the first message and then count up, the difference is that
``next`` stops at the last message while ``cycle`` continues with the
first. ::

  $ beam.py send ndef FILE [OPTIONS]

.. program:: beam.py send ndef

.. option:: FILE

   The file from which to read NDEF messages.

.. option:: --select STRATEGY

   The strategy for NDEF message selection, it may be one of ``first``,
   ``last``, ``next``, ``cycle``, ``random``.

recv
----

Receive an NDEF message from the peer device. The next positional
argument determines what is done with the received message. ::

  $ beam.py [OPTIONS] recv {print,save,echo,send} [-h] [OPTIONS]

recv print
^^^^^^^^^^

Print the received message to the standard output stream. ::

  $ beam.py recv print

.. program:: beam.py recv print

recv save
^^^^^^^^^

Save the received message into a file. If the file already exists the
message is appended. ::

  $ beam.py recv save FILE

.. program:: beam.py recv file

.. option:: FILE

   Name of the file to save messages received from the remote peer. If
   the file exists any new messages are appended.

recv echo
^^^^^^^^^

Receive a message and send it back to the peer device. ::

  $ beam.py recv echo

.. program:: beam.py recv echo

recv send
^^^^^^^^^

Receive a message and send back a corresponding message if such is
found in the *translations* file. The *translations* file must contain
an even number of NDEF messages which are sequentially read into
inbound/outbound pairs to form a translation table. If the receved
message corresponds to any of the translation table inbound messages
the corresponding outbound message is then sent back. ::

  $ beam.py [OPTIONS] recv send [-h] TRANSLATIONS

.. program:: beam.py recv send

.. option:: TRANSLATIONS

   A file with a sequence of NDEF messages.

Examples
========

Get a smartphone to open the nfcpy project page (which in fact just
points to the code repository and documentation). ::

  $ beam.py send link http://nfcpy.org "nfcpy project home"

Send the source file ``beam.py``. On an Android phone this should pop
up the "new tag collected" screen and show that a ``text/x-python``
media type has been received. ::

  $ beam.py send file beam.py

The file ``beam.py`` is about 11 KB and may take some time to
transfer, depending on the phone hardware and software. With a Google
Nexus 10 it takes as little as 500 milliseconds while a Nexus 4 won't
do it under 2.5 seconds. ::

  $ beam.py send --timeit file beam.py

Receive a single NDEF message from the peer device and save it to
*message.ndef* (note that if *message.ndef* exists the received data
will be appended): ::

  $ beam.py recv save message.ndef

With the ``--loop`` option it gets easy to collect messages into
a single file. ::

  $ beam.py --loop recv save collected.ndef

A file that contains a sequence of request/response message pairs can
be used to send a specific response message whenever the associated
request message was received. ::

  $ echo -n "this is a request message" > request.txt
  $ ndeftool.py pack -n '' request.txt -o request.ndef
  $ echo -n "this is my reponse message" > response.txt
  $ ndeftool.py pack -n '' response.txt -o response.ndef
  $ cat request.ndef response.ndef > translation.ndef
  $ beam.py recv send translation.ndef

