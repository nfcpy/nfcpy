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

send
====

Send an NDEF message to the peer device. The message depends on the
positional argument that follows the *send* command and additional
data. ::

  $ beam.py [OPTIONS] send {link,text,file,ndef} [-h] [OPTIONS]


link
----

Send a hyperlink embedded into a smartposter record. ::

  $ beam.py [OPTIONS] send link URI [TITLE]

.. option:: URI

   The uniform resource identifier, for example ``http://nfcpy.org``.

.. option:: TITLE

   The smartposter title, for example ``"nfcpy project home"``.

text
----

Send plain text embedded into an NDEF Text Record. The default
language identifier ``en`` can be changed with the ``--lang`` flag. ::

  $ beam.py [OPTIONS] send text [-h] TEXT [OPTIONS]

.. option:: TEXT

   The text string to send.

.. option:: --lang STRING

   The language code to use when constructing the NDEF Text Record.

file
----

Send a data file. This will construct a single NDEF record with *type*
and *name* set to the file's mime type and path name, and the payload
containing the file content. Both record type and name can also be
explicitly set with the options ``-t`` and ``-n``, respectively. ::

  $ beam.py [OPTIONS] send file [-h] FILE [OPTIONS]

.. option:: FILE

   The file to send.

.. option:: -t STRING

   Set the record type. See :doc:`/topics/ndef` for how to specify record
   types in *nfcpy*.

.. option:: -n STRING

   Set the record name (identifier).

ndef
----

Send an NDEF message read from file. The file may contain multiple
messages and if it does, then the strategy to select a specific
message for sending can be specified with the ``--select STRATEGY``
option. For strategies that select a different message per touch
beam.py must be called with the ``--loop`` flag. The strategies
``first``, ``last`` and ``random`` select the first, last or a random
message from the file. The strategies ``next`` and ``cycle`` start
with the first message and then count up, the difference is that
``next`` stops at the last message while ``cycle`` continues with the
first. ::

  $ beam.py [OPTIONS] send ndef [-h] FILE [OPTIONS]

.. option:: FILE

   The file from which to read NDEF messages.

.. option:: --select STRATEGY

   The strategy for NDEF message selection, it may be one of ``first``,
   ``last``, ``next``, ``cycle``, ``random``.

recv
====

Receive an NDEF message from the peer device. The next positional
argument determines what is done with the received message. ::

  $ beam.py [OPTIONS] recv {print,save,echo,send} [-h] [OPTIONS]

print
-----

Print the received message to the standard output stream. ::

  $ beam.py [OPTIONS] recv print [-h]

save
----

Save the received message into a file. If the file already exists the
message is appended. ::

  $ beam.py [OPTIONS] recv save [-h] FILE

.. option:: FILE

   Name of the file to save to. If this is a dash ``-`` then data is
   written to the standard output stream.

echo
----

Receive a message and send it back to the peer device. ::

  $ beam.py [OPTIONS] recv echo [-h]

send
----

Receive a message and send back a corresponding message if such is
found in the *translations* file. The *translations* file must contain
an even number of NDEF messages which are sequentially read into
inbound/outbound pairs to form a translation table. If the receved
message corresponds to any of the translation table inbound messages
the corresponding outbound message is then sent back. ::

  $ beam.py [OPTIONS] recv send [-h] TRANSLATIONS

.. option:: TRANSLATIONS

   A file with a sequence of NDEF messages.
