=================
Use Case Examples
=================

This page is thought to give some ideas of what can be done with NFC
and *nfcpy*, but not as something that could be done but things that
have been done.

Treasure Hunt
=============

An NFC Forum member meeting is supposed to be an event where chances
are good to find people that have an NFC smartphone. With a demo of
*nfcpy* planned for the event what is closer than the idea to use it
for some fun experience. The basic idea is simple: Use *nfcpy* as a
terminal where to pick up a question that leads to finding a tag with
the correct answer.  Instruct people to read the answer and carry it
back to the *nfcpy* terminal to receive the next question. To make it
a bit more challenging the questions were phrased as riddles.

So how to send a question to the smartphone that depends on an answer
received before? The solution is to run a SNEP default server and wait
for a message put by the peer, which translates to using what is
called *Android Beam* on a well known platform. So if the phone beams
the correct answer then *nfcpy* can reverse beam the next question.
This functionality is part of the ``examples/beam.py`` program. ::

  $ examples/beam.py recv send challenge.ndef

The file ``challenge.ndef`` contains all the questions and answers as
a sequence of binary NDEF messages. The documentation calls this the
*translations* file and that is what it provides, for every possibly
to receive message it is the next message that is to be send.

The ``challenge.ndef`` file can be build with ``examples/ndeftool.py``
like so: ::

  $ echo -n "This is the start tag." > start.txt
  $ examples/ndeftool.py pack -n '' start.txt -o start.ndef

  $ echo -n "Here's the first question" > q1.txt
  $ examples/ndeftool.py pack -n '' q1.txt -o q1.ndef

  $ echo -n "This is the first answer" > a1.txt
  $ examples/ndeftool.py pack -n '' a1.txt -o a1.ndef

  $ echo -n "Here's the second question" > q2.txt
  $ examples/ndeftool.py pack -n '' q2.txt -o q2.ndef

  $ echo -n "This is the second answer" > a2.txt
  $ examples/ndeftool.py pack -n '' a2.txt -o a2.ndef

  $ echo -n "You finished the treasure hunt" > final.txt
  $ examples/ndeftool.py pack -n '' final.txt -o final.ndef

  $ cat start.ndef q1.ndef a1.ndef q2.ndef a2.ndef final.ndef > challenge.ndef

And the answer tags can then be created with ``examples/tagtool.py``:
::

  $ examples/tagtool.py load start.ndef
  $ examples/tagtool.py load a1.ndef
  $ examples/tagtool.py load a2.ndef

The final piece needed is a smartphone app that is able to read a tag
and later forward the message to the *nfcpy* terminal when touched. So
far only the NXP TagWriter for Android has the required functionality,
but it's quite difficult to use as needed. If someone wants to build a
better app for the treasure hunt, feel free to send a note. Here are
the basic instructions for using the TagWriter:

To read an answer from a tag

   Touch the tag and the text will be shown. Unfortunately longer text
   can not be read on this screen. The only way to read longer text is
   to go back to the main menu, then *History*, then *Browse history*,
   and finally press long on the item and choose *Edit* from the
   context menu that has opened.

To send an answer to *nfcpy*

   On the main menu go to *Share* and select the answer data set. Make
   sure the *Enable sharing* checkbox is set. Go back to the main menu
   screen and then touch the *nfcpy* reader. The answer is sent
   automatically and a next question, if available, will arrive.
   Again, if the question has a bit more text it can only be read
   in the history and by edit.
