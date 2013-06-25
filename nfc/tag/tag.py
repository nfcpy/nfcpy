# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------

import logging
log = logging.getLogger(__name__)

import nfc.clf
from tt1 import Type1Tag
from tt2 import Type2Tag
from tt3 import Type3Tag, Type3TagEmulation
from tt4 import Type4Tag

def activate(clf, target):
    try:
        if type(target) == nfc.clf.TTA:
            if target.cfg[0] & 0x1F == 0 and target.cfg[1] & 0x0F == 0x0C:
                return Type1Tag(clf, target)
            if len(target.cfg) == 3:
                if target.cfg[2] & 0x64 == 0x00:
                    return Type2Tag(clf, target)
                if target.cfg[2] & 0x24 == 0x20:
                    return Type4Tag(clf, target)
        elif type(target) == nfc.clf.TTB:
            return Type2Tag(clf, target)
        elif type(target) == nfc.clf.TTF:
            return Type3Tag(clf, target)
    except nfc.clf.DigitalProtocolError:
        return None

def emulate(clf, target):
    if type(target) == nfc.clf.TTA:
        log.debug("can't emulate TTA target'")
    elif type(target) == nfc.clf.TTB:
        log.debug("can't emulate TTB target'")
    elif type(target) == nfc.clf.TTF:
        return Type3TagEmulation(clf, target)
