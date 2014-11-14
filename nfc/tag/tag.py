# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

def activate(clf, target):
    try:
        if type(target) == nfc.clf.TTA:
            if target.cfg[0] & 0x1F == 0 and target.cfg[1] & 0x0F == 0x0C:
                return activate_tt1(clf, target)
            if len(target.cfg) == 3:
                if target.cfg[2] & 0x64 == 0x00:
                    return activate_tt2(clf, target)
                if target.cfg[2] & 0x24 == 0x20:
                    return activate_tt4(clf, target)
        elif type(target) == nfc.clf.TTB:
            return activate_tt4(clf, target)
        elif type(target) == nfc.clf.TTF:
            return activate_tt3(clf, target)
    except nfc.clf.DigitalProtocolError:
        return None

def activate_tt1(clf, target):
    import nfc.tag.tt1
    return nfc.tag.tt1.Type1Tag(clf, target)
    
def activate_tt2(clf, target):
    import nfc.tag.tt2
    clf.set_communication_mode('', check_crc='OFF')
    if target.uid[0] == 0x04: # NXP
        import nfc.tag.tt2_nxp
        tag = nfc.tag.tt2_nxp.activate(clf, target)
        if tag is not None: return tag
    return nfc.tag.tt2.Type2Tag(clf, target)
    
def activate_tt3(clf, target):
    import nfc.tag.tt3, nfc.tag.tt3_sony
    tag = nfc.tag.tt3_sony.activate(clf, target)
    return tag if tag else nfc.tag.tt3.Type3Tag(clf, target)
    
def activate_tt4(clf, target):
    import nfc.tag.tt4
    return nfc.tag.tt4.Type4Tag(clf, target)
    
def emulate(clf, target):
    if type(target) == nfc.clf.TTA:
        log.debug("can't emulate TTA target'")
    elif type(target) == nfc.clf.TTB:
        log.debug("can't emulate TTB target'")
    elif type(target) == nfc.clf.TTF:
        import nfc.tag.tt3
        return nfc.tag.tt3.Type3TagEmulation(clf, target)
