import logging
log = logging.getLogger()

import os
import sys
import time, string
sys.path.insert(1, os.path.split(sys.path[0])[0])
import nfc
import nfc.ndef

def make_printable(data):
    printable = string.digits + string.letters + string.punctuation + ' '
    return ''.join([c if c in printable else '.' for c in data])

def format_data(data):
    s = []
    for i in range(0, len(data), 16):
        s.append("  %04x: " % i)
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += make_printable(data[i:i+16])
    return '\n'.join(s)

def main():
    # find and initialize an NFC reader
    try: clf = nfc.ContactlessFrontend()
    except LookupError as e:
        print str(e)
        return
    try:
        while True:
            tag = clf.poll(general_bytes = None)
            if tag: 
                print tag
#                print str(tag.read(0)).encode('hex')
                if tag.ndef:
                    print "NDEF content"
                    print "  version   = %s" % tag.ndef.version
                    print "  writeable = %s" % ("no", "yes")[tag.ndef.writeable]
                    print "  capacity  = %d byte" % tag.ndef.capacity
                    print "  data size = %d byte" % len(tag.ndef.message)
                    if len(tag.ndef.message):
                        print format_data(tag.ndef.message)
                        message = nfc.ndef.Message(tag.ndef.message)
                        print "NDEF records"
                        for index, record in enumerate(message):
                            record.data = make_printable(record.data)
                            print "  [%d] type = %s" %(index, record.type)
                            print "  [%d] name = %s" %(index, record.name)
                            print "  [%d] data = %s" %(index, record.data)
                else: print "no NDEF"
                for rec in nfc.ndef.Message.fromstring(tag.ndef.message)[0]:
                    print rec
            time.sleep(1)
    except KeyboardInterrupt:
        print
    finally:
        clf.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    
    main()