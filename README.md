# ASAP: Algorithm Substitution Attacks on Protocols

This repository contains the proof of concept code patches for the ASA attacks against TLS, WireGuard and Signal, as shown in the work from {*insert authors and link*}.

The given modifications are designed to illustrate the scale of necessary code changes. To support reproducibility, they also contain various debug outputs and the original benchmarking gadgets. There is no attempt to hide the attacks.

The patches are based on the following revisions:
- OpenSSL: https://github.com/openssl/openssl/tree/3952c5a312bde6479578dcbc162ec6ce77318924
- WireGuard: https://git.zx2c4.com/wireguard-linux-compat/tree/?id=8118c247a75ae95169f0a9a539dfc661ffda8bc5
- Signal-Desktop: https://github.com/signalapp/Signal-Desktop/tree/943cb3eb1a4edbb0991f69ee4a885f7800ba5dfc