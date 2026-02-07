#ifndef _CURVE25519_H
#define _CURVE25519_H

void curve25519_scalarmult(unsigned char *q,
                           const unsigned char *n,
                           const unsigned char *p);
#endif
