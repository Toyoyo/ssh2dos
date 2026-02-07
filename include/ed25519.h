#ifndef _ED25519_H
#define _ED25519_H

/*
 * Ed25519 signature verification (RFC 8032 Section 5.1.7)
 *
 * Returns 1 on success, 0 on failure.
 */
int ed25519_verify(const unsigned char *public_key,
                   const unsigned char *signature,
                   const unsigned char *message,
                   unsigned long message_len);

#endif
