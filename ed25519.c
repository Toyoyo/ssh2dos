/* ed25519.c - Self-contained Ed25519 signature verification
 *
 * Based on the ref10 implementation from SUPERCOP by
 * Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe,
 * Bo-Yin Yang. Public domain.
 *
 * Adapted for Watcom C / SSH2DOS:
 *  - C89 compatible (declarations at block start)
 *  - Uses __int64 for 64-bit intermediates (Watcom C extension)
 *  - Only verification (no signing)
 *  - Uses existing SHA-512 from sshsh512.c
 */

#include <string.h>
#include "sshsha.h"
#include "ed25519.h"

typedef __int64 i64;

typedef struct { long v[10]; } fe;

static void fe_0(fe *h)
{
    int i;
    for (i = 0; i < 10; i++) h->v[i] = 0;
}

static void fe_1(fe *h)
{
    h->v[0] = 1;
    h->v[1] = 0; h->v[2] = 0; h->v[3] = 0; h->v[4] = 0;
    h->v[5] = 0; h->v[6] = 0; h->v[7] = 0; h->v[8] = 0; h->v[9] = 0;
}

static void fe_copy(fe *h, const fe *f)
{
    int i;
    for (i = 0; i < 10; i++) h->v[i] = f->v[i];
}

static void fe_add(fe *h, const fe *f, const fe *g)
{
    int i;
    for (i = 0; i < 10; i++) h->v[i] = f->v[i] + g->v[i];
}

static void fe_sub(fe *h, const fe *f, const fe *g)
{
    int i;
    for (i = 0; i < 10; i++) h->v[i] = f->v[i] - g->v[i];
}

static void fe_neg(fe *h, const fe *f)
{
    int i;
    for (i = 0; i < 10; i++) h->v[i] = -f->v[i];
}

static void fe_tobytes(unsigned char *s, const fe *h);

static long fe_isnegative(const fe *f)
{
    unsigned char s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe *f)
{
    unsigned char s[32];
    unsigned char r = 0;
    int i;
    fe_tobytes(s, f);
    for (i = 0; i < 32; i++) r |= s[i];
    return r != 0;
}

static unsigned long load_3(const unsigned char *in)
{
    unsigned long result;
    result = (unsigned long)in[0];
    result |= ((unsigned long)in[1]) << 8;
    result |= ((unsigned long)in[2]) << 16;
    return result;
}

static unsigned long load_4(const unsigned char *in)
{
    unsigned long result;
    result = (unsigned long)in[0];
    result |= ((unsigned long)in[1]) << 8;
    result |= ((unsigned long)in[2]) << 16;
    result |= ((unsigned long)in[3]) << 24;
    return result;
}

static void fe_frombytes(fe *h, const unsigned char *s)
{
    i64 h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;
    i64 carry0, carry1, carry2, carry3, carry4;
    i64 carry5, carry6, carry7, carry8, carry9;

    h0 = (i64)load_4(s);
    h1 = (i64)load_3(s + 4) << 6;
    h2 = (i64)load_3(s + 7) << 5;
    h3 = (i64)load_3(s + 10) << 3;
    h4 = (i64)load_3(s + 13) << 2;
    h5 = (i64)load_4(s + 16);
    h6 = (i64)load_3(s + 20) << 7;
    h7 = (i64)load_3(s + 23) << 5;
    h8 = (i64)load_3(s + 26) << 4;
    h9 = (i64)(load_3(s + 29) & 8388607) << 2;

    carry9 = (h9 + (i64)(1L << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    carry1 = (h1 + (i64)(1L << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    carry3 = (h3 + (i64)(1L << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    carry5 = (h5 + (i64)(1L << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    carry7 = (h7 + (i64)(1L << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    carry0 = (h0 + (i64)(1L << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    carry2 = (h2 + (i64)(1L << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    carry4 = (h4 + (i64)(1L << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    carry6 = (h6 + (i64)(1L << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    carry8 = (h8 + (i64)(1L << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

    h->v[0] = (long)h0; h->v[1] = (long)h1; h->v[2] = (long)h2;
    h->v[3] = (long)h3; h->v[4] = (long)h4; h->v[5] = (long)h5;
    h->v[6] = (long)h6; h->v[7] = (long)h7; h->v[8] = (long)h8;
    h->v[9] = (long)h9;
}

static void fe_tobytes(unsigned char *s, const fe *h)
{
    long h0, h1, h2, h3, h4, h5, h6, h7, h8, h9;
    long q;

    h0 = h->v[0]; h1 = h->v[1]; h2 = h->v[2]; h3 = h->v[3]; h4 = h->v[4];
    h5 = h->v[5]; h6 = h->v[6]; h7 = h->v[7]; h8 = h->v[8]; h9 = h->v[9];

    q = (19 * h9 + (((long)1) << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    h0 += 19 * q;

    h1 += h0 >> 26; h0 &= 0x3ffffff;
    h2 += h1 >> 25; h1 &= 0x1ffffff;
    h3 += h2 >> 26; h2 &= 0x3ffffff;
    h4 += h3 >> 25; h3 &= 0x1ffffff;
    h5 += h4 >> 26; h4 &= 0x3ffffff;
    h6 += h5 >> 25; h5 &= 0x1ffffff;
    h7 += h6 >> 26; h6 &= 0x3ffffff;
    h8 += h7 >> 25; h7 &= 0x1ffffff;
    h9 += h8 >> 26; h8 &= 0x3ffffff;
                     h9 &= 0x1ffffff;

    s[0]  = (unsigned char)(h0);
    s[1]  = (unsigned char)(h0 >> 8);
    s[2]  = (unsigned char)(h0 >> 16);
    s[3]  = (unsigned char)((h0 >> 24) | (h1 << 2));
    s[4]  = (unsigned char)(h1 >> 6);
    s[5]  = (unsigned char)(h1 >> 14);
    s[6]  = (unsigned char)((h1 >> 22) | (h2 << 3));
    s[7]  = (unsigned char)(h2 >> 5);
    s[8]  = (unsigned char)(h2 >> 13);
    s[9]  = (unsigned char)((h2 >> 21) | (h3 << 5));
    s[10] = (unsigned char)(h3 >> 3);
    s[11] = (unsigned char)(h3 >> 11);
    s[12] = (unsigned char)((h3 >> 19) | (h4 << 6));
    s[13] = (unsigned char)(h4 >> 2);
    s[14] = (unsigned char)(h4 >> 10);
    s[15] = (unsigned char)(h4 >> 18);
    s[16] = (unsigned char)(h5);
    s[17] = (unsigned char)(h5 >> 8);
    s[18] = (unsigned char)(h5 >> 16);
    s[19] = (unsigned char)((h5 >> 24) | (h6 << 1));
    s[20] = (unsigned char)(h6 >> 7);
    s[21] = (unsigned char)(h6 >> 15);
    s[22] = (unsigned char)((h6 >> 23) | (h7 << 3));
    s[23] = (unsigned char)(h7 >> 5);
    s[24] = (unsigned char)(h7 >> 13);
    s[25] = (unsigned char)((h7 >> 21) | (h8 << 4));
    s[26] = (unsigned char)(h8 >> 4);
    s[27] = (unsigned char)(h8 >> 12);
    s[28] = (unsigned char)((h8 >> 20) | (h9 << 6));
    s[29] = (unsigned char)(h9 >> 2);
    s[30] = (unsigned char)(h9 >> 10);
    s[31] = (unsigned char)(h9 >> 18);
}

static void fe_mul(fe *h, const fe *f, const fe *g)
{
    long f0,f1,f2,f3,f4,f5,f6,f7,f8,f9;
    long g0,g1,g2,g3,g4,g5,g6,g7,g8,g9;
    long g1_19,g2_19,g3_19,g4_19,g5_19,g6_19,g7_19,g8_19,g9_19;
    i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    i64 carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;

    f0=f->v[0]; f1=f->v[1]; f2=f->v[2]; f3=f->v[3]; f4=f->v[4];
    f5=f->v[5]; f6=f->v[6]; f7=f->v[7]; f8=f->v[8]; f9=f->v[9];
    g0=g->v[0]; g1=g->v[1]; g2=g->v[2]; g3=g->v[3]; g4=g->v[4];
    g5=g->v[5]; g6=g->v[6]; g7=g->v[7]; g8=g->v[8]; g9=g->v[9];

    g1_19=19*g1; g2_19=19*g2; g3_19=19*g3;
    g4_19=19*g4; g5_19=19*g5; g6_19=19*g6;
    g7_19=19*g7; g8_19=19*g8; g9_19=19*g9;

    {
    long f1_2=2*f1, f3_2=2*f3, f5_2=2*f5, f7_2=2*f7, f9_2=2*f9;

    h0=(i64)f0*g0 + (i64)f1_2*g9_19 + (i64)f2*g8_19 + (i64)f3_2*g7_19 + (i64)f4*g6_19
      +(i64)f5_2*g5_19 + (i64)f6*g4_19 + (i64)f7_2*g3_19 + (i64)f8*g2_19 + (i64)f9_2*g1_19;
    h1=(i64)f0*g1 + (i64)f1*g0 + (i64)f2*g9_19 + (i64)f3*g8_19 + (i64)f4*g7_19
      +(i64)f5*g6_19 + (i64)f6*g5_19 + (i64)f7*g4_19 + (i64)f8*g3_19 + (i64)f9*g2_19;
    h2=(i64)f0*g2 + (i64)f1_2*g1 + (i64)f2*g0 + (i64)f3_2*g9_19 + (i64)f4*g8_19
      +(i64)f5_2*g7_19 + (i64)f6*g6_19 + (i64)f7_2*g5_19 + (i64)f8*g4_19 + (i64)f9_2*g3_19;
    h3=(i64)f0*g3 + (i64)f1*g2 + (i64)f2*g1 + (i64)f3*g0 + (i64)f4*g9_19
      +(i64)f5*g8_19 + (i64)f6*g7_19 + (i64)f7*g6_19 + (i64)f8*g5_19 + (i64)f9*g4_19;
    h4=(i64)f0*g4 + (i64)f1_2*g3 + (i64)f2*g2 + (i64)f3_2*g1 + (i64)f4*g0
      +(i64)f5_2*g9_19 + (i64)f6*g8_19 + (i64)f7_2*g7_19 + (i64)f8*g6_19 + (i64)f9_2*g5_19;
    h5=(i64)f0*g5 + (i64)f1*g4 + (i64)f2*g3 + (i64)f3*g2 + (i64)f4*g1
      +(i64)f5*g0 + (i64)f6*g9_19 + (i64)f7*g8_19 + (i64)f8*g7_19 + (i64)f9*g6_19;
    h6=(i64)f0*g6 + (i64)f1_2*g5 + (i64)f2*g4 + (i64)f3_2*g3 + (i64)f4*g2
      +(i64)f5_2*g1 + (i64)f6*g0 + (i64)f7_2*g9_19 + (i64)f8*g8_19 + (i64)f9_2*g7_19;
    h7=(i64)f0*g7 + (i64)f1*g6 + (i64)f2*g5 + (i64)f3*g4 + (i64)f4*g3
      +(i64)f5*g2 + (i64)f6*g1 + (i64)f7*g0 + (i64)f8*g9_19 + (i64)f9*g8_19;
    h8=(i64)f0*g8 + (i64)f1_2*g7 + (i64)f2*g6 + (i64)f3_2*g5 + (i64)f4*g4
      +(i64)f5_2*g3 + (i64)f6*g2 + (i64)f7_2*g1 + (i64)f8*g0 + (i64)f9_2*g9_19;
    h9=(i64)f0*g9 + (i64)f1*g8 + (i64)f2*g7 + (i64)f3*g6 + (i64)f4*g5
      +(i64)f5*g4 + (i64)f6*g3 + (i64)f7*g2 + (i64)f8*g1 + (i64)f9*g0;
    }

    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(i64)(1L<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(i64)(1L<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(i64)(1L<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(i64)(1L<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(i64)(1L<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(i64)(1L<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(i64)(1L<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(i64)(1L<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h->v[0]=(long)h0; h->v[1]=(long)h1; h->v[2]=(long)h2;
    h->v[3]=(long)h3; h->v[4]=(long)h4; h->v[5]=(long)h5;
    h->v[6]=(long)h6; h->v[7]=(long)h7; h->v[8]=(long)h8;
    h->v[9]=(long)h9;
}

static void fe_sq(fe *h, const fe *f)
{
    long f0,f1,f2,f3,f4,f5,f6,f7,f8,f9;
    long f0_2,f1_2,f2_2,f3_2,f4_2,f5_2,f6_2,f7_2;
    long f5_38,f6_19,f7_38,f8_19,f9_38;
    i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    i64 carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;

    f0=f->v[0]; f1=f->v[1]; f2=f->v[2]; f3=f->v[3]; f4=f->v[4];
    f5=f->v[5]; f6=f->v[6]; f7=f->v[7]; f8=f->v[8]; f9=f->v[9];

    f0_2=2*f0; f1_2=2*f1; f2_2=2*f2; f3_2=2*f3;
    f4_2=2*f4; f5_2=2*f5; f6_2=2*f6; f7_2=2*f7;
    f5_38=38*f5; f6_19=19*f6; f7_38=38*f7;
    f8_19=19*f8; f9_38=38*f9;

    h0=(i64)f0*f0 + (i64)f1_2*f9_38 + (i64)f2_2*f8_19 + (i64)f3_2*f7_38 + (i64)f4_2*f6_19 + (i64)f5*f5_38;
    h1=(i64)f0_2*f1 + (i64)f2*f9_38 + (i64)f3_2*f8_19 + (i64)f4*f7_38 + (i64)f5_2*f6_19;
    h2=(i64)f0_2*f2 + (i64)f1_2*f1 + (i64)f3_2*f9_38 + (i64)f4_2*f8_19 + (i64)f5_2*f7_38 + (i64)f6*f6_19;
    h3=(i64)f0_2*f3 + (i64)f1_2*f2 + (i64)f4*f9_38 + (i64)f5_2*f8_19 + (i64)f6*f7_38;
    h4=(i64)f0_2*f4 + (i64)f1_2*f3_2 + (i64)f2*f2 + (i64)f5_2*f9_38 + (i64)f6_2*f8_19 + (i64)f7*f7_38;
    h5=(i64)f0_2*f5 + (i64)f1_2*f4 + (i64)f2_2*f3 + (i64)f6*f9_38 + (i64)f7_2*f8_19;
    h6=(i64)f0_2*f6 + (i64)f1_2*f5_2 + (i64)f2_2*f4 + (i64)f3_2*f3 + (i64)f7_2*f9_38 + (i64)f8*f8_19;
    h7=(i64)f0_2*f7 + (i64)f1_2*f6 + (i64)f2_2*f5 + (i64)f3_2*f4 + (i64)f8*f9_38;
    h8=(i64)f0_2*f8 + (i64)f1_2*f7_2 + (i64)f2_2*f6 + (i64)f3_2*f5_2 + (i64)f4*f4 + (i64)f9*f9_38;
    h9=(i64)f0_2*f9 + (i64)f1_2*f8 + (i64)f2_2*f7 + (i64)f3_2*f6 + (i64)f4_2*f5;

    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(i64)(1L<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(i64)(1L<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(i64)(1L<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(i64)(1L<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(i64)(1L<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(i64)(1L<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(i64)(1L<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(i64)(1L<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h->v[0]=(long)h0; h->v[1]=(long)h1; h->v[2]=(long)h2;
    h->v[3]=(long)h3; h->v[4]=(long)h4; h->v[5]=(long)h5;
    h->v[6]=(long)h6; h->v[7]=(long)h7; h->v[8]=(long)h8;
    h->v[9]=(long)h9;
}

static void fe_sq2(fe *h, const fe *f)
{
    long f0,f1,f2,f3,f4,f5,f6,f7,f8,f9;
    long f0_2,f1_2,f2_2,f3_2,f4_2,f5_2,f6_2,f7_2;
    long f5_38,f6_19,f7_38,f8_19,f9_38;
    i64 h0,h1,h2,h3,h4,h5,h6,h7,h8,h9;
    i64 carry0,carry1,carry2,carry3,carry4,carry5,carry6,carry7,carry8,carry9;

    f0=f->v[0]; f1=f->v[1]; f2=f->v[2]; f3=f->v[3]; f4=f->v[4];
    f5=f->v[5]; f6=f->v[6]; f7=f->v[7]; f8=f->v[8]; f9=f->v[9];

    f0_2=2*f0; f1_2=2*f1; f2_2=2*f2; f3_2=2*f3;
    f4_2=2*f4; f5_2=2*f5; f6_2=2*f6; f7_2=2*f7;
    f5_38=38*f5; f6_19=19*f6; f7_38=38*f7;
    f8_19=19*f8; f9_38=38*f9;

    h0=(i64)f0*f0 + (i64)f1_2*f9_38 + (i64)f2_2*f8_19 + (i64)f3_2*f7_38 + (i64)f4_2*f6_19 + (i64)f5*f5_38;
    h1=(i64)f0_2*f1 + (i64)f2*f9_38 + (i64)f3_2*f8_19 + (i64)f4*f7_38 + (i64)f5_2*f6_19;
    h2=(i64)f0_2*f2 + (i64)f1_2*f1 + (i64)f3_2*f9_38 + (i64)f4_2*f8_19 + (i64)f5_2*f7_38 + (i64)f6*f6_19;
    h3=(i64)f0_2*f3 + (i64)f1_2*f2 + (i64)f4*f9_38 + (i64)f5_2*f8_19 + (i64)f6*f7_38;
    h4=(i64)f0_2*f4 + (i64)f1_2*f3_2 + (i64)f2*f2 + (i64)f5_2*f9_38 + (i64)f6_2*f8_19 + (i64)f7*f7_38;
    h5=(i64)f0_2*f5 + (i64)f1_2*f4 + (i64)f2_2*f3 + (i64)f6*f9_38 + (i64)f7_2*f8_19;
    h6=(i64)f0_2*f6 + (i64)f1_2*f5_2 + (i64)f2_2*f4 + (i64)f3_2*f3 + (i64)f7_2*f9_38 + (i64)f8*f8_19;
    h7=(i64)f0_2*f7 + (i64)f1_2*f6 + (i64)f2_2*f5 + (i64)f3_2*f4 + (i64)f8*f9_38;
    h8=(i64)f0_2*f8 + (i64)f1_2*f7_2 + (i64)f2_2*f6 + (i64)f3_2*f5_2 + (i64)f4*f4 + (i64)f9*f9_38;
    h9=(i64)f0_2*f9 + (i64)f1_2*f8 + (i64)f2_2*f7 + (i64)f3_2*f6 + (i64)f4_2*f5;

    h0+=h0; h1+=h1; h2+=h2; h3+=h3; h4+=h4;
    h5+=h5; h6+=h6; h7+=h7; h8+=h8; h9+=h9;

    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry1=(h1+(i64)(1L<<24))>>25; h2+=carry1; h1-=carry1<<25;
    carry5=(h5+(i64)(1L<<24))>>25; h6+=carry5; h5-=carry5<<25;
    carry2=(h2+(i64)(1L<<25))>>26; h3+=carry2; h2-=carry2<<26;
    carry6=(h6+(i64)(1L<<25))>>26; h7+=carry6; h6-=carry6<<26;
    carry3=(h3+(i64)(1L<<24))>>25; h4+=carry3; h3-=carry3<<25;
    carry7=(h7+(i64)(1L<<24))>>25; h8+=carry7; h7-=carry7<<25;
    carry4=(h4+(i64)(1L<<25))>>26; h5+=carry4; h4-=carry4<<26;
    carry8=(h8+(i64)(1L<<25))>>26; h9+=carry8; h8-=carry8<<26;
    carry9=(h9+(i64)(1L<<24))>>25; h0+=carry9*19; h9-=carry9<<25;
    carry0=(h0+(i64)(1L<<25))>>26; h1+=carry0; h0-=carry0<<26;

    h->v[0]=(long)h0; h->v[1]=(long)h1; h->v[2]=(long)h2;
    h->v[3]=(long)h3; h->v[4]=(long)h4; h->v[5]=(long)h5;
    h->v[6]=(long)h6; h->v[7]=(long)h7; h->v[8]=(long)h8;
    h->v[9]=(long)h9;
}

static void fe_invert(fe *out, const fe *z)
{
    fe t0, t1, t2, t3;
    int i;

    fe_sq(&t0, z);
    fe_sq(&t1, &t0);
    fe_sq(&t1, &t1);
    fe_mul(&t1, z, &t1);
    fe_mul(&t0, &t0, &t1);
    fe_sq(&t2, &t0);
    fe_mul(&t1, &t1, &t2);
    fe_sq(&t2, &t1);
    for (i = 1; i < 5; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    fe_sq(&t2, &t1);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);
    fe_sq(&t3, &t2);
    for (i = 1; i < 20; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);
    fe_sq(&t2, &t2);
    for (i = 1; i < 10; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    fe_sq(&t2, &t1);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2);
    fe_mul(&t2, &t2, &t1);
    fe_sq(&t3, &t2);
    for (i = 1; i < 100; i++) fe_sq(&t3, &t3);
    fe_mul(&t2, &t3, &t2);
    fe_sq(&t2, &t2);
    for (i = 1; i < 50; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    fe_sq(&t1, &t1);
    for (i = 1; i < 5; i++) fe_sq(&t1, &t1);
    fe_mul(out, &t1, &t0);
}

static void fe_pow2523(fe *out, const fe *z)
{
    fe t0, t1, t2;
    int i;

    fe_sq(&t0, z);
    fe_sq(&t1, &t0);
    fe_sq(&t1, &t1);
    fe_mul(&t1, z, &t1);
    fe_mul(&t0, &t0, &t1);
    fe_sq(&t0, &t0);
    fe_mul(&t0, &t1, &t0);
    fe_sq(&t1, &t0);
    for (i = 1; i < 5; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);
    fe_sq(&t1, &t0);
    for (i = 1; i < 10; i++) fe_sq(&t1, &t1);
    fe_mul(&t1, &t1, &t0);
    fe_sq(&t2, &t1);
    for (i = 1; i < 20; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    fe_sq(&t1, &t1);
    for (i = 1; i < 10; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);
    fe_sq(&t1, &t0);
    for (i = 1; i < 50; i++) fe_sq(&t1, &t1);
    fe_mul(&t1, &t1, &t0);
    fe_sq(&t2, &t1);
    for (i = 1; i < 100; i++) fe_sq(&t2, &t2);
    fe_mul(&t1, &t2, &t1);
    fe_sq(&t1, &t1);
    for (i = 1; i < 50; i++) fe_sq(&t1, &t1);
    fe_mul(&t0, &t1, &t0);
    fe_sq(&t0, &t0);
    fe_sq(&t0, &t0);
    fe_mul(out, &t0, z);
}

/* Group element types */
typedef struct { fe X; fe Y; fe Z; } ge_p2;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p1p1;
typedef struct { fe yplusx; fe yminusx; fe xy2d; } ge_precomp;
typedef struct { fe YplusX; fe YminusX; fe Z; fe T2d; } ge_cached;

static const fe ed25519_d = {{-10913610,13857413,-15372611,6949391,114729,-8787816,-6275908,-3247719,-18696448,-12055116}};
static const fe ed25519_d2 = {{-21827239,-5839606,-30745221,13898782,229458,15978800,-12551817,-6495438,29715968,9444199}};
static const fe ed25519_sqrtm1 = {{-32595792,-7943725,9377950,3500415,12389472,-272473,-25146209,-2005654,326686,11406482}};

/* Precomputed odd multiples of the basepoint for verification:
 * Bi[i] = (2*i+1)*B in ge_precomp format (yplusx, yminusx, xy2d) */
static const ge_precomp Bi[8] = {
 {{25967493,-14356035,29566456,3660896,-12694345,4014787,27544626,-11754271,-6079156,2047605},{-12545711,934262,-2722910,3049990,-727428,9406986,12720692,5043384,19500929,-15469378},{-8738181,4489570,9688441,-14785194,10184609,-12363380,29287919,11864899,-24514362,-4438546}},
 {{15636291,-9688557,24204773,-7912398,616977,-16685262,27787600,-14772189,28944400,-1550024},{16568933,4717097,-11556148,-1102322,15682896,-11807043,16354577,-11775962,7689662,11199574},{30464156,-5976125,-11779434,-15670865,23220365,15915852,7512774,10017326,-17749093,-9920357}},
 {{10861363,11473154,27284546,1981175,-30064349,12577861,32867885,14515107,-15438304,10819380},{4708026,6336745,20377586,9066809,-11272109,6594696,-25653668,12483688,-12668491,5581306},{19563160,16186464,-29386857,4097519,10237984,-4348115,28542350,13850243,-23678021,-15815942}},
 {{5153746,9909285,1723747,-2777874,30523605,5516873,19480852,5230134,-23952439,-15175766},{-30269007,-3463509,7665486,10083793,28475525,1649722,20654025,16520125,30598449,7715701},{28881845,14381568,9657904,3680757,-20181635,7843316,-31400660,1370708,29794553,-1409300}},
 {{-22518993,-6692182,14201702,-8745502,-23510406,8844726,18474211,-1361450,-13062696,13821877},{-6455177,-7839871,3374702,-4740862,-27098617,-10571707,31655028,-7212327,18853322,-14220951},{4566830,-12963868,-28974889,-12240689,-7602672,-2830569,-8514358,-10431137,2207753,-3209784}},
 {{-25154831,-4185821,29681144,7868801,-6854661,-9423865,-12437364,-663000,-31111463,-16132436},{25576264,-2703214,7349804,-11814844,16472782,9300885,3844789,15725684,171356,6466918},{23103977,13316479,9739013,-16149481,817875,-15038942,8965339,-14088058,-30714912,16193877}},
 {{-33521811,3180713,-2394130,14003687,-16903474,-16270840,17238398,4729455,-18074513,9256800},{-25182317,-4174131,32336398,5036987,-21236817,11360617,22616405,9761698,-19827198,630305},{-13720693,2639453,-24237460,-7406481,9494427,-5774029,-6554551,-15960994,-2449256,-14291300}},
 {{-3151181,-5046075,9282714,6866145,-31907062,-863023,-18940575,15033784,25105118,-7894876},{-24326370,15950226,-31801215,-14592823,-11662737,-5090925,1573892,-2625887,2198790,-15804619},{-3099351,10324967,-2241613,7453183,-5446979,-2735503,-13812022,-16236442,-32461234,-12290683}}
};

/* (large base table removed - only Bi needed for verification) */

/* Point format conversions */
static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p)
{
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p)
{
    fe_mul(&r->X, &p->X, &p->T);
    fe_mul(&r->Y, &p->Y, &p->Z);
    fe_mul(&r->Z, &p->Z, &p->T);
    fe_mul(&r->T, &p->X, &p->Y);
}

static void ge_p2_0(ge_p2 *h)
{
    fe_0(&h->X);
    fe_1(&h->Y);
    fe_1(&h->Z);
}

static void ge_p3_to_cached(ge_cached *r, const ge_p3 *p)
{
    fe_add(&r->YplusX, &p->Y, &p->X);
    fe_sub(&r->YminusX, &p->Y, &p->X);
    fe_copy(&r->Z, &p->Z);
    fe_mul(&r->T2d, &p->T, &ed25519_d2);
}

static void ge_p3_to_p2(ge_p2 *r, const ge_p3 *p)
{
    fe_copy(&r->X, &p->X);
    fe_copy(&r->Y, &p->Y);
    fe_copy(&r->Z, &p->Z);
}

/* r = 2 * p (p2 -> p1p1) */
static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p)
{
    fe t0;
    fe_sq(&r->X, &p->X);
    fe_sq(&r->Z, &p->Y);
    fe_sq2(&r->T, &p->Z);
    fe_add(&r->Y, &p->X, &p->Y);
    fe_sq(&t0, &r->Y);
    fe_add(&r->Y, &r->Z, &r->X);
    fe_sub(&r->Z, &r->Z, &r->X);
    fe_sub(&r->X, &t0, &r->Y);
    fe_sub(&r->T, &r->T, &r->Z);
}

/* r = p + q (p3 + precomp -> p1p1) */
static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->yplusx);
    fe_mul(&r->Y, &r->Y, &q->yminusx);
    fe_mul(&r->T, &q->xy2d, &p->T);
    fe_add(&t0, &p->Z, &p->Z);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_add(&r->Z, &t0, &r->T);
    fe_sub(&r->T, &t0, &r->T);
}

/* r = p - q (p3 - precomp -> p1p1) */
static void ge_msub(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->yminusx);
    fe_mul(&r->Y, &r->Y, &q->yplusx);
    fe_mul(&r->T, &q->xy2d, &p->T);
    fe_add(&t0, &p->Z, &p->Z);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_sub(&r->Z, &t0, &r->T);
    fe_add(&r->T, &t0, &r->T);
}

/* r = p + q (p3 + cached -> p1p1) */
static void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->YplusX);
    fe_mul(&r->Y, &r->Y, &q->YminusX);
    fe_mul(&r->T, &q->T2d, &p->T);
    fe_mul(&t0, &p->Z, &q->Z);
    fe_add(&t0, &t0, &t0);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_add(&r->Z, &t0, &r->T);
    fe_sub(&r->T, &t0, &r->T);
}

/* r = p - q (p3 - cached -> p1p1) */
static void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q)
{
    fe t0;
    fe_add(&r->X, &p->Y, &p->X);
    fe_sub(&r->Y, &p->Y, &p->X);
    fe_mul(&r->Z, &r->X, &q->YminusX);
    fe_mul(&r->Y, &r->Y, &q->YplusX);
    fe_mul(&r->T, &q->T2d, &p->T);
    fe_mul(&t0, &p->Z, &q->Z);
    fe_add(&t0, &t0, &t0);
    fe_sub(&r->X, &r->Z, &r->Y);
    fe_add(&r->Y, &r->Z, &r->Y);
    fe_sub(&r->Z, &t0, &r->T);
    fe_add(&r->T, &t0, &r->T);
}

/* Decompress an Edwards point from 32 bytes, negate x.
 * Returns 0 on success, -1 on failure. */
static int ge_frombytes_negate_vartime(ge_p3 *h, const unsigned char *s)
{
    fe u, v, v3, vxx, check;

    fe_frombytes(&h->Y, s);
    fe_1(&h->Z);
    fe_sq(&u, &h->Y);
    fe_mul(&v, &u, &ed25519_d);
    fe_sub(&u, &u, &h->Z);   /* u = y^2 - 1 */
    fe_add(&v, &v, &h->Z);   /* v = d*y^2 + 1 */

    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);     /* v3 = v^3 */
    fe_sq(&h->X, &v3);
    fe_mul(&h->X, &h->X, &v);
    fe_mul(&h->X, &h->X, &u); /* x = uv^7 */

    fe_pow2523(&h->X, &h->X); /* x = (uv^7)^((q-5)/8) */
    fe_mul(&h->X, &h->X, &v3);
    fe_mul(&h->X, &h->X, &u); /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(&vxx, &h->X);
    fe_mul(&vxx, &vxx, &v);
    fe_sub(&check, &vxx, &u); /* vx^2 - u */
    if (fe_isnonzero(&check)) {
        fe_add(&check, &vxx, &u); /* vx^2 + u */
        if (fe_isnonzero(&check)) return -1;
        fe_mul(&h->X, &h->X, &ed25519_sqrtm1);
    }

    if (fe_isnegative(&h->X) == (s[31] >> 7)) {
        fe_neg(&h->X, &h->X);
    }

    fe_mul(&h->T, &h->X, &h->Y);
    return 0;
}

static void ge_tobytes(unsigned char *s, const ge_p2 *h)
{
    fe recip, x, y;

    fe_invert(&recip, &h->Z);
    fe_mul(&x, &h->X, &recip);
    fe_mul(&y, &h->Y, &recip);
    fe_tobytes(s, &y);
    s[31] ^= fe_isnegative(&x) << 7;
}

/*
 * ge_double_scalarmult_vartime: compute [a]A + [b]B
 * where A is a variable point (ge_p3) and B is the basepoint.
 * a is 32 bytes, b is 32 bytes.
 * Result is written to r (ge_p2).
 *
 * Uses a simple double-and-add for the variable base part
 * and the precomputed table for the fixed base part.
 */

/* Compute e[0]+e[1]*256+...+e[63]*256^63 = b (used for basepoint scalar mul) */
static void slide(signed char *r, const unsigned char *a)
{
    int i, b, k;

    for (i = 0; i < 256; i++)
        r[i] = 1 & (a[i >> 3] >> (i & 7));

    for (i = 0; i < 256; i++) {
        if (r[i]) {
            for (b = 1; b <= 6 && i + b < 256; b++) {
                if (r[i + b]) {
                    if (r[i] + (r[i + b] << b) <= 15) {
                        r[i] += r[i + b] << b;
                        r[i + b] = 0;
                    } else if (r[i] - (r[i + b] << b) >= -15) {
                        r[i] -= r[i + b] << b;
                        for (k = i + b; k < 256; k++) {
                            if (!r[k]) {
                                r[k] = 1;
                                break;
                            }
                            r[k] = 0;
                        }
                    } else
                        break;
                }
            }
        }
    }
}

static void ge_double_scalarmult_vartime(ge_p2 *r, const unsigned char *a,
                                          const ge_p3 *A,
                                          const unsigned char *b)
{
    signed char aslide[256], bslide[256];
    ge_cached Ai[8]; /* A, 3A, 5A, 7A, 9A, 11A, 13A, 15A */
    ge_p1p1 t;
    ge_p3 u;
    ge_p3 A2;
    ge_p2 Ap2;
    int i;

    slide(aslide, a);
    slide(bslide, b);

    ge_p3_to_cached(&Ai[0], A);
    ge_p3_to_p2(&Ap2, A);
    ge_p2_dbl(&t, &Ap2);
    ge_p1p1_to_p3(&A2, &t);
    ge_add(&t, &A2, &Ai[0]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[1], &u);
    ge_add(&t, &A2, &Ai[1]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[2], &u);
    ge_add(&t, &A2, &Ai[2]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[3], &u);
    ge_add(&t, &A2, &Ai[3]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[4], &u);
    ge_add(&t, &A2, &Ai[4]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[5], &u);
    ge_add(&t, &A2, &Ai[5]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[6], &u);
    ge_add(&t, &A2, &Ai[6]); ge_p1p1_to_p3(&u, &t); ge_p3_to_cached(&Ai[7], &u);

    ge_p2_0(r);

    for (i = 255; i >= 0; i--) {
        if (aslide[i] || bslide[i]) break;
    }

    for (; i >= 0; i--) {
        ge_p2_dbl(&t, r);

        if (aslide[i] > 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_add(&t, &u, &Ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_sub(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        if (bslide[i] > 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_madd(&t, &u, &Bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            ge_p1p1_to_p3(&u, &t);
            ge_msub(&t, &u, &Bi[(-bslide[i]) / 2]);
        }

        ge_p1p1_to_p2(r, &t);
    }
}

/*
 * sc_reduce: reduce a 64-byte value modulo L
 * L = 2^252 + 27742317777372353535851937790883648493
 */
static void sc_reduce(unsigned char *s)
{
    i64 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
    i64 s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23;
    i64 carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7;
    i64 carry8, carry9, carry10, carry11, carry12, carry13, carry14;
    i64 carry15, carry16;

    s0 = 2097151 & (i64)load_3(s);
    s1 = 2097151 & ((i64)load_4(s + 2) >> 5);
    s2 = 2097151 & ((i64)load_3(s + 5) >> 2);
    s3 = 2097151 & ((i64)load_4(s + 7) >> 7);
    s4 = 2097151 & ((i64)load_4(s + 10) >> 4);
    s5 = 2097151 & ((i64)load_3(s + 13) >> 1);
    s6 = 2097151 & ((i64)load_4(s + 15) >> 6);
    s7 = 2097151 & ((i64)load_3(s + 18) >> 3);
    s8 = 2097151 & (i64)load_3(s + 21);
    s9 = 2097151 & ((i64)load_4(s + 23) >> 5);
    s10 = 2097151 & ((i64)load_3(s + 26) >> 2);
    s11 = 2097151 & ((i64)load_4(s + 28) >> 7);
    s12 = 2097151 & ((i64)load_4(s + 31) >> 4);
    s13 = 2097151 & ((i64)load_3(s + 34) >> 1);
    s14 = 2097151 & ((i64)load_4(s + 36) >> 6);
    s15 = 2097151 & ((i64)load_3(s + 39) >> 3);
    s16 = 2097151 & (i64)load_3(s + 42);
    s17 = 2097151 & ((i64)load_4(s + 44) >> 5);
    s18 = 2097151 & ((i64)load_3(s + 47) >> 2);
    s19 = 2097151 & ((i64)load_4(s + 49) >> 7);
    s20 = 2097151 & ((i64)load_4(s + 52) >> 4);
    s21 = 2097151 & ((i64)load_3(s + 55) >> 1);
    s22 = 2097151 & ((i64)load_4(s + 57) >> 6);
    s23 = ((i64)load_4(s + 60) >> 3);

    s11 += s23 * 666643;
    s12 += s23 * 470296;
    s13 += s23 * 654183;
    s14 -= s23 * 997805;
    s15 += s23 * 136657;
    s16 -= s23 * 683901;
    s23 = 0;

    s10 += s22 * 666643;
    s11 += s22 * 470296;
    s12 += s22 * 654183;
    s13 -= s22 * 997805;
    s14 += s22 * 136657;
    s15 -= s22 * 683901;
    s22 = 0;

    s9 += s21 * 666643;
    s10 += s21 * 470296;
    s11 += s21 * 654183;
    s12 -= s21 * 997805;
    s13 += s21 * 136657;
    s14 -= s21 * 683901;
    s21 = 0;

    s8 += s20 * 666643;
    s9 += s20 * 470296;
    s10 += s20 * 654183;
    s11 -= s20 * 997805;
    s12 += s20 * 136657;
    s13 -= s20 * 683901;
    s20 = 0;

    s7 += s19 * 666643;
    s8 += s19 * 470296;
    s9 += s19 * 654183;
    s10 -= s19 * 997805;
    s11 += s19 * 136657;
    s12 -= s19 * 683901;
    s19 = 0;

    s6 += s18 * 666643;
    s7 += s18 * 470296;
    s8 += s18 * 654183;
    s9 -= s18 * 997805;
    s10 += s18 * 136657;
    s11 -= s18 * 683901;
    s18 = 0;

    carry6 = (s6 + (i64)(1L << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (i64)(1L << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (i64)(1L << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry12 = (s12 + (i64)(1L << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21;
    carry14 = (s14 + (i64)(1L << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21;
    carry16 = (s16 + (i64)(1L << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21;

    carry7 = (s7 + (i64)(1L << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (i64)(1L << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (i64)(1L << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;
    carry13 = (s13 + (i64)(1L << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21;
    carry15 = (s15 + (i64)(1L << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21;

    s5 += s17 * 666643;
    s6 += s17 * 470296;
    s7 += s17 * 654183;
    s8 -= s17 * 997805;
    s9 += s17 * 136657;
    s10 -= s17 * 683901;
    s17 = 0;

    s4 += s16 * 666643;
    s5 += s16 * 470296;
    s6 += s16 * 654183;
    s7 -= s16 * 997805;
    s8 += s16 * 136657;
    s9 -= s16 * 683901;
    s16 = 0;

    s3 += s15 * 666643;
    s4 += s15 * 470296;
    s5 += s15 * 654183;
    s6 -= s15 * 997805;
    s7 += s15 * 136657;
    s8 -= s15 * 683901;
    s15 = 0;

    s2 += s14 * 666643;
    s3 += s14 * 470296;
    s4 += s14 * 654183;
    s5 -= s14 * 997805;
    s6 += s14 * 136657;
    s7 -= s14 * 683901;
    s14 = 0;

    s1 += s13 * 666643;
    s2 += s13 * 470296;
    s3 += s13 * 654183;
    s4 -= s13 * 997805;
    s5 += s13 * 136657;
    s6 -= s13 * 683901;
    s13 = 0;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = (s0 + (i64)(1L << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry2 = (s2 + (i64)(1L << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry4 = (s4 + (i64)(1L << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry6 = (s6 + (i64)(1L << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry8 = (s8 + (i64)(1L << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry10 = (s10 + (i64)(1L << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

    carry1 = (s1 + (i64)(1L << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry3 = (s3 + (i64)(1L << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry5 = (s5 + (i64)(1L << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry7 = (s7 + (i64)(1L << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry9 = (s9 + (i64)(1L << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry11 = (s11 + (i64)(1L << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

    s0 += s12 * 666643;
    s1 += s12 * 470296;
    s2 += s12 * 654183;
    s3 -= s12 * 997805;
    s4 += s12 * 136657;
    s5 -= s12 * 683901;
    s12 = 0;

    carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
    carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
    carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
    carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
    carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
    carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
    carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
    carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
    carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
    carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

    s[0]  = (unsigned char)(s0 >> 0);
    s[1]  = (unsigned char)(s0 >> 8);
    s[2]  = (unsigned char)((s0 >> 16) | (s1 << 5));
    s[3]  = (unsigned char)(s1 >> 3);
    s[4]  = (unsigned char)(s1 >> 11);
    s[5]  = (unsigned char)((s1 >> 19) | (s2 << 2));
    s[6]  = (unsigned char)(s2 >> 6);
    s[7]  = (unsigned char)((s2 >> 14) | (s3 << 7));
    s[8]  = (unsigned char)(s3 >> 1);
    s[9]  = (unsigned char)(s3 >> 9);
    s[10] = (unsigned char)((s3 >> 17) | (s4 << 4));
    s[11] = (unsigned char)(s4 >> 4);
    s[12] = (unsigned char)(s4 >> 12);
    s[13] = (unsigned char)((s4 >> 20) | (s5 << 1));
    s[14] = (unsigned char)(s5 >> 7);
    s[15] = (unsigned char)((s5 >> 15) | (s6 << 6));
    s[16] = (unsigned char)(s6 >> 2);
    s[17] = (unsigned char)(s6 >> 10);
    s[18] = (unsigned char)((s6 >> 18) | (s7 << 3));
    s[19] = (unsigned char)(s7 >> 5);
    s[20] = (unsigned char)(s7 >> 13);
    s[21] = (unsigned char)(s8 >> 0);
    s[22] = (unsigned char)(s8 >> 8);
    s[23] = (unsigned char)((s8 >> 16) | (s9 << 5));
    s[24] = (unsigned char)(s9 >> 3);
    s[25] = (unsigned char)(s9 >> 11);
    s[26] = (unsigned char)((s9 >> 19) | (s10 << 2));
    s[27] = (unsigned char)(s10 >> 6);
    s[28] = (unsigned char)((s10 >> 14) | (s11 << 7));
    s[29] = (unsigned char)(s11 >> 1);
    s[30] = (unsigned char)(s11 >> 9);
    s[31] = (unsigned char)(s11 >> 17);
}

/*
 * ed25519_verify: verify an Ed25519 signature.
 * RFC 8032 Section 5.1.7
 *
 * Returns 1 on success (valid signature), 0 on failure.
 */
int ed25519_verify(const unsigned char *public_key,
                   const unsigned char *signature,
                   const unsigned char *message,
                   unsigned long message_len)
{
    SHA512_State hash_state;
    unsigned char h[64];
    unsigned char rcheck[32];
    ge_p3 A;
    ge_p2 R;
    unsigned char scopy[32];
    int i;
    unsigned int bad;

    /* Check S < L (group order). The top 3 bits of byte 31 must be 0,
     * and we do a more detailed check. */
    if (signature[63] & 224)
        return 0;

    /* Decode public key as Edwards point (negated) */
    if (ge_frombytes_negate_vartime(&A, public_key) != 0)
        return 0;

    /* h = SHA-512(R || A || message) mod L */
    SHA512_Init(&hash_state);
    SHA512_Bytes(&hash_state, signature, 32);      /* R */
    SHA512_Bytes(&hash_state, public_key, 32);     /* A */
    SHA512_Bytes(&hash_state, message, (int)message_len);
    SHA512_Final(&hash_state, h);
    sc_reduce(h);

    /* Copy S (second half of signature) */
    memcpy(scopy, signature + 32, 32);

    /* Compute [S]B - [h]A = R (since A was negated, this is [S]B + [h](-A)) */
    ge_double_scalarmult_vartime(&R, h, &A, scopy);
    ge_tobytes(rcheck, &R);

    /* Compare with R (first half of signature) */
    bad = 0;
    for (i = 0; i < 32; i++)
        bad |= rcheck[i] ^ signature[i];

    return (bad == 0) ? 1 : 0;
}
