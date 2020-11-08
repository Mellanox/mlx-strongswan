/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /usr/bin/gperf -N proposal_get_token_static -m 10 -C -G -c -t -D --output-file=crypto/proposal/proposal_keywords_static.c ./crypto/proposal/proposal_keywords_static.txt  */
/* Computed positions: -k'1,5-7,10,15,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 1 "./crypto/proposal/proposal_keywords_static.txt"

/*
 * Copyright (C) 2009-2013 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <string.h>

#include <crypto/transform.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <crypto/diffie_hellman.h>

#line 25 "./crypto/proposal/proposal_keywords_static.txt"
struct proposal_token {
	char             *name;
	transform_type_t  type;
	uint16_t          algorithm;
	uint16_t          keysize;
};

#define TOTAL_KEYWORDS 146
#define MIN_WORD_LENGTH 3
#define MAX_WORD_LENGTH 22
#define MIN_HASH_VALUE 11
#define MAX_HASH_VALUE 243
/* maximum key range = 233, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (register const char *str, register size_t len)
{
  static const unsigned char asso_values[] =
    {
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244,  61,   3,
       18,  22,  65,  29,   9,   4,   4,   2, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 102, 244,   7,   7,  16,
       53,  15,  28,  74,   7,   4, 244, 244,   2,   6,
        2,   6,  95,  84,  96,  86,   4,  66, 244, 244,
        2,   5, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244, 244, 244, 244,
      244, 244, 244, 244, 244, 244, 244
    };
  register unsigned int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[14]];
      /*FALLTHROUGH*/
      case 14:
      case 13:
      case 12:
      case 11:
      case 10:
        hval += asso_values[(unsigned char)str[9]];
      /*FALLTHROUGH*/
      case 9:
      case 8:
      case 7:
        hval += asso_values[(unsigned char)str[6]];
      /*FALLTHROUGH*/
      case 6:
        hval += asso_values[(unsigned char)str[5]];
      /*FALLTHROUGH*/
      case 5:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
      case 3:
      case 2:
      case 1:
        hval += asso_values[(unsigned char)str[0]+1];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

static const struct proposal_token wordlist[] =
  {
#line 122 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha1",             INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA1_96,         0},
#line 32 "./crypto/proposal/proposal_keywords_static.txt"
    {"null",             ENCRYPTION_ALGORITHM, ENCR_NULL,                 0},
#line 170 "./crypto/proposal/proposal_keywords_static.txt"
    {"x448",             DIFFIE_HELLMAN_GROUP, CURVE_448,                 0},
#line 121 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha",              INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA1_96,         0},
#line 176 "./crypto/proposal/proposal_keywords_static.txt"
    {"noesn",            EXTENDED_SEQUENCE_NUMBERS, NO_EXT_SEQ_NUMBERS,   0},
#line 168 "./crypto/proposal/proposal_keywords_static.txt"
    {"x25519",           DIFFIE_HELLMAN_GROUP, CURVE_25519,               0},
#line 147 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp768",          DIFFIE_HELLMAN_GROUP, MODP_768_BIT,              0},
#line 177 "./crypto/proposal/proposal_keywords_static.txt"
    {"esn",              EXTENDED_SEQUENCE_NUMBERS, EXT_SEQ_NUMBERS,      0},
#line 132 "./crypto/proposal/proposal_keywords_static.txt"
    {"md5",              INTEGRITY_ALGORITHM,  AUTH_HMAC_MD5_96,          0},
#line 145 "./crypto/proposal/proposal_keywords_static.txt"
    {"modpnone",         DIFFIE_HELLMAN_GROUP, MODP_NONE,                 0},
#line 113 "./crypto/proposal/proposal_keywords_static.txt"
    {"serpent",          ENCRYPTION_ALGORITHM, ENCR_SERPENT_CBC,        128},
#line 154 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp8192",         DIFFIE_HELLMAN_GROUP, MODP_8192_BIT,             0},
#line 133 "./crypto/proposal/proposal_keywords_static.txt"
    {"md5_128",          INTEGRITY_ALGORITHM,  AUTH_HMAC_MD5_128,         0},
#line 36 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128",           ENCRYPTION_ALGORITHM, ENCR_AES_CBC,            128},
#line 172 "./crypto/proposal/proposal_keywords_static.txt"
    {"ntru128",          DIFFIE_HELLMAN_GROUP, NTRU_128_BIT,              0},
#line 114 "./crypto/proposal/proposal_keywords_static.txt"
    {"serpent128",       ENCRYPTION_ALGORITHM, ENCR_SERPENT_CBC,        128},
#line 130 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha512",           INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_512_256,    0},
#line 37 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192",           ENCRYPTION_ALGORITHM, ENCR_AES_CBC,            192},
#line 116 "./crypto/proposal/proposal_keywords_static.txt"
    {"serpent256",       ENCRYPTION_ALGORITHM, ENCR_SERPENT_CBC,        256},
#line 173 "./crypto/proposal/proposal_keywords_static.txt"
    {"ntru192",          DIFFIE_HELLMAN_GROUP, NTRU_192_BIT,              0},
#line 171 "./crypto/proposal/proposal_keywords_static.txt"
    {"ntru112",          DIFFIE_HELLMAN_GROUP, NTRU_112_BIT,              0},
#line 124 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha256",           INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_256_128,    0},
#line 159 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp521",           DIFFIE_HELLMAN_GROUP, ECP_521_BIT,               0},
#line 136 "./crypto/proposal/proposal_keywords_static.txt"
    {"aescmac",          INTEGRITY_ALGORITHM,  AUTH_AES_CMAC_96,          0},
#line 38 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256",           ENCRYPTION_ALGORITHM, ENCR_AES_CBC,            256},
#line 48 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm8",       ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       192},
#line 53 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm128",     ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      192},
#line 42 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm8",       ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       128},
#line 47 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm128",     ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      128},
#line 51 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm96",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      192},
#line 52 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm16",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      192},
#line 45 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm96",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      128},
#line 46 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm16",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      128},
#line 134 "./crypto/proposal/proposal_keywords_static.txt"
    {"aesxcbc",          INTEGRITY_ALGORITHM,  AUTH_AES_XCBC_96,          0},
#line 115 "./crypto/proposal/proposal_keywords_static.txt"
    {"serpent192",       ENCRYPTION_ALGORITHM, ENCR_SERPENT_CBC,        192},
#line 155 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp192",           DIFFIE_HELLMAN_GROUP, ECP_192_BIT,               0},
#line 149 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp1536",         DIFFIE_HELLMAN_GROUP, MODP_1536_BIT,             0},
#line 50 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm12",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      192},
#line 87 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia",         ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CBC,       128},
#line 44 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm12",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      128},
#line 174 "./crypto/proposal/proposal_keywords_static.txt"
    {"ntru256",          DIFFIE_HELLMAN_GROUP, NTRU_256_BIT,              0},
#line 54 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm8",       ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       256},
#line 59 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm128",     ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      256},
#line 157 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp256",           DIFFIE_HELLMAN_GROUP, ECP_256_BIT,               0},
#line 146 "./crypto/proposal/proposal_keywords_static.txt"
    {"modpnull",         DIFFIE_HELLMAN_GROUP, MODP_NULL,                 0},
#line 57 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm96",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      256},
#line 58 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm16",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV16,      256},
#line 100 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm8",  ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  192},
#line 105 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm128",ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 192},
#line 112 "./crypto/proposal/proposal_keywords_static.txt"
    {"cast128",          ENCRYPTION_ALGORITHM, ENCR_CAST,               128},
#line 103 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm96", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 192},
#line 104 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm16", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 192},
#line 89 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192",      ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CBC,       192},
#line 56 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm12",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV12,      256},
#line 88 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128",      ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CBC,       128},
#line 35 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes",              ENCRYPTION_ALGORITHM, ENCR_AES_CBC,            128},
#line 102 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm12", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 192},
#line 94 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm8",  ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  128},
#line 99 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm128",ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 128},
#line 33 "./crypto/proposal/proposal_keywords_static.txt"
    {"des",              ENCRYPTION_ALGORITHM, ENCR_DES,                  0},
#line 135 "./crypto/proposal/proposal_keywords_static.txt"
    {"camelliaxcbc",     INTEGRITY_ALGORITHM,  AUTH_CAMELLIA_XCBC_96,     0},
#line 97 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm96", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 128},
#line 98 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm16", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 128},
#line 90 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256",      ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CBC,       256},
#line 137 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfsha1",          PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA1,           0},
#line 106 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm8",  ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  256},
#line 111 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm128",ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 256},
#line 151 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp3072",         DIFFIE_HELLMAN_GROUP, MODP_3072_BIT,             0},
#line 96 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm12", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 128},
#line 109 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm96", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 256},
#line 110 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm16", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV16, 256},
#line 66 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm8",       ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       192},
#line 71 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm128",     ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      192},
#line 60 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm8",       ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       128},
#line 65 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm128",     ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      128},
#line 69 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm96",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      192},
#line 70 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm16",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      192},
#line 63 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm96",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      128},
#line 64 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm16",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      128},
#line 108 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm12", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV12, 256},
#line 49 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ccm64",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       192},
#line 167 "./crypto/proposal/proposal_keywords_static.txt"
    {"curve25519",       DIFFIE_HELLMAN_GROUP, CURVE_25519,               0},
#line 43 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ccm64",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       128},
#line 68 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm12",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      192},
#line 138 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfsha256",        PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_256,       0},
#line 62 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm12",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      128},
#line 72 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm8",       ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       256},
#line 77 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm128",     ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      256},
#line 175 "./crypto/proposal/proposal_keywords_static.txt"
    {"newhope128",       DIFFIE_HELLMAN_GROUP, NH_128_BIT,                0},
#line 75 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm96",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      256},
#line 76 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm16",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV16,      256},
#line 79 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gmac",       ENCRYPTION_ALGORITHM, ENCR_NULL_AUTH_AES_GMAC, 192},
#line 128 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha384",           INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_384_192,    0},
#line 78 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gmac",       ENCRYPTION_ALGORITHM, ENCR_NULL_AUTH_AES_GMAC, 128},
#line 55 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ccm64",      ENCRYPTION_ALGORITHM, ENCR_AES_CCM_ICV8,       256},
#line 152 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp4096",         DIFFIE_HELLMAN_GROUP, MODP_4096_BIT,             0},
#line 40 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192ctr",        ENCRYPTION_ALGORITHM, ENCR_AES_CTR,            192},
#line 83 "./crypto/proposal/proposal_keywords_static.txt"
    {"blowfish",         ENCRYPTION_ALGORITHM, ENCR_BLOWFISH,           128},
#line 39 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128ctr",        ENCRYPTION_ALGORITHM, ENCR_AES_CTR,            128},
#line 74 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm12",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV12,      256},
#line 153 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp6144",         DIFFIE_HELLMAN_GROUP, MODP_6144_BIT,             0},
#line 101 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ccm64", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  192},
#line 140 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfsha512",        PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_512,       0},
#line 34 "./crypto/proposal/proposal_keywords_static.txt"
    {"3des",             ENCRYPTION_ALGORITHM, ENCR_3DES,                 0},
#line 148 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp1024",         DIFFIE_HELLMAN_GROUP, MODP_1024_BIT,             0},
#line 150 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp2048",         DIFFIE_HELLMAN_GROUP, MODP_2048_BIT,             0},
#line 166 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp512bp",         DIFFIE_HELLMAN_GROUP, ECP_512_BP,                0},
#line 160 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp1024s160",     DIFFIE_HELLMAN_GROUP, MODP_1024_160,             0},
#line 80 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gmac",       ENCRYPTION_ALGORITHM, ENCR_NULL_AUTH_AES_GMAC, 256},
#line 126 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha256_96",        INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_256_96,     0},
#line 143 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfcamelliaxcbc",  PSEUDO_RANDOM_FUNCTION, PRF_CAMELLIA128_XCBC,    0},
#line 131 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha2_512",         INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_512_256,    0},
#line 85 "./crypto/proposal/proposal_keywords_static.txt"
    {"blowfish192",      ENCRYPTION_ALGORITHM, ENCR_BLOWFISH,           192},
#line 41 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256ctr",        ENCRYPTION_ALGORITHM, ENCR_AES_CTR,            256},
#line 84 "./crypto/proposal/proposal_keywords_static.txt"
    {"blowfish128",      ENCRYPTION_ALGORITHM, ENCR_BLOWFISH,           128},
#line 158 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp384",           DIFFIE_HELLMAN_GROUP, ECP_384_BIT,               0},
#line 95 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ccm64", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  128},
#line 125 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha2_256",         INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_256_128,    0},
#line 92 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia192ctr",   ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CTR,       192},
#line 127 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha2_256_96",      INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_256_96,     0},
#line 164 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp256bp",         DIFFIE_HELLMAN_GROUP, ECP_256_BP,                0},
#line 117 "./crypto/proposal/proposal_keywords_static.txt"
    {"twofish",          ENCRYPTION_ALGORITHM, ENCR_TWOFISH_CBC,        128},
#line 82 "./crypto/proposal/proposal_keywords_static.txt"
    {"chacha20poly1305compat", ENCRYPTION_ALGORITHM, ENCR_CHACHA20_POLY1305, 256},
#line 107 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ccm64", ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CCM_ICV8,  256},
#line 118 "./crypto/proposal/proposal_keywords_static.txt"
    {"twofish128",       ENCRYPTION_ALGORITHM, ENCR_TWOFISH_CBC,        128},
#line 156 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp224",           DIFFIE_HELLMAN_GROUP, ECP_224_BIT,               0},
#line 86 "./crypto/proposal/proposal_keywords_static.txt"
    {"blowfish256",      ENCRYPTION_ALGORITHM, ENCR_BLOWFISH,           256},
#line 162 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp2048s256",     DIFFIE_HELLMAN_GROUP, MODP_2048_256,             0},
#line 67 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes192gcm64",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       192},
#line 123 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha1_160",         INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA1_160,        0},
#line 61 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes128gcm64",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       128},
#line 91 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia128ctr",   ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CTR,       128},
#line 120 "./crypto/proposal/proposal_keywords_static.txt"
    {"twofish256",       ENCRYPTION_ALGORITHM, ENCR_TWOFISH_CBC,        256},
#line 139 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfsha384",        PSEUDO_RANDOM_FUNCTION, PRF_HMAC_SHA2_384,       0},
#line 81 "./crypto/proposal/proposal_keywords_static.txt"
    {"chacha20poly1305", ENCRYPTION_ALGORITHM, ENCR_CHACHA20_POLY1305,    0},
#line 93 "./crypto/proposal/proposal_keywords_static.txt"
    {"camellia256ctr",   ENCRYPTION_ALGORITHM, ENCR_CAMELLIA_CTR,       256},
#line 141 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfmd5",           PSEUDO_RANDOM_FUNCTION, PRF_HMAC_MD5,            0},
#line 73 "./crypto/proposal/proposal_keywords_static.txt"
    {"aes256gcm64",      ENCRYPTION_ALGORITHM, ENCR_AES_GCM_ICV8,       256},
#line 129 "./crypto/proposal/proposal_keywords_static.txt"
    {"sha2_384",         INTEGRITY_ALGORITHM,  AUTH_HMAC_SHA2_384_192,    0},
#line 165 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp384bp",         DIFFIE_HELLMAN_GROUP, ECP_384_BP,                0},
#line 119 "./crypto/proposal/proposal_keywords_static.txt"
    {"twofish192",       ENCRYPTION_ALGORITHM, ENCR_TWOFISH_CBC,        192},
#line 169 "./crypto/proposal/proposal_keywords_static.txt"
    {"curve448",         DIFFIE_HELLMAN_GROUP, CURVE_448,                 0},
#line 163 "./crypto/proposal/proposal_keywords_static.txt"
    {"ecp224bp",         DIFFIE_HELLMAN_GROUP, ECP_224_BP,                0},
#line 142 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfaesxcbc",       PSEUDO_RANDOM_FUNCTION, PRF_AES128_XCBC,         0},
#line 161 "./crypto/proposal/proposal_keywords_static.txt"
    {"modp2048s224",     DIFFIE_HELLMAN_GROUP, MODP_2048_224,             0},
#line 144 "./crypto/proposal/proposal_keywords_static.txt"
    {"prfaescmac",       PSEUDO_RANDOM_FUNCTION, PRF_AES128_CMAC,         0}
  };

static const short lookup[] =
  {
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1,   0,   1,   2,   3,   4,  -1,  -1,   5,  -1,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
      6,  -1,  -1,   7,   8,   9,  10,  11,  12,  13,
     -1,  -1,  14,  15,  -1,  -1,  -1,  -1,  -1,  16,
     -1,  17,  -1,  18,  19,  20,  -1,  21,  22,  23,
     24,  25,  26,  27,  28,  29,  30,  31,  32,  33,
     -1,  34,  35,  36,  -1,  37,  38,  39,  40,  41,
     42,  43,  44,  45,  46,  -1,  47,  48,  -1,  49,
     50,  51,  52,  53,  54,  -1,  55,  -1,  -1,  -1,
     56,  -1,  57,  58,  59,  60,  61,  62,  -1,  -1,
     63,  64,  -1,  65,  66,  67,  68,  69,  70,  71,
     72,  73,  74,  75,  76,  77,  78,  79,  80,  81,
     82,  -1,  -1,  83,  84,  85,  -1,  86,  87,  -1,
     88,  89,  90,  91,  92,  93,  94,  95,  96,  97,
     98,  99, 100, 101, 102, 103,  -1, 104, 105, 106,
    107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117,  -1,  -1, 118,  -1, 119, 120, 121, 122,  -1,
    123, 124, 125, 126,  -1, 127, 128, 129, 130, 131,
     -1, 132,  -1,  -1, 133,  -1,  -1, 134,  -1,  -1,
    135, 136,  -1,  -1, 137, 138,  -1, 139,  -1, 140,
    141,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 142,  -1,  -1,  -1,  -1,  -1,  -1,  -1, 143,
     -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,  -1,
     -1, 144,  -1, 145
  };

const struct proposal_token *
proposal_get_token_static (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = hash (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register int index = lookup[key];

          if (index >= 0)
            {
              register const char *s = wordlist[index].name;

              if (*str == *s && !strncmp (str + 1, s + 1, len - 1) && s[len] == '\0')
                return &wordlist[index];
            }
        }
    }
  return 0;
}
