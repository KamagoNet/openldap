/* pw-argon2.c - Password module for argon2 */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2017 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#define _GNU_SOURCE

#include "portable.h"
#include "ac/string.h"
#include "lber_pvt.h"
#include "lutil.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * For now, we hardcode the default values from the libsodium "INTERACTIVE" values
 */
#define SLAPD_ARGON2I_ITERATIONS crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
#define SLAPD_ARGON2I_MEMORY crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE

#ifdef crypto_pwhash_ALG_ARGON2ID13
#define SLAPD_ARGON2ID_ITERATIONS crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
#define SLAPD_ARGON2ID_MEMORY crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
#endif // crypto_pwhash_ALG_ARGON2ID13

const struct berval slapd_argon2_scheme = BER_BVC("{ARGON2}");
const struct berval slapd_argon2i_scheme = BER_BVC("{ARGON2I}");
const struct berval slapd_argon2id_scheme = BER_BVC("{ARGON2ID}");

/*
 * Argon2i creation / verification
 */

static int slapd_argon2i_hash(
  const struct berval *scheme,
  const struct berval *passwd,
  struct berval *hash,
  const char **text) {

  /*
   * Duplicate these values here so future code which allows
   * configuration has an easier time.
   */
  uint32_t iterations = SLAPD_ARGON2I_ITERATIONS;
  uint32_t memory = SLAPD_ARGON2I_MEMORY;
  char encoded_password[crypto_pwhash_STRBYTES];

  int rc = crypto_pwhash_argon2i_str(encoded_password, passwd->bv_val, passwd->bv_len,
            iterations, memory);

  if(rc) {
    return LUTIL_PASSWD_ERR;
  }

  size_t encoded_length = strlen(encoded_password);

  hash->bv_len = scheme->bv_len + encoded_length;
  hash->bv_val = ber_memalloc(hash->bv_len);

  AC_MEMCPY(hash->bv_val, scheme->bv_val, scheme->bv_len);
  AC_MEMCPY(hash->bv_val + scheme->bv_len, &encoded_password, encoded_length);

  return LUTIL_PASSWD_OK;
}

static int slapd_argon2i_verify(
  const struct berval *scheme,
  const struct berval *passwd,
  const struct berval *cred,
  const char **text) {

  int rc = crypto_pwhash_argon2i_str_verify(passwd->bv_val, cred->bv_val, cred->bv_len);

  if (rc) {
    return LUTIL_PASSWD_ERR;
  }
  return LUTIL_PASSWD_OK;
}

#ifdef crypto_pwhash_ALG_ARGON2ID13

/*
 * Argon2id creation / verification
 */

static int slapd_argon2id_hash(
  const struct berval *scheme,
  const struct berval *passwd,
  struct berval *hash,
  const char **text) {

  /*
   * Duplicate these values here so future code which allows
   * configuration has an easier time.
   */
  uint32_t iterations = SLAPD_ARGON2ID_ITERATIONS;
  uint32_t memory = SLAPD_ARGON2ID_MEMORY;
  char encoded_password[crypto_pwhash_STRBYTES];

  // libsodium expects iterations to be at least 3
  if(iterations < 3 ) {
    iterations = 3;
  }

  int rc = crypto_pwhash_argon2id_str(encoded_password, passwd->bv_val, passwd->bv_len,
            iterations, memory);

  if(rc) {
    return LUTIL_PASSWD_ERR;
  }

  size_t encoded_length = strlen(encoded_password);

  hash->bv_len = scheme->bv_len + encoded_length;
  hash->bv_val = ber_memalloc(hash->bv_len);

  AC_MEMCPY(hash->bv_val, scheme->bv_val, scheme->bv_len);
  AC_MEMCPY(hash->bv_val + scheme->bv_len, &encoded_password, encoded_length);

  return LUTIL_PASSWD_OK;
}

static int slapd_argon2id_verify(
  const struct berval *scheme,
  const struct berval *passwd,
  const struct berval *cred,
  const char **text) {

  int rc = crypto_pwhash_argon2id_str_verify(passwd->bv_val, cred->bv_val, cred->bv_len);

  if (rc) {
    return LUTIL_PASSWD_ERR;
  }
  return LUTIL_PASSWD_OK;
}

#endif // crypto_pwhash_ALG_ARGON2ID13

/*
 * Module initialization
 */

int init_module(int argc, char *argv[]) {
  int rc = sodium_init();
  if (rc == -1) {
    return -1;
  }

  rc = lutil_passwd_add((struct berval *)&slapd_argon2_scheme,
        slapd_argon2i_verify, slapd_argon2i_hash);
  if(rc) {
    return rc;
  }

  rc = lutil_passwd_add((struct berval *)&slapd_argon2i_scheme,
        slapd_argon2i_verify, slapd_argon2i_hash);
  if(rc) {
    return rc;
  }

  return lutil_passwd_add((struct berval *)&slapd_argon2id_scheme,
        slapd_argon2id_verify, slapd_argon2id_hash);
}
