/* ------------------------------------------------------------ *
 * file:        eckeycreate.c                                   *
 * purpose:     Example code for creating elliptic curve        *
 *              cryptography (ECC) key pairs                    *
 * author:      01/26/2015 Frank4DD                             * 
 *                                                              *
 * compile:     gcc -o eckeycreate eckeycreate.c -lssl -lcrypto *
 *                                                              *
 * Updated to work with OpenSSL version 3, as well as old 1.1.1 *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>  
#include <openssl/ec.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#endif

#define ECCTYPE    "secp521r1"

int main() {
  char *curvename;
  int keysize;

  /* ---------------------------------------------------------- *
   * Create the Output BIO to use PEM_write_bio functions later *
   * ---------------------------------------------------------- */
  BIO *outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Create the EVP_PKEY generic key structure in OpenSSL       *
   * ---------------------------------------------------------- */
  EVP_PKEY *pkey = EVP_PKEY_new();

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  /* -------------------------------------------------------- *
   * New EC generation code for latest OpenSSL version 3.0    *
   * EVP_PKEY_Q_keygen / EVP_EC_gen return a EVP_PKEY address *
   * or NULL on failure.                                      *
   * ---------------------------------------------------------*/
  // pkey = EVP_EC_gen(ECCTYPE); // macro for EVP_PKEY_Q_keygen
  pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", ECCTYPE);
  if(pkey == NULL) {
    BIO_printf(outbio, "Error generating the ECC key.");
    exit(1);
  }

  /* -------------------------------------------------------- *
   * get the curve information from the new key               *
   * ---------------------------------------------------------*/
  char curvestr[80];
  EVP_PKEY_get_utf8_string_param(pkey,
                                 OSSL_PKEY_PARAM_GROUP_NAME,
                                 curvestr,
                                 sizeof(curvestr),
                                 NULL);
  curvename = curvestr;
#else
  /* -------------------------------------------------------- *
   * Legacy code for old OpenSSL version prior to version 3.0 *
   * ---------------------------------------------------------*/
  int eccgrp = OBJ_txt2nid(ECCTYPE);
  EC_KEY *myecc = EC_KEY_new_by_curve_name(eccgrp);

  /* -------------------------------------------------------- *
   * For cert signing, we use the OPENSSL_EC_NAMED_CURVE flag *
   * ---------------------------------------------------------*/
  EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);

  /* -------------------------------------------------------- *
   * Create the public/private EC key pair here               *
   * ---------------------------------------------------------*/
  if (! (EC_KEY_generate_key(myecc)))
    BIO_printf(outbio, "Error generating the ECC key.");

  /* -------------------------------------------------------- *
   * Converting the EC key into a PKEY structure let us       *
   * handle the key just like any other key pair.             *
   * ---------------------------------------------------------*/
  if (!EVP_PKEY_assign_EC_KEY(pkey,myecc))
    BIO_printf(outbio, "Error assigning ECC key to EVP_PKEY structure.");

  /* -------------------------------------------------------- *
   * Now we show how to extract EC-specifics from the key     *
   * ---------------------------------------------------------*/
  myecc = EVP_PKEY_get1_EC_KEY(pkey);
  const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
  curvename = (char *) OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp));
#endif

  /* ---------------------------------------------------------- *
   * Here we print the key length and the curve type            *
   * ---------------------------------------------------------- */
  keysize = EVP_PKEY_bits(pkey);
  BIO_printf(outbio, "New EC key: %s curve with %d bits\n", curvename, keysize);

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    BIO_printf(outbio, "Error writing private key data in PEM format");

  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  EVP_PKEY_free(pkey);
  EC_KEY_free(myecc);
#endif
  BIO_free_all(outbio);

  exit(0);
}
