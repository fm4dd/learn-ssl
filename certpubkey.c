/* ------------------------------------------------------------ *
 * file:        certpubkey.c                                    *
 * purpose:     Example code to extract public keydata in certs *
 * author:      09/24/2012 Frank4DD, updated 01/17/2024         *
 *                                                              *
 * compile:     gcc -o certpubkey certpubkey.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

int main() {

  const char cert_filestr[] = "./demo/cert-file.pem";
             EVP_PKEY *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory: %s\n", cert_filestr);
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pkey = X509_get_pubkey(cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from certificate");

  /* ---------------------------------------------------------- *
   * Print the public key information and the key in PEM format *
   * ---------------------------------------------------------- */
  /* display the key type and size here */
  if (pkey) {
    BIO_printf(outbio, "Retrieved %d bit %s key", EVP_PKEY_bits(pkey),
                                     EVP_PKEY_get0_type_name(pkey));
    if(EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        char curvestr[80];
        EVP_PKEY_get_utf8_string_param(pkey,
                            OSSL_PKEY_PARAM_GROUP_NAME,
                            curvestr,
                            sizeof(curvestr),
                            NULL);
        BIO_printf(outbio, ", type %s", curvestr);
#else
        EC_KEY *myecc = NULL;
        myecc = EVP_PKEY_get1_EC_KEY(pkey);
        const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);
        BIO_printf(outbio, ", type %s",
                OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));
#endif
    }
    BIO_printf(outbio, " from %s\n\n", cert_filestr);
  }
  else {
    BIO_printf(outbio, "Could not get public key from %s\n", cert_filestr);
    exit(1);
  }

  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");

  X509_free(cert);
  EVP_PKEY_free(pkey);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}
