/* ------------------------------------------------------------ *
 * file:        keycompare.c                                    *
 * purpose:     Example code to check if a private key belongs  *
 *              to a certificate.                               *
 * author:      05/15/2015 Frank4DD                             *
 *                                                              *
 *  gcc -o keycompare keycompare.c -lssl -lcrypto               *
 *                                                              *
 * Updated to work with OpenSSL version 3, as well as old 1.1.1 *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#include <openssl/core_names.h>
static void set_optional_params(OSSL_PARAM *);
#else
const unsigned char pad = RSA_PKCS1_PADDING;
#endif

int RSAcmp_mod(EVP_PKEY *, EVP_PKEY *);
int RSAencrypt(EVP_PKEY *, const unsigned char *);
int RSAdecrypt(EVP_PKEY *, int);
ECDSA_SIG *ECsign(EVP_PKEY *, const unsigned char *);
int ECverify(EVP_PKEY *, const unsigned char *, ECDSA_SIG *);
unsigned char *encdata = NULL;
unsigned char *decdata = NULL;
int teststr_len, ret;

/* ---------------------------------------------------------- *
 * RSAcmp_mod compares RSA public modulus n of pub and priv   *
 * returns 0 if key modulus match, and 1 for mismatch         *
 * -----------------------------------------------------------*/
int RSAcmp_mod(EVP_PKEY *priv, EVP_PKEY *pub) {
  int match;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  /* -------------------------------------------------------- *
   * Old code for OpenSSL versions before version 3.0         *
   * ---------------------------------------------------------*/
  const BIGNUM *privrsa_mod;
  const BIGNUM *pubrsa_mod;
  RSA *privrsa = EVP_PKEY_get1_RSA(priv);
  RSA_get0_key(privrsa, &privrsa_mod, NULL, NULL);
  RSA *pubrsa = EVP_PKEY_get1_RSA(pub);
  RSA_get0_key(pubrsa, &pubrsa_mod, NULL, NULL);
#else
  /* -------------------------------------------------------- *
   * New code for latest OpenSSL version 3.0                  *
   * ---------------------------------------------------------*/
  BIGNUM *privrsa_mod = NULL;
  BIGNUM *pubrsa_mod = NULL;
  EVP_PKEY_get_bn_param(priv, OSSL_PKEY_PARAM_RSA_N, &privrsa_mod);
  EVP_PKEY_get_bn_param(pub, OSSL_PKEY_PARAM_RSA_N, &pubrsa_mod);
#endif

  char *privrsa_mod_hex = BN_bn2hex(privrsa_mod);
  char *pubrsa_mod_hex = BN_bn2hex(pubrsa_mod);

  printf("priv: %s\n", privrsa_mod_hex);
  printf(" pub: %s\n", pubrsa_mod_hex);

  if(strcmp(privrsa_mod_hex, pubrsa_mod_hex) == 0)
    match = 0; // the keys modulus is matching
  else
    match = 1; // the keys modulus don't match

  OPENSSL_free(privrsa_mod_hex);
  OPENSSL_free(pubrsa_mod_hex);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  RSA_free(privrsa);
  RSA_free(pubrsa);
#endif
  return match;
}

int main() {

  const char cert_filestr[] = "./demo/cert-file.pem";
  const char pkey_filestr[] = "./demo/cert-file.key";
  const unsigned char cleartextstr[] = "This line will be encrypted and, if keys match, it decrypts again.";

          EVP_PKEY *privkey = NULL;
           EVP_PKEY *pubkey = NULL;
  BIO              *certbio = NULL;
  BIO              *pkeybio = NULL;
  X509                *cert = NULL;
  int i, enc_len, dec_len;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
#endif

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  pkeybio = BIO_new(BIO_s_file());

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    printf("Error loading cert into memory\n");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Load the private key from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(pkeybio, pkey_filestr);
  if (! (privkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
    printf("Error loading private key into memory\n");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pubkey = X509_get_pubkey(cert)) == NULL) {
    printf("Error getting public key from certificate");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Print the public key information and the key in PEM format *
   * ---------------------------------------------------------- */
  /* display the key type and size here */
  if (pubkey) {
    teststr_len = strlen( (const char *) cleartextstr);

    switch (EVP_PKEY_id(pubkey)) {
      case EVP_PKEY_RSA:
        printf("Detected RSA pubkey [%d bit]. RSA modulus (n) check:\n", EVP_PKEY_bits(pubkey));
        if(RSAcmp_mod(privkey, pubkey) == 0)
          printf("Success: RSA modulus (n) matches between public and private key parts\n\n");
        else
          printf("Failure: RSA modulus (n) mismatch between public and private key parts\n\n");

        printf("Cleartext string check [%d bytes]:\n\"%s\"\n\n",
                       (int) teststr_len, cleartextstr);
        printf("Encrypting text with RSA public key [%d bit]. ", EVP_PKEY_bits(pubkey));
        enc_len = RSAencrypt(pubkey, cleartextstr);
        printf("Encrypted data (hex) [%d bytes]:\n", enc_len);
        for(i=0;i<enc_len;i++) { printf("%02x ", encdata[i]); }

        printf("\n\nDecrypting with RSA private key [%d bit]. ", EVP_PKEY_bits(privkey));
        dec_len = RSAdecrypt(privkey, enc_len);
        if (dec_len == -1) 
         printf("Failure: Keys don't match!");
        else {
          printf("Decrypted data [%d bytes]:\n\"%s\"\n", dec_len, decdata);
        }
        break;
      case EVP_PKEY_EC:
        printf("Detected EC Key[%d bit].\n\n", EVP_PKEY_bits(pubkey));
        printf("Creating signature with EC private key [%d bit]. ", EVP_PKEY_bits(privkey));
        ECDSA_SIG *sig = ECsign(privkey, cleartextstr);
        printf("\n\nVerifying signature with EC public key [%d bit]. ", EVP_PKEY_bits(pubkey));
        ret = ECverify(pubkey, cleartextstr, sig);
        break;
      default:
        printf("Unknown Key [%d bit].\n\n", EVP_PKEY_bits(pubkey));
        exit(1);
        break;
    }
  }

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  EVP_PKEY_free(pubkey);
  BIO_free_all(certbio);
#endif
  exit(0);
}

/* ---------------------------------------------------------- *
 * RSA encrypt the teststring with the certificate public key *
 * ---------------------------------------------------------- */
int RSAencrypt(EVP_PKEY *key, const unsigned char *teststring) {
  int rsa_outlen = 0;
  encdata = OPENSSL_zalloc(1024); // allocate and zero 1kb space

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  RSA *pubrsa = NULL;
  pubrsa = EVP_PKEY_get1_RSA(key);
  rsa_outlen = RSA_public_encrypt(teststr_len, teststring, encdata, pubrsa, pad);
  RSA_free(pubrsa);
#else
  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  OSSL_PARAM params[2];
  set_optional_params(params);
  EVP_PKEY_encrypt_init_ex(ctx, params);
  EVP_PKEY_encrypt(ctx, encdata, (size_t *) &rsa_outlen, teststring, teststr_len);
  EVP_PKEY_CTX_free(ctx);
#endif
  return rsa_outlen;
}

/* ---------------------------------------------------------- *
 * Decrypt a teststring with the certificate private key      *
 * ---------------------------------------------------------- */
int RSAdecrypt(EVP_PKEY *key, int rsa_inlen) {
  int rsa_outlen = 0;
  decdata = OPENSSL_zalloc(1024); // allocate and zero 1kb space

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  RSA *privrsa = NULL;
  privrsa = EVP_PKEY_get1_RSA(key);
  rsa_outlen = RSA_private_decrypt(rsa_inlen, encdata, decdata, privrsa, pad);
  RSA_free(privrsa);
#else
  EVP_PKEY_CTX *ctx = NULL;
  ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  OSSL_PARAM params[2];
  set_optional_params(params);
  EVP_PKEY_decrypt_init_ex(ctx, params);
  EVP_PKEY_decrypt(ctx, decdata, (size_t *) &rsa_outlen, encdata, rsa_inlen);
#endif
  return rsa_outlen;
}

/* ---------------------------------------------------------- *
 * Sign the teststring with the certificate private key       *
 * ---------------------------------------------------------- */
ECDSA_SIG *ECsign(EVP_PKEY *key, const unsigned char *teststring) {
  ECDSA_SIG *sig;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  EC_KEY *priveckey = NULL;
  priveckey = EVP_PKEY_get1_EC_KEY(key);
  sig = ECDSA_do_sign(teststring, teststr_len, priveckey);
  EC_KEY_free(priveckey);
#else
  EVP_MD_CTX *ctx = NULL;
  ctx = EVP_MD_CTX_new();
  unsigned char *sigstr;
  size_t *sig_len;
  EVP_DigestSign(ctx, sigstr, sig_len, teststring, teststr_len);
  sig = d2i_ECDSA_SIG(NULL, (const unsigned char **) &sigstr, (long) &sig_len);
  EVP_MD_CTX_free(ctx);
#endif
  return sig;
}

/* ---------------------------------------------------------- *
 * Validate the signature with the certificate public key     *
 * ---------------------------------------------------------- */
int ECverify(EVP_PKEY *key, const unsigned char *teststring, ECDSA_SIG *sig) {

  teststr_len = strlen( (const char *) teststring);
#if OPENSSL_VERSION_NUMBER < 0x30000000L
  EC_KEY *pubeckey = NULL;
  pubeckey = EVP_PKEY_get1_EC_KEY(key);
  ret = ECDSA_do_verify(teststring, teststr_len, sig, pubeckey);
  EC_KEY_free(pubeckey);
#else
  EVP_MD_CTX *ctx = NULL;
  ctx = EVP_MD_CTX_new();
  unsigned char *sigstr;
  i2d_ECDSA_SIG(sig, &sigstr);
  size_t sig_len = strlen( (const char *) sigstr);
  /* ---------------------------------------------------------- *
   * Successful verification returns 1                          *
   * ---------------------------------------------------------- */
    ret = EVP_DigestVerify(ctx, sigstr, sig_len, teststring, teststr_len);
   EVP_MD_CTX_free(ctx);
#endif
  return ret;
}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
/* ------------------------------------------------------------ *
 * Helper function Set optional parameters for RSA OAEP Padding *
 * ------------------------------------------------------------ */
static void set_optional_params(OSSL_PARAM *p) {
    /* "pkcs1" is used by default if the padding mode is not set */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
                                            OSSL_PKEY_RSA_PAD_MODE_PKCSV15, 0);
    *p = OSSL_PARAM_construct_end();
}
#endif
