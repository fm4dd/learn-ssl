/* ------------------------------------------------------------ *
 * file:        keycompare.c                                    *
 * purpose:     Example code to check if a private key belongs  *
 *              to a certificate.                               *
 * author:      05/15/2015 Frank4DD                             *
 *                                                              *
 *  gcc -o keycompare keycompare.c -lssl -lcrypto               *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <string.h>

int RSAcmp_mod(EVP_PKEY *, EVP_PKEY *);
int RSAencrypt(EVP_PKEY *, const char *);
int RSAdecrypt(EVP_PKEY *, int);
unsigned char *encdata = NULL;
unsigned char *decdata = NULL;
const unsigned char pad = RSA_PKCS1_PADDING;
int teststr_len, ret;

int RSAcmp_mod(EVP_PKEY *priv, EVP_PKEY *pub) {
  int match;

  RSA *privrsa = EVP_PKEY_get1_RSA(priv);
  BIGNUM *privrsa_mod = privrsa->n;
  char *privrsa_mod_hex = BN_bn2hex(privrsa_mod);

  RSA *pubrsa = EVP_PKEY_get1_RSA(pub);
  BIGNUM *pubrsa_mod = pubrsa->n;
  char *pubrsa_mod_hex = BN_bn2hex(pubrsa_mod);

  printf("priv: %s\n", privrsa_mod_hex);
  printf("pub: %s\n", pubrsa_mod_hex);

  if(strcmp(privrsa_mod_hex, pubrsa_mod_hex) == 0)
    match = 0; // the keys modulus is matching
  else
    match = 1; // the keys modulus don't match

  OPENSSL_free(privrsa_mod_hex);
  OPENSSL_free(pubrsa_mod_hex);
  RSA_free(privrsa);
  RSA_free(pubrsa);
  return match;
}

int main() {

  const char cert_filestr[] = "./cert.pem";
  const char pkey_filestr[] = "./pkey.pem";
  const char cleartextstr[] = "This line will be encrypted and, if keys match, it decrypts again.";

          EVP_PKEY *privkey = NULL;
           EVP_PKEY *pubkey = NULL;
  BIO              *certbio = NULL;
  BIO              *pkeybio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  int i, enc_len, dec_len;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  pkeybio = BIO_new(BIO_s_file());
  outbio  = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory\n");
    exit(-1);
  }

  /* ---------------------------------------------------------- *
   * Load the private key from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(pkeybio, pkey_filestr);
  if (! (privkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading private key into memory\n");
    exit(-1);
  }

  /* ---------------------------------------------------------- *
   * Extract the certificate's public key data.                 *
   * ---------------------------------------------------------- */
  if ((pubkey = X509_get_pubkey(cert)) == NULL) {
    BIO_printf(outbio, "Error getting public key from certificate");
    exit(-1);
  }

  /* ---------------------------------------------------------- *
   * Print the public key information and the key in PEM format *
   * ---------------------------------------------------------- */
  /* display the key type and size here */
  if (pubkey) {
    teststr_len = strlen(cleartextstr);
    BIO_printf(outbio, "Cleartext string [%d bytes]:\n\"%s\"\n\n",
                       (int) teststr_len, cleartextstr);

    switch (pubkey->type) {
      case EVP_PKEY_RSA:
        BIO_printf(outbio, "Encrypting with RSA public key [%d bit]. ", EVP_PKEY_bits(pubkey));
        enc_len = RSAencrypt(pubkey, cleartextstr);
        BIO_printf(outbio, "Encrypted data [%d bytes]:\n", enc_len);
        for(i=0;i<enc_len;i++) { BIO_printf(outbio, "%02x ", encdata[i]); }

        BIO_printf(outbio, "\n\nDecrypting with RSA private key [%d bit]. ", EVP_PKEY_bits(privkey));
        dec_len = RSAdecrypt(privkey, enc_len);
        if (dec_len == -1) 
         BIO_printf(outbio, "Failure: Keys don't match!");
        else {
          BIO_printf(outbio, "Decrypted data [%d bytes]:\n\"%s\"\n", dec_len, decdata);
        }
        RSAcmp_mod(privkey, pubkey);
        break;
      case EVP_PKEY_EC:
        BIO_printf(outbio, "%d bit EC Key\n\n", EVP_PKEY_bits(pubkey));
        //sig = ECsign();
        //BIO_printf(outbio, "\n\nVerifying signature with EC private key [%d bit]. ", EVP_PKEY_bits(privkey));
        //dec_len = RSAdecrypt(privkey, enc_len);
        break;
      default:
        BIO_printf(outbio, "%d bit unknown Key.\n\n", EVP_PKEY_bits(pubkey));
        exit(-1);
        break;
    }
  }

  //if(!PEM_write_bio_PUBKEY(outbio, pubkey))
 //   BIO_printf(outbio, "Error writing public key data in PEM format");

  EVP_PKEY_free(pubkey);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}

/* ---------------------------------------------------------- *
 * RSA encrypt the teststring with the certificate public key *
 * ---------------------------------------------------------- */
int RSAencrypt(EVP_PKEY *key, const char *teststring) {
  int keysize, rsa_outlen = 0;
  RSA *pubrsa = NULL;

  pubrsa = EVP_PKEY_get1_RSA(key);
  keysize = RSA_size(pubrsa);
  encdata = OPENSSL_malloc(keysize);

  rsa_outlen = RSA_public_encrypt(teststr_len, teststring, encdata, pubrsa, pad);

  RSA_free(pubrsa);
  return rsa_outlen;
}

/* ---------------------------------------------------------- *
 * Decrypt a teststring with the certificate private key      *
 * ---------------------------------------------------------- */
int RSAdecrypt(EVP_PKEY *key, int rsa_inlen) {
  int keysize, rsa_outlen = 0;
  RSA *privrsa = NULL;

  privrsa = EVP_PKEY_get1_RSA(key);
  keysize = RSA_size(privrsa);
  decdata = OPENSSL_malloc(keysize);

  rsa_outlen = RSA_private_decrypt(rsa_inlen, encdata, decdata, privrsa, pad);

  RSA_free(privrsa);
  return rsa_outlen;
}

/* ---------------------------------------------------------- *
 * Sign the teststring with the certificate public key        *
 * ---------------------------------------------------------- */
  ECDSA_SIG *ECsign(EVP_PKEY *key, const char *teststring) {
  ECDSA_SIG *sig;
  EC_KEY *pubeckey = NULL;

  pubeckey = EVP_PKEY_get1_EC_KEY(key);
  sig = ECDSA_do_sign(teststring, teststr_len, pubeckey);

  EC_KEY_free(pubeckey);
  return sig;
}

/* ---------------------------------------------------------- *
 * Validate the signature with the certificate private key    *
 * ---------------------------------------------------------- */
int ECverify(EVP_PKEY *key, const char *teststring, ECDSA_SIG *sig) {
  EC_KEY *priveckey = NULL;

  priveckey = EVP_PKEY_get1_EC_KEY(key);
  ret = ECDSA_do_verify(teststring, teststr_len, sig, priveckey);

  EC_KEY_free(priveckey);
  return ret;
}
