/* ------------------------------------------------------------ *
 * file:        keytest.c                                       *
 * purpose:     tests for reading private keys under OpenSSL    *
 * author:      02/23/2004 Frank4DD                             * 
 *                                                              *
 * compile:     gcc -o keytest keytest.c -lssl -lcrypto         *            
 * ------------------------------------------------------------ */

#include <stdio.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define CERTKEY  "./demo/cert-file.key"

int main() {
   EVP_PKEY *pkey;
   FILE *fp;
   const char *type;
   int keysize = 0;

   /* ---------------------------------------------------------- *
    * Read private key from file into EVP_KEY structure          *
    * ---------------------------------------------------------- */
   pkey = EVP_PKEY_new();
   fp = fopen (CERTKEY, "r");
   PEM_read_PrivateKey( fp, &pkey, NULL, NULL);
   printf("Key File: %s loaded\n", CERTKEY);
   fclose(fp);

   /* ---------------------------------------------------------- *
    * Check the key type we loaded from file                     *
    * values are in evp.h: NONE RSA RSA2 DSA DSA1 DSA2 DSA3 DSA4 *
    * DH DHX EC HMAC CMAC SCRYPT.. All prefixed with EVP_KEY_xxx *
    * ---------------------------------------------------------- */
   int keyid = EVP_PKEY_get_id(pkey);
   if (EVP_PKEY_is_a(pkey, "RSA")) {
      type = "RSA";
      keysize = EVP_PKEY_get_bits(pkey);
   }
   else if (EVP_PKEY_is_a(pkey, "EC")) {
      keysize = EVP_PKEY_size(pkey);
   }

  /* ---------------------------------------------------------- *
   * Validate key parameters are correct, e.g. for RSA n = p*q  *
   * ---------------------------------------------------------- */
  EVP_PKEY_CTX *ctx;
  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if(EVP_PKEY_check(ctx) == 1)
     printf("Keycheck: validation success\n");
  else
     printf("Keycheck: validation failed\n");

  /* ---------------------------------------------------------- *
   * Here we print the key length and the curve type            *
   * ---------------------------------------------------------- */
  printf("Key Info: type %d %s with %d bits\n", keyid, type, keysize);

  /* ---------------------------------------------------------- *
   * Here we print the private/public key data in PEM format.   *
   * ---------------------------------------------------------- */
  if(!PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, 0, NULL))
    printf("Error writing private key data in PEM format");

  if(!PEM_write_PUBKEY(stdout, pkey))
    printf("Error writing public key data in PEM format");
  exit(0);
}
