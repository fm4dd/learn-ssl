/* ------------------------------------------------------------ *
 * file:        certpubkey.c                                    *
 * purpose:     Example code to extract public keydata in certs *
 * author:      09/24/2012 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o certpubkey certpubkey.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {

  const char cert_filestr[] = "./cert-file.pem";
             EVP_PKEY *pkey = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  int ret;

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
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate from file (PEM).                      *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL)))
    BIO_printf(outbio, "Error loading cert into memory\n");

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
    switch (pkey->type) {
      case EVP_PKEY_RSA:
        BIO_printf(outbio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
        break;
      case EVP_PKEY_DSA:
        BIO_printf(outbio, "%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
        break;
      default:
        BIO_printf(outbio, "%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
        break;
    }
  }

  if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");

  X509_free(cert);
  EVP_PKEY_free(pkey);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}
