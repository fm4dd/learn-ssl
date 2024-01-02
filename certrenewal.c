/* ------------------------------------------------------------ *
 * file:        certrenewal.c                                   *
 * purpose:     Example code for OpenSSL certificate renewal    *
 * author:      10/28/2012 Frank4DD                             *
 * based on:    openssl-[x.x.x]/apps/crypto/x509/x509_req.c     *
 *                                                              *
 * compile:     gcc -o certrenewal certrenewal.c -lssl -lcrypto *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {

  const char cert_filestr[] = "./demo/cert-file.pem";
  const char pkey_filestr[] = "./demo/cert-file.key";
  BIO              *certbio = NULL;
  BIO              *pkeybio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_REQ         *certreq = NULL;
  EVP_PKEY            *pkey = NULL;
  EVP_MD      const *digest = EVP_sha1();
  int ret;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  pkeybio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the old certificate from file (PEM).                  *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(certbio, cert_filestr);
  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory: %s\n", cert_filestr);
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Load the original private key from file (PEM).             *
   * ---------------------------------------------------------- */
  ret = BIO_read_filename(pkeybio, pkey_filestr);
  if(ret == 0) {
    BIO_printf(outbio, "Error loading private key into BIO: %s\n", pkey_filestr);
    exit(1);
  }

  if (! (pkey = PEM_read_bio_PrivateKey(pkeybio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading private key into memory: %s\n", pkey_filestr);
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Convert the old certificate into a new request             *
   * Returns NULL on error                                      *
   * ---------------------------------------------------------- */
  if ((certreq = X509_to_X509_REQ(cert, pkey, digest)) == NULL) {
    BIO_printf(outbio, "Error converting certificate into request.\n");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Print the new certificate request (PEM)                    *
   * ---------------------------------------------------------- */
  PEM_write_bio_X509_REQ(outbio, certreq);

  X509_free(cert);
  X509_REQ_free(certreq);
  EVP_PKEY_free(pkey);
  BIO_free_all(certbio);
  BIO_free_all(pkeybio);
  BIO_free_all(outbio);
  exit(0);
}
