/* ------------------------------------------------------------ *
 * file:        certfprint.c                                    *
 * purpose:     Example code creating certificate fingerprints  *
 * author:      06/12/2012 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o certfprint certfprint.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {
  const char cert_filestr[] = "./cert-file.pem";
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  const EVP_MD *fprint_type = NULL;
  int ret, j, fprint_size;
  unsigned char fprint[EVP_MAX_MD_SIZE];

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
   * Set the digest method and calculate the cert fingerprint   *
   * SHA-1 creates a 160bit hash, displayed as a 20 byte string *
   * ---------------------------------------------------------- */
  fprint_type = EVP_sha1();

  if (!X509_digest(cert, fprint_type, fprint, &fprint_size))
    BIO_printf(outbio,"Error creating the certificate fingerprint.\n");

  /* ---------------------------------------------------------- *
   * Print the certificate fingerprint method, length and value *
   * ---------------------------------------------------------- */
  BIO_printf(outbio,"Fingerprint Method: %s\n", 
    OBJ_nid2sn(EVP_MD_type(fprint_type)));

  BIO_printf(outbio,"Fingerprint Length: %d\n", fprint_size);

  /* Microsoft Thumbprint-style: lowercase hex bytes with space */
  BIO_printf(outbio,"Fingerprint String: ");
  for (j=0; j<fprint_size; ++j) BIO_printf(outbio, "%02x ", fprint[j]);
  BIO_printf(outbio,"\n");

  /* OpenSSL fingerprint-style: uppercase hex bytes with colon */
  //for (j=0; j<fprint_size; j++) {
  //  BIO_printf(outbio,"%02X%c", fprint[j], (j+1 == fprint_size) ?'\n':':');
  //}

  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}
