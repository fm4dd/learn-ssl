/* ------------------------------------------------------------ *
 * file:        certsignature.c                                 *
 * purpose:     Example to extract and display cert signatures  *
 * author:      09/30/2012 Frank4DD                             *
 *                                                              *
 * compile: gcc -o certsignature certsignature.c -lssl -lcrypto *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>


/* ---------------------------------------------------------- *
 * This function is taken from openssl/crypto/asn1/t_x509.c.  *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);

int main() {

  const char cert_filestr[] = "./cert-file.pem";
  ASN1_STRING     *asn1_sig = NULL;
  X509_ALGOR      *sig_type = NULL;
  size_t          sig_bytes = 0;
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
   * Extract the certificate's signature data.                  *
   * ---------------------------------------------------------- */
  sig_type = cert->sig_alg;
  asn1_sig = cert->signature;
  sig_bytes = asn1_sig->length;

  /* ---------------------------------------------------------- *
   * Print the signature type here                              *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "Signature Algorithm:\n");
  if (i2a_ASN1_OBJECT(outbio, sig_type->algorithm) <= 0)
    BIO_printf(outbio, "Error getting the signature algorithm.\n");
  else BIO_puts(outbio, "\n\n");

  /* ---------------------------------------------------------- *
   * Print the signature length here                            *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "Signature Length:\n%d Bytes\n\n", sig_bytes);

  /* ---------------------------------------------------------- *
   * Print the signature data here                              *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "Signature Data:");
  if (X509_signature_dump(outbio, asn1_sig, 0) != 1)
    BIO_printf(outbio, "Error printing the signature data\n"); 

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}

/* ---------------------------------------------------------- *
 * X509_signature_dump() converts binary signature data into  *
 * hex bytes, separated with : and a newline after 54 chars.  *
 * (2 chars + 1 ':' = 3 chars, 3 chars * 18 = 54)             *
 * ---------------------------------------------------------- */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent) {
  const unsigned char *s;
  int i, n;

  n=sig->length;
  s=sig->data;
  for (i=0; i<n; i++) {
    if ((i%18) == 0) {
      if (BIO_write(bp,"\n",1) <= 0) return 0;
      if (BIO_indent(bp, indent, indent) <= 0) return 0;
    }
    if (BIO_printf(bp,"%02x%s",s[i],
      ((i+1) == n)?"":":") <= 0) return 0;
  }

  if (BIO_write(bp,"\n",1) != 1) return 0;

  return 1;
}
