/* ------------------------------------------------------------ *
 * file:        certsignature.c                                 *
 * purpose:     Example to extract and display cert signatures  *
 * author:      09/30/2012 Frank4DD                             *
 * update:      03/17/2019 OpenSSL 1.1.x _get0_ function use    *
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

  const char       cert_filestr[] = "./demo/cert-file.pem";
  const ASN1_BIT_STRING *asn1_sig = NULL;
  const X509_ALGOR      *sig_type = NULL;
  size_t                sig_bytes = 0;
  BIO                    *certbio = NULL;
  BIO                     *outbio = NULL;
  X509                      *cert = NULL;

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
   * Extract the certificate's signature data.                  *
   * ---------------------------------------------------------- */
  X509_get0_signature(&asn1_sig, &sig_type, cert);
  //sig_type = cert->sig_alg;
  //asn1_sig = cert->signature;
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
  BIO_printf(outbio, "Signature Length:\n%ld Bytes\n\n", sig_bytes);

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
