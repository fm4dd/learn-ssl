/* ------------------------------------------------------------ *
 * file:        certextensions.c                                *
 * purpose:     Example code for OpenSSL certificate extensions *
 * author:      09/12/2012 Frank4DD                             *
 * based on:    openssl-<x.x.x>/crypto/asn1/t_x509.c            *
 *                                                              *
 * gcc -o certextensions certextensions.c -lssl -lcrypto        *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

int main() {

  const char cert_filestr[] = "./demo/cert-file.pem";
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  const STACK_OF(X509_EXTENSION) *ext_list;
  int i;

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
   * Extract the certificate's extensions                       *
   * ---------------------------------------------------------- */
  ext_list = X509_get0_extensions(cert);
  if(sk_X509_EXTENSION_num(ext_list) <= 0) return 1;

  /* ---------------------------------------------------------- *
   * Print the extension value                                  *
   * ---------------------------------------------------------- */
  for (i=0; i<sk_X509_EXTENSION_num(ext_list); i++) {
    ASN1_OBJECT *obj;
    X509_EXTENSION *ext;

    ext = sk_X509_EXTENSION_value(ext_list, i);

    obj = X509_EXTENSION_get_object(ext);
    BIO_printf(outbio, "\n");
    BIO_printf(outbio, "Object %.2d: ", i);
    i2a_ASN1_OBJECT(outbio, obj);
    BIO_printf(outbio, "\n");

    if (!X509V3_EXT_print(outbio, ext, 0, 2)) {
    /* Some extensions (i.e. LogoType) have no handling    *
     * defined, we need to print their content as hex data */
      BIO_printf(outbio, "%*s", 2, "");
      ASN1_STRING_print(certbio,(ASN1_STRING *)X509_EXTENSION_get_data(ext));
    }

    BIO_printf(outbio, "\n");
  }

  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}
