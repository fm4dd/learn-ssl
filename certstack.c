/* ------------------------------------------------------------ *
 * file:        certstack.c                                     *
 * purpose:     Example how to handle a pile of CA certificates *
 * author:      07/18/2012 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o certstack certstack.c -lssl -lcrypto     *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {

  STACK_OF(X509_INFO) *certstack;
  const char   ca_filestr[] = "./demo/ca-bundle.pem";
  X509_INFO *stack_item     = NULL;
  X509_NAME    *certsubject = NULL;
  BIO             *stackbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  int i;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  stackbio = BIO_new(BIO_s_file());
  outbio   = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the file with the list of certificates in PEM format  *
   * ---------------------------------------------------------- */
  if (BIO_read_filename(stackbio, ca_filestr) <= 0) {
    BIO_printf(outbio, "Error loading cert bundle into memory: %s\n", ca_filestr);
    exit(1);
  }

  certstack = PEM_X509_INFO_read_bio(stackbio, NULL, NULL, NULL);

  /* ---------------------------------------------------------- *
   * Count the number of certs that are now on the stack        *
   * ---------------------------------------------------------- */
   BIO_printf(outbio, "# of stack certs: %d\n",
                      sk_X509_INFO_num(certstack));

  /* ---------------------------------------------------------- *
   * Cycle through the stack to display various cert data       *
   * ---------------------------------------------------------- */
  for (i = 0; i < sk_X509_INFO_num(certstack); i++) {
    char subject_cn[256] = "** n/a **";
    long cert_version;

    stack_item = sk_X509_INFO_value(certstack, i);

    certsubject = X509_get_subject_name(stack_item->x509);
    X509_NAME_get_text_by_NID(certsubject, NID_commonName,
                                           subject_cn, 256);
    cert_version = (X509_get_version(stack_item->x509)+1);

    BIO_printf(outbio, "Cert #%.2d v%ld CN: %.70s\n", i, 
                                  cert_version, subject_cn);
  }

  /* ---------------------------------------------------------- *
   * Free up the resources                                      *
   * ---------------------------------------------------------- */
  sk_X509_INFO_pop_free(certstack, X509_INFO_free);
  X509_free(cert);
  BIO_free_all(stackbio);
  BIO_free_all(outbio);
  exit(0);
}
