/* ------------------------------------------------------------ *
 * file:        crldisplay.c                                    *
 * purpose:     Example code how to display the content of a    *
 *              Certificate Revocation List (CRL) from a local  *
 *              file. Here I used the CRL file saved from URL   *
 *              http://EVIntl-crl.verisign.com/EVIntl2006.crl   *
 * author:      02/01/2015 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o crldisplay crldisplay.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>

int main() {
  const char    crl_filestr[] = "./EVIntl2006.crl";
  BIO                 *crlbio = NULL;
  BIO                 *outbio = NULL;
  X509_CRL            *mycrl  = NULL;
  X509_NAME           *issuer = NULL;
  STACK_OF(X509_REVOKED) *rev = NULL;
  X509_REVOKED     *rev_entry = NULL;
  ASN1_TIME *last_update, *next_update;
  int i, sig, extnum, revnum;
  long version;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  crlbio = BIO_new(BIO_s_file());
  outbio = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate revocation list from file (DER).      *
   * ---------------------------------------------------------- */
  if (BIO_read_filename(crlbio, crl_filestr) <= 0)
    BIO_printf(outbio, "Error loading cert into memory\n");

  mycrl = d2i_X509_CRL_bio(crlbio, NULL);

  /* ---------------------------------------------------------- *
   * Print the CRL Version Number                               *
   * ---------------------------------------------------------- */
  version = X509_CRL_get_version(mycrl);
  BIO_printf(outbio, "CRL Version: %lu (0x%lx)\n", version+1, version);

  /* ---------------------------------------------------------- *
   * Print the CRL Issuer Information                           *
   * ---------------------------------------------------------- */
  issuer = X509_NAME_new();
  issuer = X509_CRL_get_issuer(mycrl);
  BIO_printf(outbio, "CRL Issuer Details: ");
  X509_NAME_print_ex(outbio, issuer, 0, XN_FLAG_ONELINE);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Print the CRL Issue Date and Time                          *
   * ---------------------------------------------------------- */
  if (last_update = X509_CRL_get_lastUpdate(mycrl)) {
    BIO_printf(outbio, "This CRL Release Date: ");
    ASN1_TIME_print(outbio, last_update);
    BIO_printf(outbio, "\n");
  }

  /* ---------------------------------------------------------- *
   * Print the CRL Next Release Date and Time                   *
   * ---------------------------------------------------------- */
  if (next_update = X509_CRL_get_nextUpdate(mycrl)) {
    BIO_printf(outbio, "Next CRL Release Date: ");
    ASN1_TIME_print(outbio, next_update);
    BIO_printf(outbio, "\n");
  }

  /* ---------------------------------------------------------- *
   * Print the CRL Signature Algorithm                          *
   * ---------------------------------------------------------- */
  sig = OBJ_obj2nid(mycrl->sig_alg->algorithm);
  BIO_printf(outbio, " CRL Signature Format: %s\n",
             (sig == NID_undef) ? "NONE" : OBJ_nid2ln(sig));

  /* ---------------------------------------------------------- *
   * Print the Number of CRL Extensions (CRL may not have any)  *
   * ---------------------------------------------------------- */
  extnum = X509_CRL_get_ext_count(mycrl);
  BIO_printf(outbio, " Number of Extensions: %d\n", extnum);

  /* ---------------------------------------------------------- *
   * Print the Number of revoked Certs (CRL may not have any)   *
   * ---------------------------------------------------------- */
  rev = X509_CRL_get_REVOKED(mycrl);

  revnum = sk_X509_REVOKED_num(rev);
  BIO_printf(outbio, "Found # revoked certs: %d\n", revnum);

  /* ---------------------------------------------------------- *
   * Print the revoked Cert Info, if avail, but no more then 10 *
   * ---------------------------------------------------------- */
  if (revnum > 0 && revnum > 10) revnum = 10;

  for(i = 0; i < revnum; i++) {
    rev_entry = sk_X509_REVOKED_value(rev, i);
    BIO_printf(outbio, "Revocation #: %d S/N: ", i);
    i2a_ASN1_INTEGER(outbio, rev_entry->serialNumber);
    BIO_printf(outbio, " Date: ");
    ASN1_TIME_print(outbio, rev_entry->revocationDate);

    // entries *can* have extensions, e.g. the revocation reason
    X509V3_extensions_print(outbio, "extensions: ",
                            rev_entry->extensions, 0, 8);
    BIO_printf(outbio, "\n");
  }

  X509_CRL_free(mycrl);
  BIO_free_all(crlbio);
  BIO_free_all(outbio);
  exit(0);
}
