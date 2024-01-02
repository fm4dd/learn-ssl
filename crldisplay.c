/* ------------------------------------------------------------ *
 * file:        crldisplay.c                                    *
 * purpose:     Example code how to display the content of a    *
 *              Certificate Revocation List (CRL) from a local  *
 *              file. Here I used the CRL file saved from URL   *
 *              http://webcert.fm4dd.com/webcert.crl, converted *
 *              into DER format.                                *
 * author:      02/01/2015 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o crldisplay crldisplay.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int main() {
  const char    crl_filestr[] = "./demo/webcert-crl.der";
  BIO                 *crlbio = NULL;
  BIO                 *outbio = NULL;
  X509_CRL            *mycrl  = NULL;
  X509_NAME           *issuer = NULL;
  STACK_OF(X509_REVOKED) *rev = NULL;
  X509_REVOKED     *rev_entry = NULL;
  X509_EXTENSION      *reason = NULL;
  const ASN1_BIT_STRING *asn1_sig = NULL;
  const X509_ALGOR      *sig_type = NULL;
  size_t                sig_bytes = 0;
  char         sig_type_str[1024] = "";
  const ASN1_TIME *last_update, *next_update;
  const ASN1_INTEGER *ser = NULL;
  BIGNUM *bn = NULL;
  int i, extnum, revnum;
  long version;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  crlbio = BIO_new(BIO_s_file());
  outbio = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the certificate revocation list from file (DER).      *
   * ---------------------------------------------------------- */
  if (BIO_read_filename(crlbio, crl_filestr) <= 0) {
    BIO_printf(outbio, "Error loading CRL file into memory: %s\n", crl_filestr);
    exit(1);
  }

  if ((mycrl = X509_CRL_new()) == NULL) {
    BIO_printf(outbio, "Error creating a new CRL object\n");
    exit(1);
  }
  BIO_printf(outbio, "Successful creation of a new empty CRL object\n");

  if((mycrl = d2i_X509_CRL_bio(crlbio, NULL)) == NULL) {
    BIO_printf(outbio, "Error loading CRL object data.\n");
    exit(1);
  }
  BIO_printf(outbio, "CRL %s converted to internal BIO object\n", crl_filestr);

  /* ---------------------------------------------------------- *
   * Print the CRL Version Number                               *
   * ---------------------------------------------------------- */
  version = X509_CRL_get_version(mycrl);
  BIO_printf(outbio, "This CRL Version Num: %lu (0x%lx)\n", version+1, version);

  /* ---------------------------------------------------------- *
   * Print the CRL Issuer Information                           *
   * ---------------------------------------------------------- */
  issuer = X509_NAME_new();
  issuer = X509_CRL_get_issuer(mycrl);
  BIO_printf(outbio, "This CRL Issuer Info: ");
  X509_NAME_print_ex(outbio, issuer, 0, XN_FLAG_ONELINE);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Print the CRL Issue Date and Time                          *
   * ---------------------------------------------------------- */
  if ((last_update = X509_CRL_get0_lastUpdate(mycrl))) {
    BIO_printf(outbio, "This CRL Release Date: ");
    ASN1_TIME_print(outbio, last_update);
    BIO_printf(outbio, "\n");
  }

  /* ---------------------------------------------------------- *
   * Print the CRL Next Release Date and Time                   *
   * ---------------------------------------------------------- */
  if ((next_update = X509_CRL_get0_nextUpdate(mycrl))) {
    BIO_printf(outbio, "Next CRL Release Date: ");
    ASN1_TIME_print(outbio, next_update);
    BIO_printf(outbio, "\n");
  }

  /* ---------------------------------------------------------- *
   * Print the CRL Signature Algorithm                          *
   * ---------------------------------------------------------- */
  X509_CRL_get0_signature(mycrl, &asn1_sig, &sig_type);
  sig_bytes = asn1_sig->length;
  OBJ_obj2txt(sig_type_str, sizeof(sig_type_str), sig_type->algorithm, 0);

  BIO_printf(outbio, " CRL Signature Format: %s\n", sig_type_str);
  BIO_printf(outbio, " CRL Signature Length: %d Bytes\n", (int) sig_bytes);

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
   * Print the revoked Cert Info if avail. Limit output to 10   *
   * ---------------------------------------------------------- */
  if (revnum > 0 && revnum > 10) revnum = 10;

  for(i=0; i<revnum; i++) {
    rev_entry = sk_X509_REVOKED_value(rev, i);
    if(rev_entry == NULL)
       BIO_printf(outbio, "Error getting rewvoked cert info for: %d\n", i);

    /* ---------------------------------------------------------- *
     * Get cert serial from the revocation entry                  *
     * ---------------------------------------------------------- */
    ser = X509_REVOKED_get0_serialNumber(rev_entry);

    /* ---------------------------------------------------------- *
     * Convert the serial to a hex string                         *
     * ---------------------------------------------------------- */
    char *serialstr = BN_bn2hex(ASN1_INTEGER_to_BN(ser, bn));

    BIO_printf(outbio, "Revocation #: %d S/N: %s", i, serialstr);
    BIO_printf(outbio, " Date: ");
    ASN1_TIME_print(outbio, X509_REVOKED_get0_revocationDate(rev_entry));

    /* ---------------------------------------------------------- *
     * try to get the CRL reason, if the extension exists         *
     * ---------------------------------------------------------- */
    int loc = -1;
    loc = X509_REVOKED_get_ext_by_NID(rev_entry, NID_crl_reason, -1);
    reason = X509_REVOKED_get_ext(rev_entry, loc);
    if (loc > -1) X509V3_EXT_print(outbio, reason, 0, 2);
    BIO_printf(outbio, "\n");
  }

  X509_CRL_free(mycrl);
  BIO_free_all(crlbio);
  BIO_free_all(outbio);
  exit(0);
}
