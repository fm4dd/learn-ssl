/* ------------------------------------------------------------ *
 * file:        add_ev_oids.c                                   *
 * purpose:     Example how to add OID's to OpenSSL internals   *
 * author:      10/03/2012 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o add_ev_oids add_ev_oids.c -lssl -lcrypto *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* ---------------------------------------------------------- *
 * This function adds missing OID's to the internal structure *
 * ---------------------------------------------------------- */
void add_missing_ev_oids();

int main() {

  const char cert_filestr[] = "./cert-file.pem";
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_NAME    *certsubject = NULL;
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
   * Print the certificate subject here                         *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "Before OBJ_create():\n");
  certsubject = X509_NAME_new();
  certsubject = X509_get_subject_name(cert);
  X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
  BIO_printf(outbio, "\n\n");

  add_missing_ev_oids();

  BIO_printf(outbio, "After OBJ_create():\n");
  certsubject = X509_NAME_new();
  certsubject = X509_get_subject_name(cert);
  X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}

/* ---------------------------------------------------------- *
 * OpenSSL seems to lack a few OID's used for EV certificates *
 * ---------------------------------------------------------- */
void add_missing_ev_oids() {
  int nid;
  /* --------------------------------------------------------- *
   * OBJ_create():                                             *
   * First field is the OID, which will be converted to DER    *
   * encoding. Next are the long and short description of      *
   * this OID. The descriptions will not be included as the    *
   * extension identifier, but the DER encoding of the OID.    *
   * --------------------------------------------------------- */
  nid = OBJ_create("1.3.6.1.4.1.311.60.2.1.1",
                   "ASN.1 - X520LocalityName as specified in RFC 3280",
                   "jurisdictionOfIncorporationLocalityName");

  nid = OBJ_create("1.3.6.1.4.1.311.60.2.1.2",
                   "ASN.1 - X520StateOrProvinceName as specified in RFC 3280",
                   "jurisdictionOfIncorporationStateOrProvinceName");

  nid = OBJ_create("1.3.6.1.4.1.311.60.2.1.3",
                   "ASN.1 - X520countryName as specified in RFC 3280",
                   "jurisdictionOfIncorporationCountryName");
}
