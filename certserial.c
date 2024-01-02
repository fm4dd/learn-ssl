/* ------------------------------------------------------------ *
 * file:        certserial.c                                    *
 * purpose:     Example code for OpenSSL certificate serials    *
 * author:      06/12/2012 Frank4DD                             *
 *                                                              *
 * compile:     gcc -o certserial certserial.c -lssl -lcrypto   *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

int main() {

  const char cert_filestr[] = "./demo/cert-file.pem";
  ASN1_INTEGER *asn1_serial = NULL;
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  const char *neg;
  int  i;
  long l;

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
   * Extract the certificate's serial number.                   *
   * ---------------------------------------------------------- */
   asn1_serial = X509_get_serialNumber(cert);
   if (asn1_serial == NULL)
     BIO_printf(outbio, "Error getting serial number from certificate");

  /* ---------------------------------------------------------- *
   * Print the serial number value, openssl x509 -serial style  *
   * ---------------------------------------------------------- */
  BIO_puts(outbio,"serial (openssl x509 -serial style): ");
  i2a_ASN1_INTEGER(outbio, asn1_serial);
  BIO_puts(outbio,"\n");

  /* ---------------------------------------------------------- *
   * Print the serial number value, openssl x509 -text style    *
   * ---------------------------------------------------------- */
  if (asn1_serial->length <= (int)sizeof(long)) {
    l=ASN1_INTEGER_get(asn1_serial);
    if (asn1_serial->type == V_ASN1_NEG_INTEGER) {
      l= -l;
      neg="-";
    }
    else neg="";

    if (BIO_printf(outbio," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
      BIO_printf(outbio, "Error during printing the serial.\n");
  } else {
    neg=(asn1_serial->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
    //if (BIO_printf(outbio,"\n%12s%s","",neg) <= 0)
    if (BIO_printf(outbio,"serial (openssl x509 -text   style): %s ",neg) <= 0)
      BIO_printf(outbio, "Error during printing the serial.\n");

    for (i=0; i<asn1_serial->length; i++) {
     if (BIO_printf(outbio,"%02x%c",asn1_serial->data[i],
        ((i+1 == asn1_serial->length)?'\n':':')) <= 0)
      BIO_printf(outbio, "Error during printing the serial.\n");
    }
  }

  X509_free(cert);
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}
