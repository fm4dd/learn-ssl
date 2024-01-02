/* ------------------------------------------------------------ *
 * file:        set_asn1_time.c                                 *
 * purpose:     Example how to set a specific ASN1 date & time  *
 * author:      11/28/2012 Frank4DD                             *
 *                                                              *
 * compile: gcc -o set_asn1_time set_asn1_time.c -lssl -lcrypto *
 * ------------------------------------------------------------ */

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <time.h>

int main() {

  const char timestr[] = "20121018162433Z";
  BIO          *outbio = NULL;
  ASN1_TIME *str_asn1time, *now_asn1time;

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Set the ASN1 date & time structure                         *
   * ---------------------------------------------------------- */
  str_asn1time = ASN1_TIME_new();
  now_asn1time = ASN1_TIME_new();

  if (! ASN1_TIME_set_string(str_asn1time, timestr))
        BIO_printf(outbio, "Error date is invalid, should be YYYYMMDDHHMMSSZ");

  ASN1_TIME_set(now_asn1time, time(NULL));

  /* ---------------------------------------------------------- *
   * Print the ASN1 date and time here                          *
   * ---------------------------------------------------------- */
  BIO_printf(outbio, "Set ASN1 date & time from String: ");
  if (!ASN1_TIME_print(outbio, str_asn1time))
    BIO_printf(outbio, "Error printing ASN1 time");
  else
    BIO_printf(outbio, "\n");

  BIO_printf(outbio, "Set ASN1 date & time from time(): ");
  if (!ASN1_TIME_print(outbio, now_asn1time))
    BIO_printf(outbio, "Error printing ASN1 time");
  else
    BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */
  ASN1_TIME_free(str_asn1time);
  ASN1_TIME_free(now_asn1time);
  BIO_free_all(outbio);
  exit(0);
}
