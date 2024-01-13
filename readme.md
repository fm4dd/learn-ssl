## OpenSSL API Examples

![test](https://github.com/fm4dd/learn-ssl/workflows/test/badge.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://opensource.org/licenses/MIT)

### Introduction

The programs were originally written between 2007 and 2015 with OpenSSL version 1.0.
At that time, OpenSSL's documentation  was sparse, which led to the creation of sample programs that demonstrate various functions and enable "learning by doing".

The programs were updated to OpenSSL 3.0.11 on Debian 12 under gcc version 12.2.0.
The programs have hardcoded key and certificate input files, which are located in the demo folder.

### List of Example Programs

| # | Name | Description |
|---|------|-------------|
| 1 | [add_ev_oids.c](add_ev_oids.c) | How to add extra/missing OID's to OpenSSL's internal NID table structure |
| 2 | [certcreate.c](certcreate.c) | How to create a X509 digital certificate from a CSR request |
| 3 | [certextensions.c](certextensions.c) | How to extract certificate extensions from a X509 digital certificate |
| 4 | [certfprint.c](certfprint.c) | How to generate the fingerprint hash of a X509 digital certificate |
| 5 | [certpubkey.c](certpubkey.c) | How to extract public key data from a X509 digital certificate |
| 6 | [certrenewal.c](certrenewal.c) | How to create a new CSR request from a existing X509 digital certificate |
| 7 | [certserial.c](certserial.c) | How to extract the serial number from a X509 digital certificate |
| 8 | [certsignature.c](certsignature.c) | How to extract the signature data from a X509 digital certificate |
| 9 | [certstack.c](certstack.c) | How to load a list of certificates, and display various subject data |
| 10 | [certverify.c](certverify.c) | How to validate a X509 certificate against a CA cert or chain |
| 11 | [certverify-adv.c](certverify-adv.c) | 2nd version how to validate a X509 certificate against a CA cert or chain |
| 12 | [crldisplay.c](crldisplay.c) | How to extract and display data from a certificate revocation list (DER CRL) |
| 13 | [eckeycreate.c](eckeycreate.c) | How to create and display elliptic curve cryptography (ECC) key pairs |
| 14 | [keycompare.c](keycompare.c) | How to  check if a private key belongs to a X509 digital certificate |
| 15 | [keytest.c](keytest.c) | How to load and display a SSL private key using OpenSSL libraries |
| 16 | [pkcs12test.c](pkcs12test.c) | How to create a PKCS12 cert bundle (e.g. for use with Windows S/MIME) |
| 17 | [set_asn1_time.c](set_asn1_time.c) | How to create/set the ASN1 date and time for X509 digital certificates |
| 18 | [sslconnect.c](sslconnect.c) | How to make a basic SSL/TLS connection and get the servers certificate |

### Notes

With small modificiations they are reported to work also under Windows and OSX.
See also http://fm4dd.com/openssl/

