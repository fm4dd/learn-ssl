/*--------------------------------------------------------------*
 * file:        pkcs12test.c                                    *
 * purpose:     tests creating a pkcs12 certifcate bundle for   *
 *              use with Windows S/MIME                         *
 * author:      12/13/2007 Frank4DD                             *
 *                                                              *
 * compile:     gcc pkcs12test.c -o pkcs12test -lssl -lcrypto   *
 * ------------------------------------------------------------ */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

#define CERTKEY  "./demo/cert-file.key"
#define CERTFILE "./demo/cert-file.pem"
#define CAFILE   "./demo/cacert.pem"
#define P12FILE  "./demo/demo.p12"

int main() {
   X509		  *cert, *cacert;
   STACK_OF(X509) *cacertstack;
   PKCS12	  *pkcs12bundle;
   EVP_PKEY	  *cert_privkey;
   FILE 	  *cacertfile, *certfile, *keyfile, *pkcs12file;
   int		  ret, bytes = 0;
   struct stat    fstat;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
/* ------------------------------------------------------------ *
 * 1.) These function calls are essential to make PEM_read and  *
 *     other openssl functions work.                            *
 * ------------------------------------------------------------ */
   OpenSSL_add_all_algorithms();
   ERR_load_crypto_strings();
#endif

/*--------------------------------------------------------------*
 * 2.) we load the certificates private key                     *
 *    ( for this test, it has no password )                     *
 *--------------------------------------------------------------*/
   if ((cert_privkey = EVP_PKEY_new()) == NULL)
      printf("Error creating EVP_PKEY structure.\n");
   if (! (keyfile = fopen(CERTKEY, "r"))) {
      printf("Error cant read certificate private key file: %s\n", CERTKEY);
      exit(1);
   }
   if (! (cert_privkey = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL)))
      printf("Error loading certificate private key content.\n");
   fclose(keyfile);

/*--------------------------------------------------------------*
 * 3.) we load the corresponding certificate                    *
 *--------------------------------------------------------------*/
   if (! (certfile = fopen(CERTFILE, "r"))) {
      printf("Error cant read certificate file: %s\n", CERTFILE);
      exit(1);
   }
   if (! (cert = PEM_read_X509(certfile, NULL, NULL, NULL)))
      printf("Error loading cert into memory.\n");
   fclose(certfile);

/*--------------------------------------------------------------*
 * 4.) we load the CA certificate who signed it                 *
 *--------------------------------------------------------------*/
   if (! (cacertfile = fopen(CAFILE, "r"))) {
      printf("Error cant read ca certificate file: %s\n", CAFILE);
      exit(1);
   }
   if (! (cacert = PEM_read_X509(cacertfile,NULL,NULL,NULL)))
      printf("Error loading CA certificate into memory.\n");
   fclose(cacertfile);

/*--------------------------------------------------------------*
 * 5.) we load the CA certificate on the stack                  *
 *--------------------------------------------------------------*/
   if ((cacertstack = sk_X509_new_null()) == NULL)
      printf("Error creating STACK_OF(X509) structure.\n");
   sk_X509_push(cacertstack, cacert);

/*--------------------------------------------------------------*
 * 6.) we create the PKCS12 structure and fill it with our data *
 *--------------------------------------------------------------*/
   if ((pkcs12bundle = PKCS12_new()) == NULL)
      printf("Error creating PKCS12 structure.\n");

   /* values of zero use the openssl default values */
   pkcs12bundle = PKCS12_create(
          "test",      // certbundle access password
          "pkcs12test",// friendly certname
          cert_privkey,// the certificate private key
          cert,        // the main certificate
          cacertstack, // stack of CA cert chain
          0,           // int nid_key (default 3DES)
          0,           // int nid_cert (40bitRC2)
          0,           // int iter (default 2048)
          0,           // int mac_iter (default 1)
          0            // int keytype (default no flag)
   );
   if ( pkcs12bundle == NULL)
      printf("Error generating a valid PKCS12 certificate.\n");

/*--------------------------------------------------------------*
 * 7.) we write the PKCS12 structure out to file                *
 *--------------------------------------------------------------*/
   if (! (pkcs12file = fopen(P12FILE, "w"))) {
      printf("Error cant open pkcs12 file for writing: %s\n", P12FILE);
      exit(1);
   }
   ret = i2d_PKCS12_fp(pkcs12file, pkcs12bundle);
   if (ret == 0) {
      printf("Error writing PKCS12 certificate.\n");
      exit(1);
   }

/*--------------------------------------------------------------*
 * 8.) we are done, let's clean up                              *
 *--------------------------------------------------------------*/
   fclose(pkcs12file);
   X509_free(cert);
   X509_free(cacert);
   sk_X509_free(cacertstack);
   PKCS12_free(pkcs12bundle);

   /* get file status data */
   if (stat(P12FILE, &fstat) != 0) {
      printf("Error cannot stat p12 file: %s\n", P12FILE);
      printf("%s\n", strerror(errno));
      exit(1);
   }
   
   bytes = fstat.st_size;
   printf("Created PKCS12 file %s with %d Bytes.\n", P12FILE, bytes);

   return(0);
}

/*--------------------------------------------------------------*
 * Before running the compiled program, make sure you have the  *
 * following required files in the same directory:              *
 * cacert.pem + testkey.pem + testcert.pem                      *
 * Below is a quick reference how to create them with openssl:  *
 *--------------------------------------------------------------*

 *--------------------------------------------------------------*
 * Create a RSA key pair file                                   *
 *--------------------------------------------------------------*
 > openssl genrsa -out testkey.pem 1024

 *--------------------------------------------------------------*
 * Create a Certificate Request                                 *
 *--------------------------------------------------------------*
 > openssl req -new -key ./testkey.pem -out ./testcert.req

 *--------------------------------------------------------------*
 * Sign the Certificate Request and create a Certificate        *
 *--------------------------------------------------------------*
 > openssl ca -in ./testcert.req -out ./testcert.pem

 *--------------------------------------------------------------*
 * Run the pkcs12test program. If successful, a new file named  *
 * testcert.p12 has been generated. Its functionality can be    *
 * validated by importing it into Internet Explorer, using the  *
 * password "test".                                             *
 *--------------------------------------------------------------*/
