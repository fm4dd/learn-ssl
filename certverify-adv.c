/* ------------------------------------------------------------ *
 * file:        certverify-adv.c                                *
 * purpose:     Example code for OpenSSL certificate validation *
 * author:      06/12/2012 Frank4DD                             * 
 *                                                              *
 * gcc -o certverify-adv certverify-adv.c -lssl -lcrypto        *
 * ------------------------------------------------------------ */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define MAXFLAGS 15

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

/* ---------------------------------------------------------- *
 * verify_file_direct() uses X509_STORE_load_locations() to   * 
 * load the CA certs from file into the store struct, which   * 
 * is then passed to the CTX during the init.                 * 
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_file_direct(const char *file);

/* ---------------------------------------------------------- *
 * X509_load_ca_file() loads a CA file into a mem BIO using   * 
 * (BIO_read_filename(), PEM_X509_INFO_read_bio() puts them   * 
 * in a stack, which is then to be added to a store or CTX.   * 
 * ---------------------------------------------------------- */
STACK_OF(X509_INFO) *X509_load_ca_file(int *cert_counter,
                      struct stat fstat, const char *file);

/* ---------------------------------------------------------- *
 * verify_mem_store() puts the CA info stack into a store     *
 * struct, which is then passed to the CTX during the init.   *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_store(STACK_OF(X509_INFO) *st);

/* ---------------------------------------------------------- *
 * verify_mem_stack() converts the CA info stack into a       *
 * X509 stack, which is then passed to the CTX using the      *
 * function X509_STORE_CTX_trusted_stack() after the init.    *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_stack(STACK_OF(X509_INFO) *st);

X509_VERIFY_PARAM *param;
BIO              *certbio = NULL;
BIO               *outbio = NULL;
BIO               *cabio  = NULL;
X509                *cert = NULL;

const char ca_bundlestr[] = "./demo/ca-bundle.pem";
const char cert_filestr[] = "./demo/cert-file.pem";
char cacert_str[] =
"-----BEGIN CERTIFICATE-----\n\
MIIDvDCCAyWgAwIBAgIJAMbHBAm8IlugMA0GCSqGSIb3DQEBBQUAMIGbMQswCQYD\n\
VQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNV\n\
BAoTCEZyYW5rNEREMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMT\n\
D0ZyYW5rNEREIFdlYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRk\n\
ZC5jb20wHhcNMDcxMjA3MTAyMTQ2WhcNMTcxMjA0MTAyMTQ2WjCBmzELMAkGA1UE\n\
BhMCSlAxDjAMBgNVBAgTBVRva3lvMRAwDgYDVQQHEwdDaHVvLWt1MREwDwYDVQQK\n\
EwhGcmFuazRERDEYMBYGA1UECxMPV2ViQ2VydCBTdXBwb3J0MRgwFgYDVQQDEw9G\n\
cmFuazRERCBXZWIgQ0ExIzAhBgkqhkiG9w0BCQEWFHN1cHBvcnRAZnJhbms0ZGQu\n\
Y29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7r7yPJdXmDL2/+L2iogxQ\n\
rLML+10EwAY9lJRCHGPqSJ8if7teqnXgFr6MAEiCwTcLvk4h1UxLrDXmxooegNg1\n\
zx/OODbcc++SfFCGmflwj/wjLpYRwPgux7/QIgrUqzsj2HtdRFd+WPVD4AOtY9gn\n\
xjNXFpVe1zmgAm/UFLdMewIDAQABo4IBBDCCAQAwHQYDVR0OBBYEFGLze+0G1LHV\n\
nH9I5e/FyRVh/dkRMIHQBgNVHSMEgcgwgcWAFGLze+0G1LHVnH9I5e/FyRVh/dkR\n\
oYGhpIGeMIGbMQswCQYDVQQGEwJKUDEOMAwGA1UECBMFVG9reW8xEDAOBgNVBAcT\n\
B0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNEREMRgwFgYDVQQLEw9XZWJDZXJ0IFN1\n\
cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdlYiBDQTEjMCEGCSqGSIb3DQEJARYU\n\
c3VwcG9ydEBmcmFuazRkZC5jb22CCQDGxwQJvCJboDAMBgNVHRMEBTADAQH/MA0G\n\
CSqGSIb3DQEBBQUAA4GBALosLpHduFOY30wKS2WQ32RzRgh0ZWNlLXWHkQYmzTHN\n\
okwYLy0wGfIqzD1ovLMjDuPMC3MBmQPg8zhd+BY2sgRhgdEBmYWTiw71eZLLmI/e\n\
dQbu1z6rOXJb8EegubJNkYTcuxsKLijIfJDnK2noqPt03puJEsBxosN14XPEhIEO\n\
-----END CERTIFICATE-----";

int main() {

  X509          *error_cert = NULL;
  X509_NAME    *certsubject = NULL;
  STACK_OF(X509_INFO) *list = NULL;
  X509_STORE_CTX  *vrfy_ctx = NULL;
  int cert_counter = 0;
  int vrfy_err, i, ret, depth;
  unsigned int vrfy_flag;
  char *vrfy_name = NULL;
  struct stat ca_stat;

  struct Vrfy_Flags {
    unsigned long flag_code;
            char* flag_name;
            char* flag_desc;
  };

  struct Vrfy_Flags flagslist[MAXFLAGS];
  flagslist[0].flag_code  = 0x1;
  flagslist[0].flag_name  = "X509_V_FLAG_CB_ISSUER_CHECK";
  flagslist[0].flag_desc  = "This flag allows debugging of certificate issuer checks. It sends issuer+subject information to the verification call back function.";
  flagslist[1].flag_code  = 0x2;
  flagslist[1].flag_name  = "X509_V_FLAG_USE_CHECK_TIME";
  flagslist[1].flag_desc  = "This flag allows using check time instead of current time";
  flagslist[2].flag_code  = 0x4;
  flagslist[2].flag_name  = "X509_V_FLAG_CRL_CHECK";
  flagslist[2].flag_desc  = "This flag enables CRL checking for the certificate chain leaf certificate. An error occurs if a suitable CRL cannot be found.";
  flagslist[3].flag_code  = 0x8;
  flagslist[3].flag_name  = "X509_V_FLAG_CRL_CHECK_ALL";
  flagslist[3].flag_desc  = "This flag enables CRL checking for the entire certificate chain. If enabled, CRLs are expected to be available in the X509_STORE structure. There is no auto-download of CRLs from the CRL distribution points extension.";
  flagslist[4].flag_code  = 0x10;
  flagslist[4].flag_name  = "X509_V_FLAG_IGNORE_CRITICAL";
  flagslist[4].flag_desc  = "This flag disables critical extension checking. By default, any unhandled critical extensions in certificates or (if checked) CRLs results in a fatal error. If this flag is set, unhandled critical extensions are ignored. Setting this option can be a security risk.";
  flagslist[5].flag_code  = 0x20;
  flagslist[5].flag_name  = "X509_V_FLAG_X509_STRICT";
  flagslist[5].flag_desc  = "This flag disables workarounds for some broken certificates and makes the verification strictly apply X509 rules.";
  flagslist[6].flag_code  = 0x40;
  flagslist[6].flag_name  = "X509_V_FLAG_ALLOW_PROXY_CERTS";
  flagslist[6].flag_desc  = "This flag enables proxy certificate verification.";
  flagslist[7].flag_code  = 0x80;
  flagslist[7].flag_name  = "X509_V_FLAG_POLICY_CHECK";
  flagslist[7].flag_desc  = "This flag enables certificate policy checking. By default, no policy checking is peformed. Additional information is sent to the verification callback relating to policy checking.";
  flagslist[8].flag_code  = 0x100;
  flagslist[8].flag_name  = "X509_V_FLAG_EXPLICIT_POLICY";
  flagslist[8].flag_desc  = "This flag is enabling policy checking per RFC3280. When enabled, all certificates in the path must contain an acceptable policy identifier in the certificate policies extension.";
  flagslist[9].flag_code  = 0x200;
  flagslist[9].flag_name  = "X509_V_FLAG_INHIBIT_ANY";
  flagslist[9].flag_desc  = "If this flag is set, the value indicates the number of additional certificates that may appear in the path before policy mapping is no longer permitted.  For example, a value of one indicates that policy mapping may be processed in certificates issued by the subject of this certificate, but not in additional certificates in the path.";
  flagslist[10].flag_code = 0x400;
  flagslist[10].flag_name = "X509_V_FLAG_INHIBIT_MAP";
  flagslist[10].flag_desc = "If this flag is set, the value indicates the number of additional certificates that may appear in the path before policy mapping is no longer permitted.  For example, a value of one indicates that policy mapping may be processed in certificates issued by the subject of this certificate, but not in additional certificates in the path.";
  flagslist[11].flag_code = 0x800;
  flagslist[11].flag_name = "X509_V_FLAG_NOTIFY_POLICY";
  flagslist[11].flag_desc = "This flag sends extra policy information to the cllback function.";
  flagslist[12].flag_code = 0x1000;
  flagslist[12].flag_name = "X509_V_FLAG_EXTENDED_CRL_SUPPORT";
  flagslist[12].flag_desc = "This flag enables extended CRL features such as indirect CRLs, alternate CRL signing keys.";
  flagslist[13].flag_code = 0x2000;
  flagslist[13].flag_name = "X509_V_FLAG_USE_DELTAS";
  flagslist[13].flag_desc = "This flag enables the use of Delta CRL's, if available. OpenSSL's Delta CRL checking is currently primitive. Only a single delta can be used and constructed CRLs are not maintained.";
  flagslist[14].flag_code = 0x4000;
  flagslist[14].flag_name = "X509_V_FLAG_CHECK_SS_SIGNATURE";
  flagslist[14].flag_desc = "This flag enables the check if the root CA has a self-signed cerificate signature. By default this check is disabled because it doesn't add any additional security. In some cases, applications might want to check the signature anyway. A side effect of not checking the root CA signature is that disabled or unsupported message digests on the root CA are not treated as fatal errors.";

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  outbio  = BIO_new(BIO_s_file());
  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * Load the cert file into a BIO and then into a x509 struct. *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  ret = BIO_read_filename(certbio, cert_filestr);

  if (! (cert = PEM_read_bio_X509(certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading cert into memory: %s\n", cert_filestr);
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Load a CA cert file into a BIO and then into a x509 stack. *
   * ---------------------------------------------------------- */
  list = X509_load_ca_file(&cert_counter, ca_stat, ca_bundlestr);

  /* ---------------------------------------------------------- *
   * Create a verification context from the stack, add the cert *
   * ---------------------------------------------------------- */
  vrfy_ctx = verify_mem_store(list); 
  //vrfy_ctx = verify_mem_stack(list);
  //vrfy_ctx = verify_file_direct(ca_bundlestr);

  /* ---------------------------------------------------------- *
   * Set the verification options and depth for this operation. *
   * ---------------------------------------------------------- */
  param = X509_VERIFY_PARAM_new();
  //X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CB_ISSUER_CHECK);
  X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_X509_STRICT);
  X509_VERIFY_PARAM_set_depth(param, 5);

  X509_STORE_CTX_set_verify_cb(vrfy_ctx, verify_callback);
  /* ---------------------------------------------------------- *
   * Check the verification settings used for this operation.   *
   * ---------------------------------------------------------- */
  vrfy_flag = X509_VERIFY_PARAM_get_flags(param);
  for(i=0; i<MAXFLAGS; i++) {
  depth = X509_VERIFY_PARAM_get_depth(param);
    if(flagslist[i].flag_code == vrfy_flag) 
      vrfy_name = (flagslist[i].flag_name);
  }

  BIO_printf(outbio, "Verification check flags: %#x [%s]\n", vrfy_flag, vrfy_name);
  BIO_printf(outbio, "Verification depth limit: %d\n", depth);
  BIO_printf(outbio, "Verification CA cert num: %d CA certs provided\n", cert_counter);


  /* ---------------------------------------------------------- *
   * Check the complete cert chain can be build and validated.  *
   * Returns 1 on success, 0 on verification failures, and -1   *
   * for trouble with the ctx object (i.e. missing certificate) *
   * ---------------------------------------------------------- */
  ret = X509_verify_cert(vrfy_ctx);
  BIO_printf(outbio, "Verification return code: %d\n", ret);

  /* ---------------------------------------------------------- *
   * A negative return value indicates a verification error     *
   * ---------------------------------------------------------- */
  if (ret < 0) {
    BIO_printf(outbio, "Error loading CA cert or chain file: %s\n", ca_bundlestr);
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * For verification return of 0 or 1, check validation result *
   * ---------------------------------------------------------- */
  vrfy_err = X509_STORE_CTX_get_error(vrfy_ctx);
  BIO_printf(outbio, "Verification result text: %s\n",
             X509_verify_cert_error_string(vrfy_err));

  /* ---------------------------------------------------------- *
   * The error handling below shows how to get failure details  *
   * from the offending certificate.                            *
   * ---------------------------------------------------------- */
  if(ret == 0) {
    /*  get the offending certificate causing the failure */
    error_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
    certsubject = X509_NAME_new();
    certsubject = X509_get_subject_name(error_cert);
    BIO_printf(outbio, "\nVerification certsubject: ---------------start----------------------\n");
    X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
    BIO_printf(outbio, "\nVerification certsubject: ----------------End-----------------------\n");
  }

  /* ---------------------------------------------------------- *
   * Free up all structures                                     *
   * ---------------------------------------------------------- */

  X509_VERIFY_PARAM_free(param);
  X509_STORE_CTX_free(vrfy_ctx); 
  BIO_free_all(certbio);
  BIO_free_all(outbio);
  exit(0);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
  X509_NAME    *certissuer = NULL;
  char    buf[4096] = "";
  X509   *err_cert;
  int     err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  /* ---------------------------------------------------------- *
   * Show the subject info at certification depth level         *
   * ---------------------------------------------------------- */
  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
  printf("Verification check depth: %d - %.49s\n", depth, buf);

  /* ---------------------------------------------------------- *
   * Catch a too long certificate chain. The depth limit with   *
   * SSL_CTX_set_verify_depth() is on purpose set to "limit+1". *
   * ---------------------------------------------------------- */
  if (depth > X509_VERIFY_PARAM_get_depth(param)) {
      preverify_ok = 0;
      err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
      X509_STORE_CTX_set_error(ctx, err);
      printf("Verification fail detail: %d - %s\n", err, X509_verify_cert_error_string(err)); 
      printf("Verification result text: %d - FAILED\n", depth);
      return err;
  }

  if (!preverify_ok) {
      BIO_printf(outbio, "Verification result text: %d - FAILED\n", depth);
      BIO_printf(outbio, "Verification fail reason: %d - %s [error code: %d]\n", depth, X509_verify_cert_error_string(err), err); 
  }

  /* ---------------------------------------------------------- *
   * At this point, err contains the last verification error.   *
   * We can use it for something special                        *
   * ---------------------------------------------------------- */
  if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
      certissuer = X509_NAME_new();
      certissuer = X509_get_issuer_name(err_cert);
      BIO_printf(outbio, "\nVerification fail issuer: ---------------start----------------------\n");
      X509_NAME_print_ex(outbio, certissuer, 0, XN_FLAG_MULTILINE);
      BIO_printf(outbio, "\nVerification fail issuer: ----------------End-----------------------\n");
  }

  if (preverify_ok) printf("Verification result text: %d - PASSED\n", depth);
  return preverify_ok;
}

/* ---------------------------------------------------------- *
 * verify_file_direct() uses X509_STORE_load_locations() to   * 
 * load the CA certs from file into the store struct, which   * 
 * is then passed to the CTX during the init.                 * 
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_file_direct(const char *file) {
  X509_STORE         *store = NULL;
  X509_STORE_CTX  *vrfy_ctx = NULL;

  /* ---------------------------------------------------------- *
   * Initialize the global certificate validation store object. *
   * ---------------------------------------------------------- */
  if (!(store=X509_STORE_new()))
     BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

  /* ---------------------------------------------------------- *
   * Create the context structure for the validation operation. *
   * ---------------------------------------------------------- */
  vrfy_ctx = X509_STORE_CTX_new();

  /* ---------------------------------------------------------- *
   * Load the certificate and cacert chain from file (PEM).     *
   * ---------------------------------------------------------- */
  if ((X509_STORE_load_locations(store, file, NULL)) != 1)
    BIO_printf(outbio, "Error loading CA cert or chain file\n");

  /* ---------------------------------------------------------- *
   * Initialize the ctx structure for a verification operation: *
   * Set the trusted cert store, the unvalidated cert, and any  *
   * potential certs that could be needed (here we set it NULL) *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_init(vrfy_ctx, store, cert, NULL);

  return vrfy_ctx; 
}

/* ---------------------------------------------------------- *
 * X509_load_ca_file() loads a CA file into a mem BIO using   * 
 * (BIO_read_filename(), PEM_X509_INFO_read_bio() puts them   * 
 * in a stack, which is then to be added to a store or CTX.   *
 * ---------------------------------------------------------- */
STACK_OF(X509_INFO) *X509_load_ca_file(int *cert_count, 
                                       struct stat fstat, const char *file) {
  STACK_OF(X509_INFO) *st = NULL;
  BIO *inbio=NULL;

  /* complain if we got an empty filename */
  if (file == NULL)
    BIO_printf(outbio, "Error receiving a valid CA bundle file name.\n");

  /* get file status data */
  if (stat(file, &fstat) != 0) {
    BIO_printf(outbio, "Error cannot stat cert bundle file: %s.\n", file);
    exit(1);
  }

  /* complain if the file is empty (0 bytes) */
  if(fstat.st_size == 0)
    BIO_printf(outbio, "Error cert bundle file size is zero bytes.\n");

  inbio=BIO_new(BIO_s_file());

  /* check if we can open the file for reading */
  if ((inbio == NULL) || (BIO_read_filename(inbio, file) <= 0))
    BIO_printf(outbio, "Error loading cert bundle file into memory.\n");

  /* read all certificates from file */
  if (! (st = PEM_X509_INFO_read_bio(inbio, NULL, NULL, NULL)))
    BIO_printf(outbio, "Error reading certs from BIO.\n");

  /* get the number of certs that are now on the stack */
  *cert_count = sk_X509_INFO_num(st);

  /* return the STACK_OF(X509_INFO) pointer, or exit */
  if (cert_count > 0) return st;
  else exit(1);
}

/* ---------------------------------------------------------- *
 * verify_mem_store() puts the CA info stack into a store     *
 * struct, which is then passed to the CTX during the init.   *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_store(STACK_OF(X509_INFO) *st) {
  X509_STORE         *store = NULL;
  X509_STORE_CTX       *ctx = NULL;
  //STACK_OF(X509)  *ca_stack = NULL;
  X509_INFO      *list_item = NULL;
  int cert_count            = 0;
  int i                     = 0;

  /* ---------------------------------------------------------- *
   * Initialize the global certificate validation store object. *
   * ---------------------------------------------------------- */
  if (!(store=X509_STORE_new()))
     BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");

  /* ---------------------------------------------------------- *
   * Create the context structure for the validation operation. *
   * ---------------------------------------------------------- */
  ctx = X509_STORE_CTX_new();

  /* ---------------------------------------------------------- *
   * Get the number of certs on the stack                       *
   * ---------------------------------------------------------- */
  cert_count = sk_X509_INFO_num(st);

  /* ---------------------------------------------------------- *
   * Complain if there is no cert                               *
   * ---------------------------------------------------------- */
  if (! (cert_count > 0)) {
    BIO_printf(outbio, "Error no certs on stack.\n");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Cycle through all info stack items, extract the X509 cert  *
   * and put it into the X509_STORE called store.               *
   * ---------------------------------------------------------- */
  for (i = 0; i < cert_count; i++) {
    list_item = sk_X509_INFO_value(st, i);
    X509_STORE_add_cert(store, list_item->x509);
  }

  /* ---------------------------------------------------------- *
   * Initialize the ctx structure for a verification operation: *
   * Set the trusted cert store, the unvalidated cert, and any  *
   * potential certs that could be needed (here we set it NULL) *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_init(ctx, store, cert, NULL);

  return ctx;
}

/* ---------------------------------------------------------- *
 * verify_mem_stack() converts the CA info stack into a       *
 * X509 stack, which is then passed to the CTX using the      *
 * function X509_STORE_CTX_trusted_stack() after the init.    *
 * ---------------------------------------------------------- */
X509_STORE_CTX  *verify_mem_stack(STACK_OF(X509_INFO) *st) {
  X509_STORE_CTX       *ctx = NULL;
  STACK_OF(X509)  *ca_stack = NULL;
  X509_INFO      *list_item = NULL;
  int cert_count            = 0;
  int i                     = 0;

  /* ---------------------------------------------------------- *
   * Get the number of certs on the stack                       *
   * ---------------------------------------------------------- */
  cert_count = sk_X509_INFO_num(st);

  /* ---------------------------------------------------------- *
   * Complain if there is no cert                               *
   * ---------------------------------------------------------- */
  if (! (cert_count > 0)) {
    BIO_printf(outbio, "Error no certs on stack.\n");
    exit(1);
  }

  /* ---------------------------------------------------------- *
   * Initialize the X509 stack ca_stack                         *
   * ---------------------------------------------------------- */
  ca_stack = sk_X509_new_null();

  /* ---------------------------------------------------------- *
   * Cycle through all info stack items, extract the X509 cert  *
   * and put it on the X509 stack.                              *
   * ---------------------------------------------------------- */
  for (i = 0; i < cert_count; i++) {
    list_item = sk_X509_INFO_value(st, i);
    sk_X509_push(ca_stack, list_item->x509);
  }

  /* ---------------------------------------------------------- *
   * Create the context structure for the validation operation. *
   * ---------------------------------------------------------- */
  ctx = X509_STORE_CTX_new();

  /* ---------------------------------------------------------- *
   * Initialize the ctx structure for a verification operation: *
   * Set the trusted cert store, the unvalidated cert, and any  *
   * potential certs that could be needed (here we set it NULL) *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_init(ctx, NULL, cert, NULL);

  /* ---------------------------------------------------------- *
   * Add the list of CA certs to the ctx verification structure *
   * ---------------------------------------------------------- */
  X509_STORE_CTX_trusted_stack(ctx, ca_stack);

  return ctx;
}
