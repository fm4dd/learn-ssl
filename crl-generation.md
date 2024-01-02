## CRL Generation with OpenSSL

### Edit the OpenSSL configuration

```
sudo vi /usr/lib/ssl/openssl.cnf
...
####################################################################
[ ca ]
default_ca      = CA_default             # The default ca section

####################################################################
[ CA_default ]

dir             = /srv/app/webCA         # Where everything is kept
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
certs           = $dir/certs             # Where the issued certs are kept
crl_dir         = $dir/crl               # Where the issued crl are kept
database        = $dir/index.txt         # database index file.
serial          = $dir/serial            # The current serial number
crlnumber       = $dir/crlnumber         # the current crl number
crl             = $dir/crl.pem           # The current CRL
private_key     = $dir/private/cakey.pem # The private key
...
```

### Create the CLR directory and certificate database

```
sudo mkdir /srv/app/webCA/crl
```

```
sudo touch /srv/app/webCA/index.txt
```

### Create the CRL file 

```
sudo sh -c "echo \"01\" >  /srv/app/webCA/crlnumber"
```

```
sudo openssl ca -gencrl
Using configuration from /usr/lib/ssl/openssl.cnf
Enter pass phrase for /srv/app/webCA/private/cakey.pem:
-----BEGIN X509 CRL-----
MIICuTCBogIBATANBgkqhkiG9w0BAQsFADBgMQswCQYDVQQGEwJKUDEOMAwGA1UE
CAwFVG9reW8xFDASBgNVBAcMC1NoaW5qdWt1LWt1MQwwCgYDVQQKDANHSVMxDDAK
BgNVBAsMA0lSTTEPMA0GA1UEAwwGVGVzdENBFw0xNzA4MTgwMTIyMzFaFw0xNzA5
MTcwMTIyMzFaoA4wDDAKBgNVHRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAgEAm2c7
MAcbGzewVZXaPLF6V2SqosC8BCg03s/1TOsI99jVlCwvpWtRNxeQVx3gO+Urc0OZ
P958SfAebkqiqPxKMV/ExU/hu+Jb9p3jT3iqbFenf+VpzI34883tfqsJWsRsVTTp
CXfndZbD5ebqxltpBbvtAwZrm4p6WjK3VLCx4CpSP+8IG6Ik8dLKUFxnR5buRkP4
WE4MOkmEUo28gwxj+DuIM4icewoVGVJt3bBzatnVcEmXsIRN6VYNMjXmfgff7gVV
XX9L2p4fmHJai97QHqNNwDwwoWTkLHXuf6/Ijf6eNUluan+8bcFNtMNYEG/0lpkE
M1AsnmSSC8cz0zkadq82tTg2/2oip8YrLRKCEG1pfMzmKXCC+swv9Wj8fLm2LXvW
KDPzfBP/4tsNx8xVEe6wpL4OejKUazs95DgLyVXZuMDtmtIh9zAZ6+V9SmYZnINX
noDSvPq1YyUa1WTLqhYt7spbYY152/ZTkOH7RYUcgmRvFwoPZbdIVEy5TKCJ9aGE
ltYDlqyo7jepRnUNRTJSpTkr5N1T3tJ1+l2W4OhiX01hMPkiMQbRebRL8UGyOJII
+AE1J/Gw+eXAairP0MYNuEbQh74LsjlcoTvQcoHLQezRriUxfIynimAGBtbOJI7v
feNi/KF4L5pd0VK3x4fN8bKpeSZixvSqprJRy/8=
-----END X509 CRL-----
```

```
fm@lts1604:~$ cat /srv/app/webCA/crlnumber
02

fm@lts1604:~$ cat /srv/app/webCA/crlnumber.old 
01
```

```
sudo vi /srv/app/webCA/crl/crl.pem
... add output above ...
```

```
openssl crl -in /srv/app/webCA/crl/crl.pem -noout -text
Certificate Revocation List (CRL):
        Version 2 (0x1)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: /C=JP/ST=Tokyo/L=Shinjuku-ku/O=GIS/OU=IRM/CN=TestCA
        Last Update: Aug 18 01:22:31 2017 GMT
        Next Update: Sep 17 01:22:31 2017 GMT
        CRL extensions:
            X509v3 CRL Number: 
                1
No Revoked Certificates.
    Signature Algorithm: sha256WithRSAEncryption
         9b:67:3b:30:07:1b:1b:37:b0:55:95:da:3c:b1:7a:57:64:aa:
         a2:c0:bc:04:28:34:de:cf:f5:4c:eb:08:f7:d8:d5:94:2c:2f:
         a5:6b:51:37:17:90:57:1d:e0:3b:e5:2b:73:43:99:3f:de:7c:
         49:f0:1e:6e:4a:a2:a8:fc:4a:31:5f:c4:c5:4f:e1:bb:e2:5b:
         f6:9d:e3:4f:78:aa:6c:57:a7:7f:e5:69:cc:8d:f8:f3:cd:ed:
         7e:ab:09:5a:c4:6c:55:34:e9:09:77:e7:75:96:c3:e5:e6:ea:
         c6:5b:69:05:bb:ed:03:06:6b:9b:8a:7a:5a:32:b7:54:b0:b1:
         e0:2a:52:3f:ef:08:1b:a2:24:f1:d2:ca:50:5c:67:47:96:ee:
         46:43:f8:58:4e:0c:3a:49:84:52:8d:bc:83:0c:63:f8:3b:88:
         33:88:9c:7b:0a:15:19:52:6d:dd:b0:73:6a:d9:d5:70:49:97:
         b0:84:4d:e9:56:0d:32:35:e6:7e:07:df:ee:05:55:5d:7f:4b:
         da:9e:1f:98:72:5a:8b:de:d0:1e:a3:4d:c0:3c:30:a1:64:e4:
         2c:75:ee:7f:af:c8:8d:fe:9e:35:49:6e:6a:7f:bc:6d:c1:4d:
         b4:c3:58:10:6f:f4:96:99:04:33:50:2c:9e:64:92:0b:c7:33:
         d3:39:1a:76:af:36:b5:38:36:ff:6a:22:a7:c6:2b:2d:12:82:
         10:6d:69:7c:cc:e6:29:70:82:fa:cc:2f:f5:68:fc:7c:b9:b6:
         2d:7b:d6:28:33:f3:7c:13:ff:e2:db:0d:c7:cc:55:11:ee:b0:
         a4:be:0e:7a:32:94:6b:3b:3d:e4:38:0b:c9:55:d9:b8:c0:ed:
         9a:d2:21:f7:30:19:eb:e5:7d:4a:66:19:9c:83:57:9e:80:d2:
         bc:fa:b5:63:25:1a:d5:64:cb:aa:16:2d:ee:ca:5b:61:8d:79:
         db:f6:53:90:e1:fb:45:85:1c:82:64:6f:17:0a:0f:65:b7:48:
         54:4c:b9:4c:a0:89:f5:a1:84:96:d6:03:96:ac:a8:ee:37:a9:
         46:75:0d:45:32:52:a5:39:2b:e4:dd:53:de:d2:75:fa:5d:96:
         e0:e8:62:5f:4d:61:30:f9:22:31:06:d1:79:b4:4b:f1:41:b2:
         38:92:08:f8:01:35:27:f1:b0:f9:e5:c0:6a:2a:cf:d0:c6:0d:
         b8:46:d0:87:be:0b:b2:39:5c:a1:3b:d0:72:81:cb:41:ec:d1:
         ae:25:31:7c:8c:a7:8a:60:06:06:d6:ce:24:8e:ef:7d:e3:62:
         fc:a1:78:2f:9a:5d:d1:52:b7:c7:87:cd:f1:b2:a9:79:26:62:
         c6:f4:aa:a6:b2:51:cb:ff
```

```
fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -hash
c94ac8e0

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -hash_old
1a4d787e

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -crlnumber
crlNumber=01

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -issuer
issuer=/C=JP/ST=Tokyo/L=Shinjuku-ku/O=GIS/OU=IRM/CN=TestCA

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -lastupdate
lastUpdate=Aug 18 01:22:31 2017 GMT

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -nextupdate
nextUpdate=Sep 17 01:22:31 2017 GMT

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -fingerprint
SHA1 Fingerprint=1C:06:2F:EA:08:E2:86:80:0B:4F:4D:61:37:67:3D:AD:19:0F:14:FE

fm@lts1604:~$ openssl crl -in /srv/app/webCA/crl/crl.pem -noout -badsig

fm@lts1604:~$ gcc crltest.c -o crltest -lssl -lcrypto
fm@lts1604:~$ ./crltest 
Found crl file ./test.crl
CRL Version: 2 (0x1)
CRL Issuer Details: C = JP, ST = Tokyo, L = Shinjuku-ku, O = GIS, OU = IRM, CN = TestCA
This CRL Release Date: Aug 18 01:22:31 2017 GMT
Next CRL Release Date: Sep 17 01:22:31 2017 GMT
 CRL Signature Format: sha256WithRSAEncryption
 Number of Extensions: 1
Found # revoked certs: -1
```


The command openssl ca -gencrl actually reads the content from the Openssl text database (index.txt), and creates a CRL for all cert lines marked with R (revoked). It does not keep state. Corruption or re-generation of the database (index.txt) will fully reflect in the CRL.  E.g. creating a new, empty index.txt file will result in a empty CRL file, even if the previous version had data in it.

Even if no OpenSSL database is maintained during certificate creation, the file will be updated when the certificate revocation command "openssl ca -revoke" is run.

```
root@lts1604:~# openssl ca -revoke /srv/app/webCA/certs/1A.pem 
Using configuration from /usr/lib/ssl/openssl.cnf
Enter pass phrase for /srv/app/webCA/private/cakey.pem:
Adding Entry with serial number 1A to DB for /CN=2ss
Revoking Certificate 1A.
Data Base Updated

root@lts1604:~# ls -la /srv/app/webCA/
total 44
drwxr-xr-x 5 root root     4096 Aug 21 13:43 .
drwxr-xr-x 4 root root     4096 Mar 17 15:56 ..
-rw-r----- 1 root www-data 1992 Jul 11 10:15 cacert.pem
drwxrwx--- 2 root www-data 4096 Aug 18 09:56 certs
drwxr-xr-x 2 root root     4096 Aug 18 10:26 crl
-rw-r--r-- 1 root root        3 Aug 18 10:22 crlnumber
-rw-r--r-- 1 root root        3 Aug 18 10:21 crlnumber.old
-rw-r--r-- 1 root root       49 Aug 21 13:43 index.txt
-rw-r--r-- 1 root root       21 Aug 21 13:43 index.txt.attr
-rw-r--r-- 1 root root        0 Aug 18 10:17 index.txt.old
drwxr-x--- 2 root www-data 4096 Jul 11 10:14 private
-rw-rw---- 1 root www-data    3 Aug 18 09:56 serial

root@lts1604:~# cat /srv/app/webCA/index.txt
R	200817005646Z	170821044339Z	1A	unknown	/CN=2ss

root@lts1604:~# cat /srv/app/webCA/index.txt.attr 
unique_subject = yes
```

Now we run "openssl ca -gencrl" again, and update the CRL


Note that OpenSSL creates v2 CRLs. Per https://www.ietf.org/rfc/rfc5280.txt, those CRLs can have extensions. 
The OpenSSL CRL carries "X509v3 CRL Number", which is a increasing counter that can help diff and determine latest version.
OpenSSL carries the CRL version in a text file crlnumber and crlnumber.old (e.g. "/srv/app/webCA/crlnumber").

The Verisign CRL in the old example is a v1 CRL without extensions.

The only link between a CRL entry and a CA-signed certificate is the serial number. This means the SN needs to be unique per CA.

Another example of a CRL, having one single removed cert:

```
fm@lts1604:~$ ./crltest 
Found crl file ./test.crl
CRL Version: 2 (0x1)
CRL Issuer Details: C = JP, ST = Tokyo, L = Shinjuku-ku, O = GIS, OU = IRM, CN = TestCA
This CRL Release Date: Aug 21 09:07:18 2017 GMT
Next CRL Release Date: Sep 20 09:07:18 2017 GMT
CRL Signature Format: sha256WithRSAEncryption
Number of Extensions: 1
Extension Object 00: X509v3 CRL Number
  4
Found # revoked certs: 1
Revocation #: 0 S/N: 1A Date: Aug 21 04:43:39 2017 GMT
```
