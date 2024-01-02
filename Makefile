CC=gcc
CFLAGS= -O3 -Wall -g
LIBS= -lssl -lcrypto
AR=ar

ALLBIN=add_ev_oids certextensions certpubkey certserial certstack certverify \
sslconnect certcreate certfprint certrenewal certsignature certverify-adv crldisplay \
pkcs12test set_asn1_time eckeycreate keytest keycompare

all: ${ALLBIN}

clean:
	rm -f ${ALLBIN}

add_ev_oids:
	$(CC) $(CFLAGS) add_ev_oids.c -o add_ev_oids ${LIBS}

certextensions:
	$(CC) $(CFLAGS) certextensions.c -o certextensions ${LIBS}

certpubkey:
	$(CC) $(CFLAGS) certpubkey.c -o certpubkey ${LIBS}

certserial:
	$(CC) $(CFLAGS) certserial.c -o certserial ${LIBS}

certstack:
	$(CC) $(CFLAGS) certstack.c -o certstack ${LIBS}

certverify:
	$(CC) $(CFLAGS) certverify.c -o certverify ${LIBS}

sslconnect:
	$(CC) $(CFLAGS) sslconnect.c -o sslconnect ${LIBS}

certcreate:
	$(CC) $(CFLAGS) certcreate.c -o certcreate ${LIBS}

certfprint:
	$(CC) $(CFLAGS) certfprint.c -o certfprint ${LIBS}

certrenewal:
	$(CC) $(CFLAGS) certrenewal.c -o certrenewal ${LIBS}

certsignature:
	$(CC) $(CFLAGS) certsignature.c -o certsignature ${LIBS}

certverify-adv:
	$(CC) $(CFLAGS) certverify-adv.c -o certverify-adv ${LIBS}

crldisplay:
	$(CC) $(CFLAGS) crldisplay.c -o crldisplay ${LIBS}

pkcs12test:
	$(CC) $(CFLAGS) pkcs12test.c -o pkcs12test ${LIBS}

set_asn1_time:
	$(CC) $(CFLAGS) set_asn1_time.c -o set_asn1_time ${LIBS}

eckeycreate:
	$(CC) $(CFLAGS) eckeycreate.c -o eckeycreate ${LIBS}

keytest:
	$(CC) $(CFLAGS) keytest.c -o keytest ${LIBS}

keycompare:
	$(CC) $(CFLAGS) keycompare.c -o keycompare ${LIBS}
