target:
	gcc client.c -o client -lssl -lcrypto
	gcc irc.c -o irc -lssl -lcrypto
	gcc kdc.c -o kdc -lssl -lcrypto