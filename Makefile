all:
	gcc CA.c helper/client_helper.c client.c -lssl -lcrypto -o client
	gcc helper/server_helper.c server.c -o server
clean:
	rm -f client
	rm -f server