#include "kdc.hh"


void* clientHandler(void* arg){
	param* p = (param*)arg;
	int clientSock = p->clientSock;
	
	// reading ticket from client 
	unsigned char msg[1024];
	int res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);
	// decrypt ticket using ircServerKey i.e. private key
	unsigned char* ircServerKey = getIrcServerKey();
	unsigned char* IV = (unsigned char*)malloc(16);
	memcpy(IV, msg+res-16, 16);
	encryptRet* ticket = decrypt(ircServerKey, msg, res-16, IV); 
	free(ircServerKey);
	unsigned char* userName = (unsigned char*)malloc(5);
	memcpy(userName, ticket->ciphertext, 5);
	unsigned char* sessionKey = (unsigned char*)malloc(32);
	memcpy(sessionKey, ticket->ciphertext+5, 32);
	// recieve challenge from client
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);

	// IV = (unsigned char*)malloc(16);
	memcpy(IV, msg+res-16, 16);
	// decrypt challenge using sessionKey
	encryptRet* challenge = decrypt(sessionKey, msg, res-16, IV);
	// solving challenge
	unsigned char* ct = challenge->ciphertext;
	challenge->ciphertext[3] = challenge->ciphertext[3] + 1;
	// generate new challenge 
	unsigned char* newChallenge = getRand(4);
	// encrypt new challenge and old challenge response using sessionKey

	unsigned char* challengeResStr = (unsigned char*)malloc(8);
	memcpy(challengeResStr, challenge->ciphertext, 4);
	memcpy(challengeResStr+4, newChallenge, 4);
	IV = getRand(16);
	encryptRet* challengeResEnc = encrypt(sessionKey, challengeResStr, 8, IV);
	unsigned char* challengeResEncIV = (unsigned char*) malloc(challengeResEnc->ciphertext_len+16);
	memcpy(challengeResEncIV,challengeResEnc->ciphertext,challengeResEnc->ciphertext_len);
	memcpy(challengeResEncIV+challengeResEnc->ciphertext_len,IV,16);
	write(clientSock, challengeResEncIV, challengeResEnc->ciphertext_len+16);
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);
	IV = (unsigned char*)malloc(16);
	memcpy(IV, msg+res-16, 16);
	// decrypt message using sessionKey
	encryptRet* msgDec = decrypt(sessionKey, msg, res-16, IV);
	// validate challenge response
	if (msgDec->ciphertext[0] != newChallenge[0] || msgDec->ciphertext[1] != newChallenge[1] || msgDec->ciphertext[2] != newChallenge[2] || msgDec->ciphertext[3] != newChallenge[3]+1){
		printf("[-]Challenge response failed\n");
		return NULL;
	}
	printf("[+]Challenge response passed\n");
	
	// this is ticket: sessionKey, userName
	// for (int i=0; i<res; i++){
	// 	printf("%02x", msg[i]);
	// }
	// printf("\n");
	return NULL;
}

int main(){
	signal(SIGPIPE,SIG_IGN);
  pthread_t tid;
  int sock = serverSetup(9090);
  int clientSock;
  while(1){
    clientSock = accept(sock, (struct sockaddr*)NULL, NULL);
    if (clientSock < 0){
      perror("[-]Accept error");
    }
    param *p = (param*)malloc(sizeof(param));
    p->clientSock = clientSock;
	pthread_create(&tid,NULL, clientHandler, (void*)p);

  }
}