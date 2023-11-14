#include "kdc.hh"

// encryptRet* encrypt(unsigned char* key, unsigned char* msg,int msgLen){
//   EVP_CIPHER_CTX *ctx;
//   unsigned char* ciphertext = (unsigned char*)malloc(1024);
//   int len;
//   int ciphertext_len;
//   ctx = EVP_CIPHER_CTX_new();
//   EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
//   EVP_EncryptUpdate(ctx, ciphertext, &len, msg, msgLen);
//   ciphertext_len = len;
//   EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
//   ciphertext_len += len;
//   EVP_CIPHER_CTX_free(ctx);
//   encryptRet* ret = (encryptRet*)malloc(sizeof(encryptRet));
//   ret->ciphertext = ciphertext;
//   ret->ciphertext_len = ciphertext_len;
//   return ret;
// }

// encryptRet* decrypt(unsigned char* key, unsigned char* ciphertext, int msgLen){
//   EVP_CIPHER_CTX *ctx;
//   int len;
//   int plaintext_len;
//   unsigned char* plaintext = (unsigned char*)malloc(1024);
//   encryptRet* ret = (encryptRet*)malloc(sizeof(encryptRet));
//   ctx = EVP_CIPHER_CTX_new();
//   EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
//   EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, msgLen);
//   plaintext_len = len;
//   EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
//   plaintext_len += len;
//   EVP_CIPHER_CTX_free(ctx);
//   ret->ciphertext = plaintext;
//   ret->ciphertext_len = plaintext_len;
//   return ret;
// }

int serverSetup(){
  int port = 9090;
  int sock;
  struct sockaddr_in addr;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){
    perror("[-]Socket error");
  }
  memset(&addr, '\0', sizeof(addr));;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
    perror("[-]Bind error");
  }

  if (listen(sock, 2) < 0){
    perror("[-]Listen error");
  }
  return sock;
}

void* clientHandler(void* arg){
	param* p = (param*)arg;
	int clientSock = p->clientSock;
	
	// reading ticket from client 
	unsigned char msg[1024];
	int res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);
	// decrypt ticket using ircServerKey i.e. private key
	unsigned char* ircServerKey = getIrcServerKey();
	encryptRet* ticket = decrypt(ircServerKey, msg, res); 
	free(ircServerKey);
	unsigned char* userName = (unsigned char*)malloc(5);
	memcpy(userName, ticket->ciphertext, 5);
	unsigned char* sessionKey = (unsigned char*)malloc(32);
	memcpy(sessionKey, ticket->ciphertext+5, 32);
	
	// recieve challenge from client
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);

	// decrypt challenge using sessionKey
	encryptRet* challenge = decrypt(sessionKey, msg, res);
	// solving challenge
	challenge->ciphertext[3] = challenge->ciphertext[3] + 1;
	// generate new challenge 
	unsigned char* newChallenge = (unsigned char*)malloc(4);
	FILE* urandom = fopen("/dev/urandom", "r");
	fread(newChallenge, 1, 4, urandom);
	fclose(urandom);
	// encrypt new challenge and old challenge response using sessionKey

	unsigned char* challengeResStr = (unsigned char*)malloc(8);
	memcpy(challengeResStr, challenge->ciphertext, 4);
	memcpy(challengeResStr+4, newChallenge, 4);
	encryptRet* challengeResEnc = encrypt(sessionKey, challengeResStr, 8);
	write(clientSock, challengeResEnc->ciphertext, challengeResEnc->ciphertext_len);
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);
	// decrypt message using sessionKey
	encryptRet* msgDec = decrypt(sessionKey, msg, res);
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
  int sock = serverSetup();
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