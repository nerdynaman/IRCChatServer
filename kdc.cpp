#include "kdc.hh"

int serverSetup(){
  int port = 8080;
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

int verifyUser(char* userName){
  // check if userName file exists
  FILE* fp = fopen(userName, "r");
  if (fp == NULL){
    return -1;
  }
  fclose(fp);
  return 0;
}

unsigned char* getSessionKey(char* userName){
  // use /dev/urandom to generate 32bytes random key
  unsigned char* sessionKey = (unsigned char*)malloc(32);
  FILE* urandom = fopen("/dev/urandom", "r");
  fread(sessionKey, 1, 32, urandom);
  fclose(urandom);
  // for (int i=0; i<32; i++){
  //   printf("%02x", sessionKey[i]);
  // }
  // printf("\n");
  return sessionKey;
}
// unsigned char* getIrcServerKey(){
//   FILE* fp = fopen("ircServerKey", "r");
//   unsigned char* ircServerKey = (unsigned char*)malloc(32);
//   fread(ircServerKey, 1, 32, fp);
//   fclose(fp);
//   return ircServerKey;
// }
// unsigned char* getUserKey(char* userName){
//   // open userName file
//   FILE* fp = fopen(userName, "r");
//   unsigned char* userKey = (unsigned char*)malloc(32);
//   fread(userKey, 1, 32, fp);
//   fclose(fp);
//   return userKey;
// }
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
encryptRet* generateTicket(char* userName, unsigned char* sessionKey){
  unsigned char* ticket = (unsigned char*)malloc(37);
  memcpy(ticket, userName, 5);
  memcpy(ticket+5, sessionKey, 32);
  encryptRet* ret = encrypt(getIrcServerKey(), ticket, 37);
  free(ticket);
  for (int i=0; i<ret->ciphertext_len; i++){
    printf("%02x ",ret->ciphertext[i]);
  }
  printf("\n");
  return ret;
}

encryptRet* generateMessage(char* nonce, unsigned char* sessionKey, encryptRet* ticket, char* userName){
  unsigned char* msgMsg = (unsigned char*)malloc(4+32+ticket->ciphertext_len+1);
  memcpy(msgMsg, nonce, 4);
  memcpy(msgMsg+4, sessionKey, 32);
  memcpy(msgMsg+36, ticket->ciphertext, ticket->ciphertext_len);
  encryptRet* msg = encrypt(getUserKey(userName), msgMsg, 36+ticket->ciphertext_len);
  free(msgMsg);
  free(ticket->ciphertext);
  free(ticket);
  return msg;
}

void* clientHandler(void* arg){
	int clientSock = ((param*)arg)->clientSock;
  char buffer[1024];
  // msg format: sender:receiver:nonce
  if(read(clientSock, buffer, 1024) < 0){
    perror("[-]Read error");
  }
  char* sender = strtok(buffer, ":");
  char* receiver = strtok(NULL, ":");
  char* nonce = strtok(NULL, ":");
  // if reciever is not kdc, drop
  if (strcmp(receiver, "kdc") != 0){
    printf("[-]Receiver is not kdc\n");
    return NULL;
  }
  // if sender is not in database, drop
  if (verifyUser(sender) < 0){
    printf("[-]User not found\n");
    return NULL;
  }
  // get session key(32bytes)
  unsigned char* sessionKey = getSessionKey(sender);
  // get user key(32bytes)
  unsigned char* userKey = getUserKey(sender);
  // ticket = ENCircserverkey{userName,sessionKey}
  // user name is of 5bytes
  // nonce is of 4bytes
  // keys are of 32bytes
  encryptRet* ticket = generateTicket(sender, sessionKey);
  // msg = ENCuserkey{nonce:sessionKey:ticket}
  encryptRet* msg = generateMessage(nonce, sessionKey, ticket, sender);
	
  // send msg to client
  if (write(clientSock, msg->ciphertext, msg->ciphertext_len) < 0){
    perror("[-]Write error");
  }
  
  free(msg->ciphertext);
  free(msg);
  close(clientSock);
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
	// tid[tidCounter] = pthread_create(&tid[tidCounter],NULL,clientHandler,NULL);
	// tidCounter++;
  }

  // for (int i =0; i <tidCounter; i++){
  //   pthread_join(tid[i],NULL);
  // }
  return 0;
}

// gcc kdc.cpp -o kdc -lssl -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -I/usr/local/include/node/openssl/