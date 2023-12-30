#include "kdc.hh"

encryptRet* generateTicket(char* userName, unsigned char* sessionKey){
  unsigned char* ticket = (unsigned char*)malloc(37);
  memcpy(ticket, userName, 5);
  memcpy(ticket+5, sessionKey, 32);
  encryptRet* ret = encMessage(ticket, getIrcServerKey(), 37);
  free(ticket);
  return ret;
}

encryptRet* generateMessage(char* nonce, unsigned char* sessionKey, encryptRet* ticket, char* userName){
  unsigned char* msgMsg = (unsigned char*)malloc(4+32+ticket->ciphertext_len);
  memcpy(msgMsg, nonce, 4);
  memcpy(msgMsg+4, sessionKey, 32);
  memcpy(msgMsg+36, ticket->ciphertext, ticket->ciphertext_len);
  encryptRet* msg = encMessage(msgMsg, getUserKey(userName), 4+32+ticket->ciphertext_len);
  free(msgMsg);
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
  printf("sender: %s request recieved\n", sender);
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
  unsigned char* sessionKey = getRand(32);
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
  printf("msg sent\n");
  free(msg->ciphertext);
  free(msg);
  close(clientSock);
	return NULL;
}

int main(){
  signal(SIGPIPE,SIG_IGN);
  pthread_t tid;
  int sock = serverSetup(8080);
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