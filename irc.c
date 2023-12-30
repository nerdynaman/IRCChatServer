#include "kdc.hh"
#include "irc.hh"

userInfo usersInIRC[100];
int userCount = 0;

Group groups[20];  // Maximum of 20 groups
int groupCount = 0;

// storing tickets and userName for each user
userTicket userTickets[100];
int userTicketCount = 0;

int authenticate(int clientSock){
	// reading ticket from client
	unsigned char msg[1024];
	int res = read(clientSock, msg, 1024); //read res number of bytes
	printf("%d data recieved\n",res);

	// // decrypt ticket using ircServerKey i.e. private key
	unsigned char* ticket = decryptIV(msg, getIrcServerKey(), res);
	// saving username and sessionKey from ticket
	unsigned char* userName = (unsigned char*)malloc(5);
	memcpy(userName, ticket, 5);
	unsigned char* sessionKey = (unsigned char*)malloc(32);
	memcpy(sessionKey, ticket+5, 32);
	sessionKey[32] = '\0';
	userName[5] = '\0';
	// checking for ticket replay attack 
	for (int i = 0; i < userTicketCount; i++){
		if (strcmp(userTickets[i].sessionKey, sessionKey) == 0 && strcmp(userTickets[i].userName, userName) == 0){
			printf("[-]Ticket replay attack detected\n");
			return 0;
		}
	}
	printf("[+]Ticket replay attack passed\n");
	// recieve challenge from client to verify authenticity of irc server
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);

	// decrypt challenge using sessionKey
	unsigned char* challenge = decryptIV(msg, sessionKey, res);
	// solving challenge by incrementing last byte by 1
	challenge[3] = challenge[3] + 1;
	// generate new challenge 
	unsigned char* newChallenge = getRand(4);
	
	// encrypt new challenge and old challenge response using sessionKey
	// allocating memory for old challenge response and new challenge i.e. 4 + 4 = 8 bytes
	// format: oldChallengeResponse:NewChallenge
	unsigned char* challengeResStr = (unsigned char*)malloc(8);
	memcpy(challengeResStr, challenge, 4);
	memcpy(challengeResStr+4, newChallenge, 4);
	// encrypting challenge response using sessionKey with IV
	encryptRet* challengeResEnc = encMessage(challengeResStr, sessionKey, 8);
	// sending challenge response to client
	write(clientSock, challengeResEnc->ciphertext, challengeResEnc->ciphertext_len);
	
	// read challenge response from client
	res = read(clientSock, msg, 1024);
	printf("%d data recieved\n",res);
	// decrypt challenge response using sessionKey
	unsigned char* msgDec = decryptIV(msg, sessionKey, res);
	// validate challenge response
	if (msgDec[0] != newChallenge[0] || msgDec[1] != newChallenge[1] || msgDec[2] != newChallenge[2] || msgDec[3] != newChallenge[3]+1){
		printf("[-]Challenge response failed\n");
		return 0;
	}
	printf("[+]Challenge response passed\n");

	// adding user to list of users in irc
	userInfo* user = (userInfo*)malloc(sizeof(userInfo));
	user->userName = userName;
	user->pubKey = NULL;
	usersInIRC[userCount++] = *user;
	
	// adding userTicket to list of userTickets
	userTicket* ticketObj = (userTicket*)malloc(sizeof(userTicket));
	ticketObj->userName = userName;
	ticketObj->sessionKey = sessionKey;
	userTickets[userTicketCount++] = *ticketObj;

	return 1;
}

void* clientHandler(void* arg){
	param* p = (param*)arg;
	int clientSock = p->clientSock;
	if (authenticate(clientSock) == 0){
		printf("[-]Authentication failed\n");
		return NULL;
	}

	
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