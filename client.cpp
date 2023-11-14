#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

typedef struct encryptRet{
  unsigned char* ciphertext;
  int ciphertext_len;
} encryptRet;

encryptRet* encrypt(unsigned char* key, unsigned char* msg,int msgLen, unsigned char* IV){
  EVP_CIPHER_CTX *ctx;
  unsigned char* ciphertext = (unsigned char*)malloc(1024);
  int len;
  int ciphertext_len;
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, IV);
  EVP_EncryptUpdate(ctx, ciphertext, &len, msg, msgLen);
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  encryptRet* ret = (encryptRet*)malloc(sizeof(encryptRet));
  ret->ciphertext = ciphertext;
  ret->ciphertext_len = ciphertext_len;
  return ret;
}

// decrypt function
encryptRet* decrypt(unsigned char* key, unsigned char* ciphertext, int msgLen, unsigned char* IV){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  unsigned char* plaintext = (unsigned char*)malloc(1024);
  encryptRet* ret = (encryptRet*)malloc(sizeof(encryptRet));
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, IV);
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, msgLen);
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  ret->ciphertext = plaintext;
  ret->ciphertext_len = plaintext_len;
  return ret;
}
unsigned char* getRand(int size){
  unsigned char* randBytes = (unsigned char*) malloc(size);
  FILE* urandom = fopen("/dev/urandom", "r");
  fread(randBytes, 1, size, urandom);
  fclose(urandom);
  return randBytes;
}
int main(){
  signal(SIGPIPE,SIG_IGN);
//   client program
  int port = 8080;
  int sock, clientSock;
  struct sockaddr_in addr;
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0){
	perror("[-]Socket error");
  }
  memset(&addr, '\0', sizeof(addr));;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
//   connect
  if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0){
	perror("[-]Connect error");
  }
  // msg format: 12345:kdc:1
  unsigned char* nonceSent = getRand(4);
  char msg[1024];
  sprintf(msg, "%d:%s:%s", 12345, "kdc", nonceSent);
  if (write(sock, msg, strlen(msg)) < 0){
    perror("[-]Write error");
  }
  // read response
  unsigned char response[1024];
  int res = read(sock, response, 1024);
  if ( res < 0){
    perror("[-]Read error");
  }
  printf("reponse length %d\n",res);
  // for (int i=0; i<res; i++){
  //   printf("%02x", response[i]);
  // }
  // printf("\n");
  unsigned char* IV = (unsigned char*) malloc(16);
  memcpy(IV,response+res-16,16);
  unsigned char* privateKey = (unsigned char*)malloc(32);
  FILE* fp = fopen("12345", "r");
  fread(privateKey, 1, 32, fp);
  fclose(fp);
  encryptRet* decrypted = decrypt(privateKey, response, res-16, IV);

  unsigned char* nonceRecieved = (unsigned char*)malloc(4);
  memcpy(nonceRecieved, decrypted->ciphertext, 4);
  // compare nonce with nonce sent
  if (nonceSent[0]!=nonceRecieved[0] || nonceSent[1]!=nonceRecieved[1] || nonceSent[2]!=nonceRecieved[2] || nonceSent[3]!=nonceRecieved[3]){
    printf("Nonce mismatch\n");
    // close connection
  }
  else{
    printf("Nonce matched\n");
  }
  // printf("nonce: %s\n", nonce);
  unsigned char* sessionKey = (unsigned char*)malloc(32);
  memcpy(sessionKey, decrypted->ciphertext+4, 32);
  // ticket = ENCircserverkey{userName,sessionKey}
  // user name is of 5bytes
  // nonce is of 4bytes
  // keys are of 32bytes
  // msg = ENCuserkey{nonce:sessionKey:ticket}
  // print all elements in hexa, first 4bytes are nonce
  // get nonce and session key
    unsigned char* ticket = (unsigned char*)malloc(decrypted->ciphertext_len-36);
  memcpy(ticket, decrypted->ciphertext+36, decrypted->ciphertext_len-36);
  // encryptRet* ticketDecrypted = decrypt(ircserverkey, ticket);
  //   first 5bytes are username and print it
  // char* username = (char*)malloc(5);
  // memcpy(username, ticketDecrypted->ciphertext, 5);
  // printf("username: %d %s\n",ticketDecrypted->ciphertext_len, username);
  close(sock);
  
  port = 9090;
  addr.sin_port = htons(port);
  sock = socket(AF_INET, SOCK_STREAM, 0);
  connect(sock, (struct sockaddr*)&addr, sizeof(addr));
  
  // send ticket first then send challenge
  res = send(sock, ticket, decrypted->ciphertext_len-36, 0);
  printf("ticket sent %d\n", res);
  // generate a 4 byte challenge && 16 byte IV
  unsigned char* randomNumberChar = getRand(4);
  IV = getRand(16);
  encryptRet* encryptedRandomNumber = encrypt(sessionKey, randomNumberChar, 4, IV);
  sleep(1);
  unsigned char* msg2 = (unsigned char*) malloc(encryptedRandomNumber->ciphertext_len+16); 
  memcpy(msg2,encryptedRandomNumber->ciphertext,encryptedRandomNumber->ciphertext_len);
  memcpy(msg2+encryptedRandomNumber->ciphertext_len,IV,16);
  res = send(sock, msg2, encryptedRandomNumber->ciphertext_len+16, 0);
  // free(msg2);
  printf("random number sent %d\n", res);
  // read response
  IV = (unsigned char*) malloc(16);
  res = read(sock, response, 1024);
  if ( res < 0){
    perror("[-]Read error");
  }
  memcpy(IV,response+res-16,16);
  // printf("reponse length %d\n",res);
  // response would have first 4 bytes as challenge response and next 4 bytes as new challenge
  encryptRet* decryptedResponse = decrypt(sessionKey, response, res, IV);
  unsigned char* challengeResponseChar = (unsigned char*)malloc(4);
  unsigned char* newChallengeChar = (unsigned char*)malloc(4);
  memcpy(challengeResponseChar, decryptedResponse->ciphertext, 4);
  memcpy(newChallengeChar, decryptedResponse->ciphertext+4, 4);
// compare challenge response with randomNumberChar[3]+1
  int challengeResponse = (int)challengeResponseChar[3];
  int randomNumber = (int)randomNumberChar[3];

  // printf("new challenge: %d\n", newChallenge);
  if (challengeResponse == randomNumber+1){
    printf("Challenge passed\n");
  }
  else{
    printf("Challenge failed\n");
    // close connection
  }
  // send new challenge response
  newChallengeChar[3] = newChallengeChar[3] + 1;
  IV = getRand(16);
  encryptRet* newChallengeResponse = encrypt(sessionKey, newChallengeChar, 4, IV);
  msg2 = (unsigned char*) malloc(newChallengeResponse->ciphertext_len+16);
  memcpy(msg2,newChallengeResponse->ciphertext,newChallengeResponse->ciphertext_len);
  memcpy(msg2+newChallengeResponse->ciphertext_len,IV,16);
  res = send(sock, msg2, newChallengeResponse->ciphertext_len+16, 0);
  printf("new challenge response sent %d\n", res);


  
  return 0;
}