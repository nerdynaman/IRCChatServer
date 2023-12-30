#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

typedef struct param{
  int clientSock;
} param;

typedef struct encryptRet{
  unsigned char* ciphertext;
  int ciphertext_len;
} encryptRet;

unsigned char* getIrcServerKey(){
  FILE* fp = fopen("ircServerKey", "r");
  unsigned char* ircServerKey = (unsigned char*)malloc(32);
  fread(ircServerKey, 1, 32, fp);
  fclose(fp);
  return ircServerKey;
}
unsigned char* getUserKey(char* userName){
  // open userName file
  FILE* fp = fopen(userName, "r");
  unsigned char* userKey = (unsigned char*)malloc(32);
  fread(userKey, 1, 32, fp);
  fclose(fp);
  return userKey;
}
unsigned char* getRand(int size){
  unsigned char* randBytes = (unsigned char*) malloc(size);
  FILE* urandom = fopen("/dev/urandom", "r");
  fread(randBytes, 1, size, urandom);
  fclose(urandom);
  return randBytes;
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

encryptRet* encMessage(unsigned char* message, unsigned char* key, int msgLen){
  unsigned char* IV = getRand(16);
  encryptRet* encMessage = encrypt(key, message, msgLen, IV);
  unsigned char* encMessageIV = (unsigned char*)malloc(encMessage->ciphertext_len+16);
  memcpy(encMessageIV, encMessage->ciphertext, encMessage->ciphertext_len);
  memcpy(encMessageIV+encMessage->ciphertext_len, IV, 16);
  // free(encMessage->ciphertext);
  // free(IV);
  encMessage->ciphertext = encMessageIV;
  encMessage->ciphertext_len = encMessage->ciphertext_len+16;
  return encMessage;
}

unsigned char* decryptIV(unsigned char* message, unsigned char* key, int msgLen){
  unsigned char* IV = (unsigned char*)malloc(16);
  memcpy(IV, message+msgLen-16, 16);
  encryptRet* decMessage = decrypt(key, message, msgLen-16, IV);
  // free(IV);
  return decMessage->ciphertext;
}

int serverSetup(int port){
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

  if (listen(sock, 10) < 0){
    perror("[-]Listen error");
  }
  return sock;
}