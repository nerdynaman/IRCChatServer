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
encryptRet* encrypt(unsigned char* key, unsigned char* msg,int msgLen){
  EVP_CIPHER_CTX *ctx;
  unsigned char* ciphertext = (unsigned char*)malloc(1024);
  int len;
  int ciphertext_len;
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
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
encryptRet* decrypt(unsigned char* key, unsigned char* ciphertext, int msgLen){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  unsigned char* plaintext = (unsigned char*)malloc(1024);
  encryptRet* ret = (encryptRet*)malloc(sizeof(encryptRet));
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
  EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, msgLen);
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  ret->ciphertext = plaintext;
  ret->ciphertext_len = plaintext_len;
  return ret;
}