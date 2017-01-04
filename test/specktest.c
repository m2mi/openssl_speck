#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/********************** Test Sepck 128 **************************** */

int encrypt128(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_speck_128_cbc(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt128(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_speck_128_cbc(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int test128(void) {

  /* A 128 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 64 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

  printf("Plaintext is:\n");
  BIO_dump_fp (stdout, (const char *)plaintext, strlen ((const char *)plaintext));


  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  ciphertext_len = encrypt128(plaintext, strlen ((const char *)plaintext), key, iv, ciphertext);

  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  decryptedtext_len = decrypt128(ciphertext, ciphertext_len, key, iv, decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';

  printf("Decrypted text is:\n");
  BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

  EVP_cleanup();
  ERR_free_strings();

  return strcmp((const char *)plaintext, (const char *)decryptedtext);

}

/* ******************** Test Sepck 256 ***************************** */

int encrypt256(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_speck_256_cbc(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt256(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_speck_256_cbc(), NULL, key, iv))
    handleErrors();

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int test256(void) {

  /* A 256 bit key */
  unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

  /* A 128 bit IV */
  unsigned char *iv = (unsigned char *)"01234567890123456";

  /* Message to be encrypted */
  unsigned char *plaintext = (unsigned char *)"The quick brown fox jumps over the lazy dog";

  printf("Plaintext is:\n");
  BIO_dump_fp (stdout, (const char *)plaintext, strlen ((const char *)plaintext));


  unsigned char ciphertext[128];
  unsigned char decryptedtext[128];

  int decryptedtext_len, ciphertext_len;

  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();

  ciphertext_len = encrypt256(plaintext, strlen ((const char *)plaintext), key, iv, ciphertext);

  printf("Ciphertext is:\n");
  BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

  decryptedtext_len = decrypt256(ciphertext, ciphertext_len, key, iv, decryptedtext);
  decryptedtext[decryptedtext_len] = '\0';

  printf("Decrypted text is:\n");
  BIO_dump_fp (stdout, (const char *)decryptedtext, decryptedtext_len);

  EVP_cleanup();
  ERR_free_strings();

  return strcmp((const char *)plaintext, (const char *)decryptedtext);

}

int main (int argc, char **argv)
{
  printf("Testing Speck 128:\n");
  int test1 = test128();
  printf("Testing Speck 256:\n");
  int test2 = test256();

  return test1 + test2;

}