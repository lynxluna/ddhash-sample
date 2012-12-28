#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * This program create hex digest from string from command line
 */

static const char *g_key = "avrakedavra";
static size_t g_keysize  = 11;
int main ( int argc, char **argv )
{
  if (argc < 2) {
    printf("Usage %s [hashtext]\n", argv[0]);
    return EXIT_FAILURE;
  }
  HMAC_CTX ctx;
  unsigned char hash_sha1[SHA_DIGEST_LENGTH];
  unsigned char hash_sha256[SHA256_DIGEST_LENGTH];

  char hash_sha1_hex[SHA_DIGEST_LENGTH * 2 + 1 ];
  char hash_sha256_hex[SHA256_DIGEST_LENGTH * 2 + 1];

  memset( hash_sha1_hex, 0, SHA_DIGEST_LENGTH * 2 + 1 );
  memset( hash_sha256_hex, 0, SHA256_DIGEST_LENGTH * 2 + 1);

  unsigned int i, len;
  /* Init all engines */

  ENGINE_load_builtin_engines();
  ENGINE_register_all_complete();

  /* HMAC-SHA1 digest */
  HMAC_CTX_init( &ctx );

  HMAC_Init_ex( &ctx, g_key, g_keysize, EVP_sha1(), 0);
  HMAC_Update( &ctx, (unsigned char*) argv[1], strlen(argv[1]));
  HMAC_Final(&ctx, hash_sha1, &len);
  

  char *p = &hash_sha1_hex[0];
  unsigned char *h = &hash_sha1[0];
  for ( i = 0; i < len; ++i, ++h)
  {
    p += snprintf( p, 3, "%02x", *h);
  }


  HMAC_CTX_cleanup( &ctx );

  /* HMAC-SHA256 digest */
  HMAC_CTX_init( &ctx );
  HMAC_Init_ex( &ctx, g_key, g_keysize, EVP_sha256(), 0);
  HMAC_Update( &ctx, (unsigned char*) argv[1], strlen(argv[1]));
  HMAC_Final(&ctx, hash_sha256, &len);

  p = &hash_sha256_hex[0];
  h = &hash_sha256[0];
  for ( i = 0; i < len; ++i, ++h)
  {
    p += snprintf(p, 3, "%02x", *h);
  }

  HMAC_CTX_cleanup( &ctx );

  printf("Key\t: %s\nString\t: %s\nSHA1\t: %s\nSHA256\t: %s\n", g_key, argv[1], hash_sha1_hex, hash_sha256_hex);
  
  return EXIT_SUCCESS;
}
