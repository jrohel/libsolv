/*
 * Copyright (c) 2008-2012, Novell Inc.
 *
 * This program is licensed under the BSD license, read LICENSE.BSD
 * for further information
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pool.h"
#include "util.h"
#include "chksum.h"

#if HASH_LIB == USE_OPENSSL

#include <openssl/md5.h>
#include <openssl/sha.h>

typedef SHA_CTX SHA1_CTX;
typedef SHA256_CTX SHA224_CTX;
typedef SHA512_CTX SHA384_CTX;

#define solv_MD5_Init(ctx) MD5_Init(ctx)
#define solv_MD5_Update(ctx, data, len) MD5_Update(ctx, data, len)
#define solv_MD5_Final(md, ctx) MD5_Final(md, ctx)
#define solv_SHA1_Init(ctx) SHA1_Init(ctx)
#define solv_SHA1_Update(ctx, data, len) SHA1_Update(ctx, data, len)
#define solv_SHA1_Final(ctx, md) SHA1_Final(md, ctx)
#define solv_SHA224_Init(ctx) SHA224_Init(ctx)
#define solv_SHA224_Update(ctx, data, len) SHA224_Update(ctx, data, len)
#define solv_SHA224_Final(md, ctx) SHA224_Final(md, ctx)
#define solv_SHA256_Init(ctx) SHA256_Init(ctx)
#define solv_SHA256_Update(ctx, data, len) SHA256_Update(ctx, data, len)
#define solv_SHA256_Final(md, ctx) SHA256_Final(md, ctx)
#define solv_SHA384_Init(ctx) SHA384_Init(ctx)
#define solv_SHA384_Update(ctx, data, len) SHA384_Update(ctx, data, len)
#define solv_SHA384_Final(md, ctx) SHA384_Final(md, ctx)
#define solv_SHA512_Init(ctx) SHA512_Init(ctx)
#define solv_SHA512_Update(ctx, data, len) SHA512_Update(ctx, data, len)
#define solv_SHA512_Final(md, ctx) SHA512_Final(md, ctx)

#elif HASH_LIB == USE_NETTLE

#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>

typedef struct md5_ctx MD5_CTX;
typedef struct sha1_ctx SHA1_CTX;
typedef struct sha224_ctx SHA224_CTX;
typedef struct sha256_ctx SHA256_CTX;
typedef struct sha384_ctx SHA384_CTX;
typedef struct sha512_ctx SHA512_CTX;

#define solv_MD5_Init(ctx) md5_init(ctx)
#define solv_MD5_Update(ctx, data, len) md5_update(ctx, len, data)
#define solv_MD5_Final(md, ctx) md5_digest(ctx, MD5_DIGEST_SIZE, md)
#define solv_SHA1_Init(ctx) sha1_init(ctx)
#define solv_SHA1_Update(ctx, data, len) sha1_update(ctx, len, data)
#define solv_SHA1_Final(ctx, md) sha1_digest(ctx, SHA1_DIGEST_SIZE, md)
#define solv_SHA224_Init(ctx) sha224_init(ctx)
#define solv_SHA224_Update(ctx, data, len) sha224_update(ctx, len, data)
#define solv_SHA224_Final(md, ctx) sha224_digest(ctx, SHA224_DIGEST_SIZE, md)
#define solv_SHA256_Init(ctx) sha256_init(ctx)
#define solv_SHA256_Update(ctx, data, len) sha256_update(ctx, len, data)
#define solv_SHA256_Final(md, ctx) sha256_digest(ctx, SHA256_DIGEST_SIZE, md)
#define solv_SHA384_Init(ctx) sha384_init(ctx)
#define solv_SHA384_Update(ctx, data, len) sha384_update(ctx, len, data)
#define solv_SHA384_Final(md, ctx) sha384_digest(ctx, SHA384_DIGEST_SIZE, md)
#define solv_SHA512_Init(ctx) sha512_init(ctx)
#define solv_SHA512_Update(ctx, data, len) sha512_update(ctx, len, data)
#define solv_SHA512_Final(md, ctx) sha512_digest(ctx, SHA512_DIGEST_SIZE, md)

#elif HASH_LIB == USE_GCRYPT

#include <gcrypt.h>

typedef gcry_md_hd_t MD5_CTX;
typedef gcry_md_hd_t SHA1_CTX;
typedef gcry_md_hd_t SHA224_CTX;
typedef gcry_md_hd_t SHA256_CTX;
typedef gcry_md_hd_t SHA384_CTX;
typedef gcry_md_hd_t SHA512_CTX;

static void
hash_final(unsigned char *md, gcry_md_hd_t *ctx, int algo)
{
  unsigned char * tmp = gcry_md_read(*ctx, 0);
  memcpy(md, tmp, gcry_md_get_algo_dlen(algo));
  gcry_md_close(*ctx);
  *ctx = NULL;
}

#define solv_MD5_Init(ctx) gcry_md_open(ctx, GCRY_MD_MD5, 0)
#define solv_MD5_Update(ctx, data, len) gcry_md_write(*ctx, data, len)
#define solv_MD5_Final(md, ctx) hash_final(md, ctx, GCRY_MD_MD5)
#define solv_SHA1_Init(ctx) gcry_md_open(ctx, GCRY_MD_SHA1, 0)
#define solv_SHA1_Update(ctx, data, len)  gcry_md_write(*ctx, data, len)
#define solv_SHA1_Final(ctx, md) hash_final(md, ctx, GCRY_MD_SHA1)
#define solv_SHA224_Init(ctx) gcry_md_open(ctx, GCRY_MD_SHA224, 0)
#define solv_SHA224_Update(ctx, data, len)  gcry_md_write(*ctx, data, len)
#define solv_SHA224_Final(md, ctx) hash_final(md, ctx, GCRY_MD_SHA224)
#define solv_SHA256_Init(ctx) gcry_md_open(ctx, GCRY_MD_SHA256, 0)
#define solv_SHA256_Update(ctx, data, len)  gcry_md_write(*ctx, data, len)
#define solv_SHA256_Final(md, ctx) hash_final(md, ctx, GCRY_MD_SHA256)
#define solv_SHA384_Init(ctx) gcry_md_open(ctx, GCRY_MD_SHA384, 0)
#define solv_SHA384_Update(ctx, data, len)  gcry_md_write(*ctx, data, len)
#define solv_SHA384_Final(md, ctx) hash_final(md, ctx, GCRY_MD_SHA384)
#define solv_SHA512_Init(ctx) gcry_md_open(ctx, GCRY_MD_SHA512, 0)
#define solv_SHA512_Update(ctx, data, len)  gcry_md_write(*ctx, data, len)
#define solv_SHA512_Final(md, ctx) hash_final(md, ctx, GCRY_MD_SHA512)

#else

#include "md5.h"
#include "sha1.h"
#include "sha2.h"

#endif

struct s_Chksum {
  Id type;
  int done;
  unsigned char result[64];
  union {
    MD5_CTX md5;
    SHA1_CTX sha1;
    SHA224_CTX sha224;
    SHA256_CTX sha256;
    SHA384_CTX sha384;
    SHA512_CTX sha512;
  } c;
};

Chksum *
solv_chksum_create(Id type)
{
  Chksum *chk;
  chk = solv_calloc(1, sizeof(*chk));
  chk->type = type;
  switch(type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Init(&chk->c.md5);
      return chk;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Init(&chk->c.sha1);
      return chk;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Init(&chk->c.sha224);
      return chk;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Init(&chk->c.sha256);
      return chk;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Init(&chk->c.sha384);
      return chk;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Init(&chk->c.sha512);
      return chk;
    default:
      break;
    }
  free(chk);
  return 0;
}

Chksum *
solv_chksum_create_clone(Chksum *chk)
{
  Chksum *clone = solv_memdup(chk, sizeof(*chk));
#if HASH_LIB == USE_GCRYPT
  if (chk->c.sha512)
    gcry_md_copy(&clone->c.sha512, chk->c.sha512);
#endif
  return clone;
}

int
solv_chksum_len(Id type)
{
  switch (type)
    {
    case REPOKEY_TYPE_MD5:
      return 16;
    case REPOKEY_TYPE_SHA1:
      return 20;
    case REPOKEY_TYPE_SHA224:
      return 28;
    case REPOKEY_TYPE_SHA256:
      return 32;
    case REPOKEY_TYPE_SHA384:
      return 48;
    case REPOKEY_TYPE_SHA512:
      return 64;
    default:
      return 0;
    }
}

Chksum *
solv_chksum_create_from_bin(Id type, const unsigned char *buf)
{
  Chksum *chk;
  int l = solv_chksum_len(type);
  if (buf == 0 || l == 0)
    return 0;
  chk = solv_calloc(1, sizeof(*chk));
  chk->type = type;
  chk->done = 1;
  memcpy(chk->result, buf, l);
  return chk;
}

void
solv_chksum_add(Chksum *chk, const void *data, int len)
{
  if (chk->done)
    return;
  switch(chk->type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Update(&chk->c.md5, (void *)data, len);
      return;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Update(&chk->c.sha1, data, len);
      return;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Update(&chk->c.sha224, data, len);
      return;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Update(&chk->c.sha256, data, len);
      return;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Update(&chk->c.sha384, data, len);
      return;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Update(&chk->c.sha512, data, len);
      return;
    default:
      return;
    }
}

const unsigned char *
solv_chksum_get(Chksum *chk, int *lenp)
{
  if (chk->done)
    {
      if (lenp)
        *lenp = solv_chksum_len(chk->type);
      return chk->result;
    }
  switch(chk->type)
    {
    case REPOKEY_TYPE_MD5:
      solv_MD5_Final(chk->result, &chk->c.md5);
      chk->done = 1;
      if (lenp)
	*lenp = 16;
      return chk->result;
    case REPOKEY_TYPE_SHA1:
      solv_SHA1_Final(&chk->c.sha1, chk->result);
      chk->done = 1;
      if (lenp)
	*lenp = 20;
      return chk->result;
    case REPOKEY_TYPE_SHA224:
      solv_SHA224_Final(chk->result, &chk->c.sha224);
      chk->done = 1;
      if (lenp)
	*lenp = 28;
      return chk->result;
    case REPOKEY_TYPE_SHA256:
      solv_SHA256_Final(chk->result, &chk->c.sha256);
      chk->done = 1;
      if (lenp)
	*lenp = 32;
      return chk->result;
    case REPOKEY_TYPE_SHA384:
      solv_SHA384_Final(chk->result, &chk->c.sha384);
      chk->done = 1;
      if (lenp)
	*lenp = 48;
      return chk->result;
    case REPOKEY_TYPE_SHA512:
      solv_SHA512_Final(chk->result, &chk->c.sha512);
      chk->done = 1;
      if (lenp)
	*lenp = 64;
      return chk->result;
    default:
      if (lenp)
	*lenp = 0;
      return 0;
    }
}

Id
solv_chksum_get_type(Chksum *chk)
{
  return chk->type;
}

int
solv_chksum_isfinished(Chksum *chk)
{
  return chk->done != 0;
}

const char *
solv_chksum_type2str(Id type)
{
  switch(type)
    {
    case REPOKEY_TYPE_MD5:
      return "md5";
    case REPOKEY_TYPE_SHA1:
      return "sha1";
    case REPOKEY_TYPE_SHA224:
      return "sha224";
    case REPOKEY_TYPE_SHA256:
      return "sha256";
    case REPOKEY_TYPE_SHA384:
      return "sha384";
    case REPOKEY_TYPE_SHA512:
      return "sha512";
    default:
      return 0;
    }
}

Id
solv_chksum_str2type(const char *str)
{
  if (!strcasecmp(str, "md5"))
    return REPOKEY_TYPE_MD5;
  if (!strcasecmp(str, "sha") || !strcasecmp(str, "sha1"))
    return REPOKEY_TYPE_SHA1;
  if (!strcasecmp(str, "sha224"))
    return REPOKEY_TYPE_SHA224;
  if (!strcasecmp(str, "sha256"))
    return REPOKEY_TYPE_SHA256;
  if (!strcasecmp(str, "sha384"))
    return REPOKEY_TYPE_SHA384;
  if (!strcasecmp(str, "sha512"))
    return REPOKEY_TYPE_SHA512;
  return 0;
}

void *
solv_chksum_free(Chksum *chk, unsigned char *cp)
{
  if (cp)
    {
      const unsigned char *res;
      int l;
      res = solv_chksum_get(chk, &l);
      if (l && res)
        memcpy(cp, res, l);
    }
  solv_free(chk);
  return 0;
}

int
solv_chksum_cmp(Chksum *chk, Chksum *chk2)
{
  int len;
  const unsigned char *res1, *res2;
  if (chk == chk2)
    return 1;
  if (!chk || !chk2 || chk->type != chk2->type)
    return 0;
  res1 = solv_chksum_get(chk, &len);
  res2 = solv_chksum_get(chk2, 0);
  return memcmp(res1, res2, len) == 0 ? 1 : 0;
}
