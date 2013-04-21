#include "base64.h"
#include "stralloc.h"
#include "substdio.h"
#include "str.h"

static char *b64alpha =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define B64PAD '='

/* returns 0 ok, 1 illegal, -1 problem */

int b64decode(in,l,out)
const unsigned char *in;
int l;
stralloc *out; /* not null terminated */
{
  int i, j;
  unsigned char a[4];
  unsigned char b[3];
  char *s;

  if (l == 0)
  {
    if (!stralloc_copys(out,"")) return -1;
    return 0;
  }

  if (!stralloc_ready(out,l + 2)) return -1; /* XXX generous */
  s = out->s;

  for (i = 0;i < l;i += 4) {
    for (j = 0;j < 4;j++)
      if ((i + j) < l && in[i + j] != B64PAD)
      {
        a[j] = str_chr(b64alpha,in[i + j]);
        if (a[j] > 63) return 1;
      }
      else a[j] = 0;

    b[0] = (a[0] << 2) | (a[1] >> 4);
    b[1] = (a[1] << 4) | (a[2] >> 2);
    b[2] = (a[2] << 6) | (a[3]);

    *s++ = b[0];

    if (in[i + 1] == B64PAD) break;
    *s++ = b[1];

    if (in[i + 2] == B64PAD) break;
    *s++ = b[2];
  }
  out->len = s - out->s;
  while (out->len && !out->s[out->len - 1]) --out->len; /* XXX avoid? */
  return 0;
}

int b64encode(in,out)
stralloc *in;
stralloc *out; /* not null terminated */
{
  unsigned char a, b, c;
  int i;
  char *s;

  if (in->len == 0)
  {
    if (!stralloc_copys(out,"")) return -1;
    return 0;
  }

  if (!stralloc_ready(out,in->len / 3 * 4 + 4)) return -1;
  s = out->s;

  for (i = 0;i < in->len;i += 3) {
    a = in->s[i];
    b = i + 1 < in->len ? in->s[i + 1] : 0;
    c = i + 2 < in->len ? in->s[i + 2] : 0;

    *s++ = b64alpha[a >> 2];
    *s++ = b64alpha[((a & 3 ) << 4) | (b >> 4)];

    if (i + 1 >= in->len) *s++ = B64PAD;
    else *s++ = b64alpha[((b & 15) << 2) | (c >> 6)];

    if (i + 2 >= in->len) *s++ = B64PAD;
    else *s++ = b64alpha[c & 63];
  }
  out->len = s - out->s;
  return 0;
}
