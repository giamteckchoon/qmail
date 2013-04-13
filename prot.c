#include "hasshsgr.h"
#include "prot.h"
#include "auto_uids.h"

/* XXX: there are more portability problems here waiting to leap out at me */

int prot_gid(gid) int gid;
{
  gid = get_gid(gid);
#ifdef HASSHORTSETGROUPS
  short x[2];
  x[0] = gid; x[1] = 73; /* catch errors */
  if (setgroups(1,x) == -1) return -1;
#else
  if (setgroups(1,&gid) == -1) return -1;
#endif
  return setgid(gid); /* _should_ be redundant, but on some systems it isn't */
}

int prot_uid(uid) int uid;
{
  uid = get_uid(uid);
  return setuid(uid);
}
