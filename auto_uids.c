#include <stdlib.h>
#include <sys/stat.h>
#include "exit.h"
#include "subfd.h"
#include "substdio.h"
#include "auto_qmail.h"
#include "auto_uids.h"

/* These are offsets from the end of either uid_files or gid_files */

int auto_uida = -8;
int auto_uidd = -7;
int auto_uidl = -6;
int auto_uido = -5;
int auto_uidp = -4;
int auto_uidq = -3;
int auto_uidr = -2;
int auto_uids = -1;

int auto_gidn = -2;
int auto_gidq = -1;

#define uid_table_size 8
#define gid_table_size 2

struct file_ref { const char *name; int *var; };

static struct file_ref uid_files[uid_table_size] = {
	{ "uida", &auto_uida },
	{ "uidd", &auto_uidd },
	{ "uidl", &auto_uidl },
	{ "uido", &auto_uido },
	{ "uidp", &auto_uidp },
	{ "uidq", &auto_uidq },
	{ "uidr", &auto_uidr },
	{ "uids", &auto_uids }
};

static struct file_ref gid_files[gid_table_size] = {
	{ "gidn", &auto_gidn },
	{ "gidq", &auto_gidq }
};

static int stat_control_file(name, buf) char* name; struct stat* buf;
{
  int result;
  char* file = malloc(strlen(auto_qmail) + strlen(name) + 10);
  if(file == 0)
   {
    substdio_putsflush(subfderr,"fatal: unable to allocate memory\n");
    _exit(111);
   }
  strcpy(file, auto_qmail);
  strcat(file, "/owners/");
  strcat(file, name);
  result = stat(file, buf);
  free(file);
  return result;
}

static int stat_uid_file(ref) struct file_ref* ref;
{
  struct stat statbuf;
  if(stat_control_file(ref->name, &statbuf) == -1)
   {
    substdio_puts(subfderr,"fatal: unable to stat uid control file '");
    substdio_puts(subfderr,ref->name);
    substdio_puts(subfderr,"'\n");
    substdio_flush(subfderr);
    _exit(111);
   }
  return *(ref->var) = statbuf.st_uid;
}

static int stat_gid_file(ref) struct file_ref* ref;
{
  struct stat statbuf;
  if(stat_control_file(ref->name, &statbuf) == -1)
   {
    substdio_puts(subfderr,"fatal: unable to stat gid control file '");
    substdio_puts(subfderr,ref->name);
    substdio_puts(subfderr,"'\n");
    substdio_flush(subfderr);
    _exit(111);
   }
  return *(ref->var) = statbuf.st_gid;
}

int get_uid(id) int id;
{
  if(id >= 0)
    return id;
  else if(id < -uid_table_size)
    return -1;
  else
    return stat_uid_file(&uid_files[uid_table_size+id]);
}

int get_gid(id) int id;
{
  if(id >= 0)
    return id;
  else if(id < -gid_table_size)
    return -1;
  else
    return stat_gid_file(&gid_files[gid_table_size+id]);
}

