/* 
 * Does preprocessing of keyrings for an intermediate file to be monged
 * by keyanalyze.
 *
 * Copyright (c)2001 Thomas Roessler <roessler@does-not-exist.org>
 * 
 * This program can be freely distributed under the GNU General Public
 * License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <getopt.h>

static int DontRequireSelfSig = 0;

#define IDBUF 17

struct sig
{
  struct sig *next;
  char id[IDBUF];
};

struct uid
{
  struct uid *next;
  struct sig *sigs;
  unsigned self : 1;
};

struct key
{
  char id[IDBUF];
  struct uid *uids;
  unsigned rev : 1;
};

static void free_sig (struct sig **sigpp)
{
  struct sig *sigp, *q;
  
  if (!sigpp || !*sigpp)
    return;
  
  for (sigp = *sigpp; sigp; sigp = q)
  {
    q = sigp->next;
    free (sigp);
  }
  
  *sigpp = NULL;
}

static void free_uid (struct uid **uidpp)
{
  struct uid *uidp, *q;
  
  if (!uidpp || !*uidpp)
    return;
  
  for (uidp = *uidpp; uidp; uidp = q)
  {
    q = uidp->next;
   free (uidp);
  }
  
  *uidpp = NULL;
}

static void free_key (struct key **keypp)
{
  struct key *keyp;
  
  if (!keypp || !(keyp = *keypp))
    return;
  
  free_uid (&keyp->uids);
  
  free (keyp);
  *keypp = NULL;
}

#define new_sig() calloc (sizeof (struct sig), 1)
#define new_uid() calloc (sizeof (struct uid), 1)
#define new_key() calloc (sizeof (struct key), 1)

/* Is a signature with this ID present? */

static int check_sig_id (struct sig *signatures, char *id)
{
  struct sig *s;
  
  for (s = signatures; s; s = s->next)
    if (!strcmp (s->id, id))
      return 1;
  
  return 0;
}

/* Is this user ID self-signed? */

static int check_selfsig (struct uid *uid, struct key *key)
{
  return (uid->self = check_sig_id (uid->sigs, key->id));
}

/* Append a list of signatures to a different list of signatures */

static void join_siglists (struct sig **sig_d, struct sig **sig_s)
{
  while (*sig_d)
    sig_d = &((*sig_d)->next);
  
  *sig_d = *sig_s;
  *sig_s = NULL;
}

/* Clean up a list of signatures - inefficient! */

static void cleanup_siglist (struct sig **sig, char *keyid)
{
  struct sig **last = sig;
  struct sig *p, *q;
  
  for (p = *sig; p; p = q)
  {
    q = p->next;
    if (!strcmp (keyid, p->id) || check_sig_id (p->next, p->id))
    {
      *last = p->next;
      p->next = NULL;
      free_sig (&p);
    }
    else
      last = &p->next;
  }
}

/* print the information gathered */

static void do_key (struct key *k)
{
  struct sig *interesting_signatures = NULL, *sigp;
  struct uid *uidp;
  
  if (k->rev)
    return;
  
  for (uidp = k->uids; uidp; uidp = uidp->next)
    if (DontRequireSelfSig || check_selfsig (uidp, k))
      join_siglists (&interesting_signatures, &uidp->sigs);
  
  cleanup_siglist (&interesting_signatures, k->id);
  if (interesting_signatures)
  { 
    printf ("p%s\n", k->id);
    for (sigp = interesting_signatures; sigp; sigp = sigp->next)
      printf ("s%s\n", sigp->id);
  }

  free_sig (&interesting_signatures);
  free_uid (&k->uids);
}

/* the main routine */

int main (int argc, char *argv[])
{
  char buff[1024];
  char *s;
  
  struct sig **lastsig = NULL;
  struct uid **lastuid = NULL;
  struct key *k = new_key();
  
  lastuid = &k->uids;

  if (argc == 2 && !strcmp (argv[1], "-S"))
    DontRequireSelfSig = 1;

  while (fgets (buff, sizeof (buff), stdin))
  {
    if ((s = strtok (buff, ":")))
    {
      if (!strcmp (s, "pub"))
      {
	do_key (k);
	k->rev = 0;
	k->uids = new_uid();

	lastuid = &k->uids->next;
	lastsig = &k->uids->sigs;

	strtok (NULL, ":");
	strtok (NULL, ":");
	strtok (NULL, ":");

	sprintf (k->id, "%s", strtok (NULL, ":"));
      }
      else if (!strcmp (s, "rev"))
	k->rev = 1;
      else if (!strcmp (s, "uid"))
      {
	struct uid *uid = *lastuid = new_uid();
	lastuid = &(*lastuid)->next;
	lastsig = &uid->sigs;
      }
      else if (!strcmp (s, "sig"))
      {
	struct sig *sig = *lastsig = new_sig();
	lastsig = &sig->next;
	sprintf (sig->id, "%s", strtok (NULL, ":"));
      }
    }
  }
  
  do_key (k);
  
  return 0;
}
