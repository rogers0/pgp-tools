/* keyanalyze.c
 * Does some analysis of pre-monged pgp keyrings for some interesting data.
 * Some code (c)2001 M. Drew Streib <dtype@dtype.org>
 * Some code (c)2001 Thomas Roessler <roessler@does-not-exist.org>
 * Some code (c)2001 Hal J. Burch <hburch@halport.lumeta.com>
 * Some code (c)2001 Matt Kraai <kraai@alumni.carnegiemellon.edu>
 * Some Code (c)2001 Steve Langasek <vorlon@netexpress.net>
 *
 * You are licenced to use this code under the terms of the GNU General
 * Public License (GPL) version 2.
 */

/* some configurables */
static char *infile = "preprocess.keys";
static char *outdir = "output/";
static int outsubdirs = 1; /* create output/12/12345678 or output/12345678 */
#define MAXKEYS 	160000 /* MUST be > `grep p preprocess.keys | wc` */
#define MINSETSIZE	10 /* minimum set size we care about for strong sets */
#define MAXHOPS		30 /* max hop count we care about for report */

/* includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

/* globals */
struct sig {
	int id;
	struct sig *next;
};
typedef struct sig sig;

struct threadparam {
	int threadnum;
};
typedef struct threadparam threadparam;

struct keydata {
	unsigned int id1;
	unsigned int id2;
	sig *to;
	sig *from;
};

struct keydata		keys[MAXKEYS];
FILE 			*fpin,*fpout,*fpstat,*fpsets,*fpmsd;
int 			numkeys = 0;
int 			numsigs = 0;
int			component[MAXKEYS];
int			max_component;
int			max_size;
int			reachable[MAXKEYS];
int			num_reachable;
float 			meantotal;
pthread_mutex_t mean_l;

/* declarations */
void AddKey (unsigned char *newid);
void AddSig (int src, int dst);
void CloseFiles();
int CountSigs(sig *current);
unsigned int ConvertFromHex (const unsigned char *c);
int GetKeyById(const unsigned char* searchid);
void MeanCrawler(int *distset, int id, int len);
float MeanDistance(int id, int *hops, int *hophigh, sig **farthest);

/* ################################################################# */
/* helper functions, in alpha order */

void AddKey (unsigned char *newid) {
	struct keydata *key = &keys[numkeys++];

	/* assume no dupes for now */
	key->id1 = ConvertFromHex(newid);
	key->id2 = ConvertFromHex(newid+8);
}

void AddKeyToList(sig **pptr, int id)
{
	while (*pptr)
		pptr = &(*pptr)->next;

	*pptr = (sig *) calloc (1,sizeof(sig));
	(*pptr)->id = id;
}

void AddSig (int src, int dst) {
	/* if GetKeyById returned -1, then we exit here */
	if ((src == -1) || (dst == -1))
		return;

	AddKeyToList(&keys[dst].to, src);
	AddKeyToList(&keys[src].from, dst);
	
	numsigs++;
}

void CloseFiles() {
	fclose(fpin);
	fclose(fpout);
}

int CountSigs(sig *current) {
	int ret = 0;

	while (current->next) {
		current = current->next;
		ret++;
	}

	return ret;
}

unsigned int ConvertFromHex (const unsigned char *c) {
	unsigned char buf1[5];
	unsigned char buf2[5];
	unsigned int ret;

	buf1[4] = 0;
	buf2[4] = 0;
	memcpy (buf1,c,4);
	memcpy (buf2,c+4,4);
	ret = strtol(buf1,NULL,16)*65536 + strtol(buf2,NULL,16);
	return ret;
}

void DeleteKeyList(sig **pptr)
{
	sig *current = *pptr;

	while (*pptr) {
		current = (*pptr)->next;
		free (*pptr);
		*pptr = current;
	}
}

/* recursive function to mark connected keys in the connected set */
int DFSMarkConnected (int *markset, int id) {
	sig *psig;
	int num = 1;
	/* mark this node, call this function for all subnodes that aren't
	 * marked already */
	markset[id] = 1;
	for (psig = keys[id].from; psig; psig = psig->next) {
		if (!markset[psig->id])
			num += DFSMarkConnected (markset, psig->id);
	}

	return num;
}

int GetKeyById(const unsigned char* searchid) {
	int i;
	unsigned int s1,s2;

	s1 = ConvertFromHex(searchid);
	s2 = ConvertFromHex(searchid+8);
	for (i = 0; i < numkeys; i++) {
		struct keydata *key = &keys[i];
		if ((s1 == key->id1) && (s2 == key->id2)) {
			return i;
		}
	}
	return (-1);
}

/* new _much_ faster BFS version of MeanCrawler() contributed by
 * Hal J. Burch <hburch@halport.lumeta.com> */
void MeanCrawler(int *distset, int id, int len) {
	sig *psig;
	int queue[MAXKEYS];
	int qhead, qtail;

	memset(queue,0,sizeof(int)*MAXKEYS);
	queue[0] = id;
	distset[id] = 0;
	qhead = 0;
	qtail = 1;

	while (qtail > qhead) {
		id = queue[qhead++];
		len = distset[id];
		psig = keys[id].to;
		while (psig) {
			if ((len+1) < distset[psig->id]) {
				distset[psig->id] = len+1;
				queue[qtail++] = psig->id;
			}
			psig = psig->next;
		}
	}
} 

float MeanDistance(int id, int *hops, int *hophigh, sig **farthest) {
	int dist[MAXKEYS];
	int i;
	int totaldist = 0;

	/* init to a large value here, so shortest distance will always be
	 * less */
	memset(dist,100,sizeof(int)*MAXKEYS);

	MeanCrawler(dist,id,0);

	for (i=0;i<numkeys;i++) {
		if (component[i] == max_component) {
			totaldist += dist[i];
			if (dist[i] < MAXHOPS) hops[dist[i]]++;
			if (dist[i] > *hophigh) {
				*hophigh = dist[i];
				DeleteKeyList(farthest);
			}
			if (dist[i] == *hophigh) {
				AddKeyToList(farthest, i);
			}
		}
	}

	if (*hophigh > MAXHOPS) *hophigh = MAXHOPS;

	return ((float)totaldist / max_size);
}

FILE *OpenFileById(unsigned int id) {
	char buf[255];
	char idchr[9];

	sprintf(idchr,"%08X",id);
	
	/* first the directory */
 	buf[0] = '\0';
	strcat(buf, outdir);
	if (outsubdirs) {
		strncat(buf,idchr,2);
		mkdir(buf,(mode_t)493);
		strcat(buf,"/");
	}
	strcat(buf,idchr);
	return fopen(buf,"w");
}

/* ################################################################# */
/* program block functions, not predeclared */

int OpenFiles() {
	char buf[255];

	fpin = fopen(infile, "r");
	if (!fpin) return 1;

	/* create output dir if necessary. this will just fail if it exists */
	mkdir(outdir, (mode_t)493);

	/* status file */
	buf[0] = '\0';
	strcat(buf, outdir);
	strcat(buf,"status.txt"); 
	fpstat = fopen(buf,"w");
	if (!fpstat) return 1;

	/* msd output file */
	buf[0] = '\0';
	strcat(buf, outdir);
	strcat(buf,"msd.txt"); 
	fpmsd = fopen(buf,"w");
	if (!fpmsd) return 1;

	/* othersets output file */
	buf[0] = '\0';
	strcat(buf, outdir);
	strcat(buf,"othersets.txt"); 
	fpsets = fopen(buf,"w");
	if (!fpsets) return 1;

	/* other output file */
	buf[0] = '\0';
	strcat(buf, outdir);
	strcat(buf,"other.txt"); 
	fpout = fopen(buf,"w");
	if (!fpout) return 1;

	return 0;
}

void ParseArgs(int argc, char **argv)
{
	int outdirlen;

	while (1) {
		int option = getopt(argc, argv, "hi:o:1");
		if (option == -1)
			break;
		switch (option) {
		case 'h':
			printf ("Usage: %s [-h1] [-i infile] [-o outdir]\n", argv[0]);
			exit (0);
			break;
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outdir = optarg;
			outdirlen = strlen(outdir);
			if (outdir[outdirlen - 1] != '/') {
				outdir = malloc(outdirlen + 2);
				memcpy(outdir, optarg, outdirlen);
				outdir[outdirlen] = '/';
				outdir[outdirlen + 1] = '\0';
			}
			break;
		case '1':
			outsubdirs = 0;
			break;
		}
	}

	if (optind < argc) {
		/* Assume it's infile */
		infile = argv[optind];
	}
}

int PrintKeyList(FILE *f, sig *s)
{
	int i = 0;
	while (s) {
		struct keydata *key = &keys[s->id];
		fprintf(f, "  %08X %08X\n", key->id1, key->id2);
		s = s->next;
		i++;
	}
	return i;
}

void ReadInput() {
	unsigned char buf[20];
	int currentkey = -1;
	
	fprintf(fpstat,"Importing pass 1 (keys)...\n");
	while (fread(buf,1,18,fpin) == 18) {
		if (buf[17] != '\n') continue;
		if (buf[0] == 'p') {
			AddKey(buf+1);
		}
	}
	fprintf(fpstat,"done.\n");
	fprintf(fpstat,"%d keys imported\n",numkeys);

	rewind(fpin);
	fprintf(fpstat,"Importing pass 2 (sigs)...\n");
	while (fread(buf,1,18,fpin) == 18) {
		if (buf[17] != '\n') continue;
		if (buf[0] == 'p') {
			currentkey = GetKeyById(buf+1);
			if (currentkey == -1) {
				fprintf(fpstat,"Error finding key in pass 2.\n");
				exit(EXIT_FAILURE);
			}
		}
		if (buf[0] == 's') {
				AddSig(GetKeyById(buf+1),currentkey);
				if ((numsigs%1000) == 0) {
					fprintf(fpstat,"%d sigs imported...\n",numsigs);
					fflush(fpstat);
				}
		} 
	}
	fprintf(fpstat,"done.\n");
	fprintf(fpstat,"%d sigs imported\n",numsigs);
}

/* This is intended for later use. As it takes a lot of time for the
 * signature imports, this will save time for future runs of the program
 * with the same data set. */

void SaveState() {
	/* not yet implemented. need to figure out how to best handle the
	 * linked lists of sigs first */
}

int dfsnum[MAXKEYS];
int lownum[MAXKEYS];
int removed[MAXKEYS];
int stack[MAXKEYS];
int stackindex;
int lastdfsnum;

void DFSVisit(int id) {
	sig *psig;

	dfsnum[id] = lownum[id] = ++lastdfsnum;
	stack[stackindex++] = id;

	for (psig = keys[id].to; psig; psig = psig->next) {
		int neighbor = psig->id;

		if (removed[neighbor])
			continue;

		if (!dfsnum[neighbor]) {
			DFSVisit (neighbor);

			if (lownum[neighbor] < lownum[id])
				lownum[id] = lownum[neighbor];
		} else if (dfsnum[neighbor] < lownum[id])
			lownum[id] = dfsnum[neighbor];
	}

	if (lownum[id] == dfsnum[id]) {
		int i, size = 0;

		do {
			struct keydata *key;
			i = stack[--stackindex];
			key = &keys[i];
			component[i] = id;
			removed[i] = 1;
			size++;
			fprintf(fpsets, "%08X %08X\n", key->id1, key->id2);
		} while (i != id);

		fprintf(fpsets,
			"*** %d keys in this strongly connected set\n\n", size);

		if (max_size < size) {
			max_size = size;
			max_component = id;
		}
	}
}

void TestConnectivity() {
	int i;

	for (i = 0; i < numkeys; i++)
		if (!dfsnum[i])
			DFSVisit (i);

	num_reachable = DFSMarkConnected (reachable, max_component);

	fprintf(fpstat,"reachable set is size %d\n", num_reachable);
	fprintf(fpstat,"strongly connected set is size %d\n", max_size);
}

/* ################################################################# */
/* report functions, sort of top level */

void IndivReport(FILE *fp,int key) {
	int totalsigsto, totalsigsfrom;

	/* head of report */
	fprintf(fp,"KeyID %08X %08X\n\n", keys[key].id1, keys[key].id2);

	fprintf(fp,"This individual key report was generated as part of the monthly keyanalyze\n");
	fprintf(fp,"report at http://dtype.org/keyanalyze/.\n\n");

	fprintf(fp,"Note: Key signature counts and lists are from a pruned list that only\n");
	fprintf(fp,"includes keys with signatures other than their own.\n\n");

	fprintf(fp,"Signatures to this key:\n");
	totalsigsto = PrintKeyList(fp, keys[key].to);
	fprintf(fp,"Total: %d signatures to this id from this set\n\n",totalsigsto);
		 
	fprintf(fp,"Signatures from this key:\n");
	totalsigsfrom = PrintKeyList(fp, keys[key].from);
	fprintf(fp,"Total: %d signatures from this id to this set\n\n",totalsigsfrom);
}

/* ################################################################# */
/* thread routine */

void *thread_slave(void *arg) {
	int 	i,j;
	float 	threadmean;
	sig	*distant_sigs = NULL;
	FILE	*fpindiv;

	int		hops[MAXHOPS]; /* array for hop histogram */
	int		hophigh; /* highest number of hops for this key */

	threadparam data = *(threadparam *)arg;

	for (i=0;i<numkeys;i++) {
		struct keydata *key = &keys[i];
		/* do this for all set2 now */
		if (reachable[i] && ((i%2)==data.threadnum)) {
			/* zero out hop histogram */
			memset(hops,0,sizeof(int)*MAXHOPS);
			hophigh = 0;

			threadmean = MeanDistance(i,hops,&hophigh,&distant_sigs);

			pthread_mutex_lock(&mean_l);
			meantotal += threadmean;
			fprintf(fpmsd,"%08X %08X %8.4f\n"
				,key->id1, key->id2, threadmean);
			fflush(fpmsd);
			pthread_mutex_unlock(&mean_l);

			/* individual report */
			fpindiv = OpenFileById(key->id2);
			IndivReport(fpindiv,i);
			fprintf(fpindiv, "This key is %sin the strong set.\n",
				component[i] == max_component ? "" : "not ");
			fprintf(fpindiv,"Mean distance to this key from strong set: %8.4f\n\n",threadmean);
			fprintf(fpindiv,"Breakout by hop count (only from strong set):\n");
			for (j=0;j<=hophigh;j++) {
				fprintf(fpindiv,"%2d hops: %5d\n",j,hops[j]);
		 	}
			if (distant_sigs) {
				fprintf(fpindiv,"\nFarthest keys (%d hops):\n", j-1);
				PrintKeyList(fpindiv, distant_sigs);
				DeleteKeyList(&distant_sigs);
			}
			fclose(fpindiv);
		} 
	}
	return NULL;
}

/* ################################################################# */
/* main() */

int main(int argc, char **argv)
{
	pthread_t 	*slave0,*slave1;
	threadparam arg0,arg1;
	void 	 	*retval;

	ParseArgs(argc, argv);
	if (OpenFiles()) {
		fprintf(stderr, "Error opening files.\n");
		exit(EXIT_FAILURE);
	}
	ReadInput();
	TestConnectivity();

	pthread_mutex_init(&mean_l,NULL);
	slave0 = (pthread_t *) calloc(1, sizeof(pthread_t));
	slave1 = (pthread_t *) calloc(1, sizeof(pthread_t));
	arg0.threadnum = 0;
	arg1.threadnum = 1;

	if (pthread_create(slave0,NULL,thread_slave,&arg0)) {
		fprintf(stderr,"Cannot create thread 0.");
	}
	if (pthread_create(slave1,NULL,thread_slave,&arg1)) {
		fprintf(stderr,"Cannot create thread 1.");
	}
	pthread_join(*slave0, &retval);
	pthread_join(*slave1, &retval);

	fprintf(fpout,"Average mean is %9.4f\n",meantotal/num_reachable);
	/* ReportMostSignatures(); */
	CloseFiles(); 
	return 0;
}
