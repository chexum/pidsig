
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

void bail(const char *a0,const char *a1)
{
  if (a0) { write(2,a0,strlen(a0)); }
  if (a1) { write(2,a1,strlen(a1)); }
  write(2,"\n",sizeof("\n")-1);
  exit(1);
}

#define USAGE "pidsig [-p pidN].. [-d chroot] [-u user] cmd..."

/* pidsig -p pid1 -p pid2 -d chroot -u root fghack /usr/bin/nginx */

char *optu=NULL;
long int uval=0;
long int gval=0;
char *optd=NULL;
char *optp=NULL;
pid_t child;

int main(int argc, char *argv[])
{
  char *val,opt,*uend,buf[1];
  int status;
  struct passwd *upw;
  int fdpair[2];
  fd_set fdr;

  /* empty cmd?? */
  if (argc <= 1) { bail(USAGE,NULL); }
  argv++; argc--;

  /* parse options */
  while((argc > 0) && *argv && (argv[0][0] == '-')) {
    argc--;
    opt=argv[0][1];
    switch(opt) {
      case 'u':
      case 'd':
      case 'p':
        if (argv[0][2]) {
	  val=&argv[0][2];
	} else if (argc > 0) {
	  argc--; val=*++argv;
	} else {
	  bail("option needs arg: ",USAGE);
	}
	argv++;

	if ('u' == opt) { optu=val; }
	if ('d' == opt) { optd=val; }
	if ('p' == opt) { optp=val; }
	break;

      case '-':
        argv++;
        continue;

      default:
	bail("bad option, usage: ",USAGE);
	break;
    }
  }

  /* prepare for options */
  if (optd) {
    if (getuid()) {
      bail("only root can ","chroot");
    }
    if (chdir(optd)) {
      bail("bad chroot dir: ",optd);
    }
  }
  if (optu) {
    if (getuid()) {
      bail("only root can ","change users");
    }
    uval=strtol(optu,&uend,10);
    if (*uend!='\0') {
      upw=getpwnam(optu);
      if (!upw) {
        bail("bad user to change: ",optu);
      }
      uval=upw->pw_uid;
      gval=upw->pw_gid;
    }
  }

  /* fghack/startup delay */
  if (pipe(fdpair)) {
    bail("can't create ","pipe");
  }

  /* djb-chain */
  child=fork();
  if (child==-1) { bail("pidsig cannot fork",NULL); }
  if (child==0) {
    read(fdpair[0],buf,1);
    close(fdpair[0]);
    execvp(*argv,argv);
    bail("pidsig can't exec ",*argv);
  }

  /* execute options */
  if (optd) { chroot(optd); chdir("/"); }
  if (optu) { if(gval) setgid(gval); setuid(uval); }

  /* go */
  write(fdpair[1],"\n",1);
  close(fdpair[1]);

  /* select for fdpair[0] readability (eof, QUIT) */
  /* pass signals through */
  /* XXX */

  /* wait for any signal or exiting child */
  for(;;) {
    FD_ZERO(&fdr);
    FD_SET(fdpair[0],&fdr);
    if (select(fdpair[0]+1,&fdr,NULL,NULL,NULL)>0) break;
    waitpid(-1,&status,WNOHANG);
  }

  exit (0);
}
