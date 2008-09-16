
/* Copyright (C) 2008, Farkas Janos
 * See LICENSE.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <fcntl.h>
#include <signal.h>

void bail(const char *a0,const char *a1)
{
  if (a0) { write(2,a0,strlen(a0)); }
  if (a1) { write(2,a1,strlen(a1)); }
  write(2,"\n",sizeof("\n")-1);
  exit(1);
}

#define USAGE "pidsig [-p pidN].. [-d chroot] [-u user] [--] cmd..."

/* pidsig -p pid1 -p pid2 -d chroot -u root fghack /usr/bin/nginx */

char *optu=NULL;
long int uval=0;
long int gval=0;
char *optd=NULL;
#define OPTPMAX 16
int optpnum=0;
char *optp[OPTPMAX];
pid_t child;
int pipefd=-1;

int killpidfile(char *pidfile,int sig)
{
  int fd;
  char buf[20],*uend;
  pid_t pid;
  size_t sz;

  if((fd=open(pidfile,O_RDONLY,0))>0) {
    sz=read(fd,buf,sizeof(buf)-1);
    close(fd);
    if (sz > 0) {
      buf[sz]=0;
      pid=strtol(buf,&uend,10);
      if (uend != buf && (*uend == '\0' || *uend == '\n' || *uend == '\r' || *uend == ' ' || *uend == '\t') && pid > 1) {
        return kill (pid,sig);
      }
    }
  }
  return -1;
}

void pidsighandler(int sig)
{
  int childstatus;
  int killed=0;
  int i;

  if (SIGCHLD == sig) {
    /* only care about our single descendant */
    if (0 != child) {
      if(waitpid(-1,&childstatus,WNOHANG) == child) {
        if (WIFEXITED(childstatus) || WIFSIGNALED(childstatus)) { child=0; }
      }
    }
    return;
  }

  if (child && kill(child,sig)==0) { killed++; }
  for(i=0; i<optpnum; i++) {
    if (killpidfile(optp[i],sig)==0) { killed++; }
  }
  if (!killed) { exit(1); }
}

void setsighandler(void (*myhandler)(int))
{
  struct sigaction sa;
  memset(&sa,0,sizeof(sa));
  sa.sa_handler=myhandler;
  /* common signals */
  sigaction(SIGINT,&sa,NULL);
  sigaction(SIGHUP,&sa,NULL);
  sigaction(SIGTERM,&sa,NULL);

  /* less common ones */
  sigaction(SIGQUIT,&sa,NULL);
  sigaction(SIGUSR1,&sa,NULL);
  sigaction(SIGUSR2,&sa,NULL);
  /* qmail-send */
  sigaction(SIGALRM,&sa,NULL);
  /* nginx */
  sigaction(SIGWINCH,&sa,NULL);
  /* only to handle our single one */
  sigaction(SIGCHLD,&sa,NULL);
}

int main(int argc, char *argv[])
{
  char *val,opt,*uend,buf[1];
  struct passwd *upw;
  int fdpair[2];
  char **optparr=optp;

  /* empty cmd?? */
  if (argc <= 1) { bail("pidsig: usage:\n",USAGE); }
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
	  bail("pidsig: option needs arg: ",argv[0]); val=0;
	}
	argv++;

	if ('u' == opt) {
	  if (optu) { bail("pidsig: option can be specified only once: ","-u"); }
	  optu=val;
	}
	if ('d' == opt) {
	  if (optd) { bail("pidsig: option can be specified only once: ","-d"); }
	  optd=val;
	}
	if ('p' == opt) {
	  if (optpnum >= OPTPMAX) { bail("pidsig: too many -p options, last: ",val); }
	  *optparr++=val;
	  optpnum++;
	}
	break;

      case '-':
        argv++;
        continue;

      default:
	bail("pidsig: bad option, usage:\n",USAGE);
	break;
    }
  }

  /* prepare for options */
  if (optd) {
    /* XXX with -u given, root may not be able to change to the directory (NFS) */
    if (chdir(optd)) {
      bail("pidsig: can't change to directory: ",optd);
    }
  }
  if (optu) {
    uval=strtol(optu,&uend,10);
    if (*uend!='\0' || uend == optu) {
      upw=getpwnam(optu);
      if (!upw) {
        bail("pidsig: unknown uid: ",optu);
      }
      uval=upw->pw_uid;
      gval=upw->pw_gid;
    }
  }
  if (*argv == NULL) {
    bail("pidsig: no command to ","execv");
  }
  if (optu || optd) {
    if (getuid()) {
      if (optu && optd) {
        bail("pidsig: only root can ","chroot or change uid");
      }
      if (optu) {
        bail("pidsig: only root can ","change uid");
      }
      if (optd) {
        bail("pidsig: only root can ","chroot");
      }
    }
  }

  /* fghack/startup delay */
  if (pipe(fdpair)) {
    bail("pidsig: can't create ","pipe");
  }

  /* djb-chain */
  child=fork();
  if (child==-1) { bail("pidsig: can't ","fork"); }
  if (child==0) {
    read(fdpair[0],buf,1);
    close(fdpair[0]);
    execvp(*argv,argv);
    bail("pidsig: can't exec ",*argv);
  }

  /* execute options */
  if (optd) { chroot(optd); chdir("/"); }
  if (optu) { if(gval) setgid(gval); setuid(uval); }
  setsighandler(pidsighandler);

  /* go */
  write(fdpair[1],"\n",1);
  close(fdpair[1]);
  pipefd=fdpair[0];

  /* wait for any signal or exiting child */
  for(;;) {
    fd_set fdr;
    int res;

    FD_ZERO(&fdr);
    if (pipefd>=0) FD_SET(pipefd,&fdr);
    /* if the pipe hack is closed and out of children, we'll leave */
    res=select(pipefd+1,&fdr,NULL,NULL,NULL);
    if (res > 0) {
      if (pipefd>=0) {
        close(pipefd); pipefd=-1;
      }
    }
    if (-1 == pipefd && 0 == child) break;
  }

  exit (0);
}
