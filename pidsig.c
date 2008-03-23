
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/wait.h>

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
char *optd=NULL;
char *optp=NULL;

int main(int argc, char *argv[])
{
  pid_t child;
  int status;
  char *val,opt;

  /* empty cmd?? */
  if (argc <= 1) { bail(USAGE,NULL); }
  argv++; argc--;

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

  if (optd) {
    if (getuid()) {
      bail("only root can chroot",NULL);
    }
    if (chdir(optd)) {
      bail("chroot dir",NULL);
    }
  }

  child=fork();
  if (child==-1) { bail("pidsig cannot fork",NULL); }
  if (child==0) {
    execvp(*argv,argv);
    bail("pidsig can't exec",NULL);
  }

  if (optd) { chroot(optd); chdir("/"); }
  if (optu) { }
  if (optp) { }

  while (waitpid(-1,&status,0)) {
    if (WIFEXITED(status)) break;
  }

  exit (0);
}
