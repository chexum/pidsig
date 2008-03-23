
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void bail(const char *msg)
{
  write(2,msg,strlen(msg));
  write(2,"\n",sizeof("\n")-1);
  exit(1);
}

#define USAGE "pidsig [-p pidN].. [-d chroot] [-u user] cmd..."

/* pidsig -p pid1 -p pid2 -d chroot -u root fghack /usr/bin/nginx */

int main(int argc, char *argv[])
{
  char *val,opt;

  /* empty cmd?? */
  if (argc <= 1) { bail(USAGE); }
  argv++; argc--;

  while((argc > 0) && *argv && (argv[0][0] == '-')) {
    argc--;
    opt=argv[0][1];
    switch(opt) {
      case 'p':
      case 'd':
      case 'u':
        if (argv[0][2]) {
	  val=&argv[0][2];
	} else if (argc > 0) {
	  argc--; val=*++argv;
	} else {
	  bail(USAGE);
	}
	argv++;
	break;

      case '-':
        argv++;
        continue;

      default:
	bail(USAGE);
	break;
    }
  }

  execvp(*argv,argv);

  exit (0);
}
