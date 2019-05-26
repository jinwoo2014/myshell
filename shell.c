#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_LEN_LINE    30
#define LEN_HOSTNAME    30
#define BUFSZ           100

// ls함수 선언
int ls(void);

int main(void)
{
    char command[MAX_LEN_LINE];
    char *args[] = {command, NULL};
	 
	 char *getcwd(char *buf, size_t size);
	 char *getwd(char *buf);
	 char *get_current_dir_name(void);

	 int ret, status;
    pid_t pid, cpid;
    
	 // gethostusername
	 char hostname[LEN_HOSTNAME + 1];
	 memset(hostname, 0x00, sizeof(hostname));
	 gethostname(hostname, LEN_HOSTNAME);

    while (true) {
        char *s;
        int len;
        char *p;
		  char *commandArr[MAX_LEN_LINE] = {NULL};

		  // username@hostname
        printf("%s@%s $ ", getpwuid(getuid()) -> pw_name, hostname);

		  s = fgets(command, MAX_LEN_LINE, stdin);
       
		  if (s == NULL) {
			  fprintf(stderr, "fgets failed\n");
			  exit(1);
        }

			
		  // strtok를 이용해 프로그램 차례대로 실행
		  int i = 0;
		  p = strtok(s, ";");
		  while (p != NULL){
			  commandArr[i] = p;
			  i++;
			  p = strtok(NULL, " ;");
		  }
			  

		  for (int j=0; j<i; j++){
			  s = commandArr[j];
			  strcpy(command, s);
			  len = strlen(command);
			  if (command[len - 1] == '\n') {
				  command[len - 1] = '\0'; 
			  }
			 
			  printf("%d\n", len);
			  printf("[%s]\n", command);
				
			  
			  // exit
			  if(!strcmp(command, "exit")){
				  exit(0);
			  }

			  // pwd
			  char buf[BUFSZ];
			  if(!strcmp(command, "pwd")){
				  getcwd(buf, BUFSZ);
				  printf("%s\n", buf);
			  }

			  // ls
			  if(!strcmp(command, "ls")){
				  ls();
			  }
			  

			  pid = fork();
			  if (pid < 0) {
				  fprintf(stderr, "fork failed\n");
				  exit(1);
			  } 
			  if (pid != 0) {  /* parent */
				  cpid = waitpid(pid, &status, 0);
				  if (cpid != pid) {
					  fprintf(stderr, "waitpid failed\n");        
				  }
				  printf("Child process terminated\n");
				  if (WIFEXITED(status)) {
					  printf("Exit status is %d\n", WEXITSTATUS(status)); 
				  }
			  }
			  else {  /* child */
				  ret = execve(args[0], args, NULL);
				  if (ret < 0) {
					  fprintf(stderr, "execve failed\n");   
					  return 1;
				  }
			  }
		  }
	 }
	 return 0;
}

// ls함수 구현
int ls(void){
	char *cwd = (char *)malloc(sizeof(char)*1024);
	DIR *dir = NULL;
	struct dirent *entry = NULL;
	getcwd(cwd, 1024);
	
	if((dir = opendir(cwd)) == NULL){
	printf("current directory error\n");
	exit(1);
	}
	while((entry = readdir(dir)) != NULL){
		printf("%s\n", entry -> d_name);
	}
	free(cwd);
	closedir(dir);
	return 0;
}
