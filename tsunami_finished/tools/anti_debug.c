#define _GNU_SOURCE

#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char **args)
{
	int fd = 0;
    int ret = 0;
    #ifdef ELF_32
    Elf32_Ehdr *elf_header;
    #else
    Elf64_Ehdr *elf_header;
    #endif

    if(argc < 2)
    {
    	#ifdef DEBUG
        printf("Usage: %s [input]\n", args[0]);
        #endif
        return 1;
    }

    if((fd = open(args[1], O_RDWR)) == -1)
    {
    	return 1;
    }

    #ifdef DEBUG
    printf("Opened target file %s\n", args[1]);
    #endif

    #ifdef ELF_32
    elf_header = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
    #else
    elf_header = (Elf64_Ehdr *)malloc(sizeof(Elf64_Ehdr));
    #endif

    #ifdef ELF_32
    ret = read(fd, elf_header, sizeof(Elf32_Ehdr));
    #else
    ret = read(fd, elf_header, sizeof(Elf64_Ehdr));
    #endif
    if(ret < 1)
    {
    	free(elf_header);
    	close(fd);
    	return 1;
    }

    #ifdef DEBUG
    printf("Read %d bytes!\n", ret);
    #endif

    elf_header->e_shoff = 0;
    elf_header->e_shentsize = 0;
    elf_header->e_shnum = 0;
    elf_header->e_shstrndx = 0;

   	lseek(fd, 0, SEEK_SET);

    #ifdef ELF_32
    ret = write(fd, elf_header, sizeof(Elf32_Ehdr));
    #else
    ret = write(fd, elf_header, sizeof(Elf64_Ehdr));
    #endif
    if(ret < 1)
    {
    	free(elf_header);
    	close(fd);
    	return 1;
    }

    #ifdef DEBUG
    printf("Wrote %d bytes!\n", ret);
    #endif

    free(elf_header);
    close(fd);
    return 0;
}
