# include <stdio.h>
# include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
    struct stat file_info;
    unsigned int file_size;
    unsigned int blocks;

    if(2 > argc)
    {
        fprintf(stderr, "usage: %s file.uf2\n", argv[0]);
        return 1;
    }

    if(stat(argv[1], &file_info) != 0)
    {
        fprintf(stderr, "can not get file information for %s\n", argv[1]);
        return 2;
    }
    file_size = file_info.st_size;
    printf("file size %d bytes\n", file_size);
    blocks = file_size / 512;
    if(blocks * 512 != file_size)
    {
        fprintf(stderr, "invalid file size  of %d bytes\n", file_size);
        return 3;
    }
    printf("file has %d blocks\n", blocks);


    return 0;
}
