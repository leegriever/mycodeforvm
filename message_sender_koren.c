#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "message_slot.h"

#define SUCCESS (0)
#define SET_STATUS(cond, message){							\
	if((cond)){												\
		perror((message));									\
		exit(1);											\
	}														\
}															\

int main(int argc, char ** argv){
	int fd = 0;
	unsigned long channel = 0;

	SET_STATUS(4 != argc, "invalid args num");
	fd = open(argv[1], O_WRONLY);
	SET_STATUS(0 > fd, "couldn't open file");
	channel = (unsigned long) atoi(argv[2]);
	SET_STATUS(SUCCESS != ioctl(fd, MSG_SLOT_CHANNEL, channel), "couldn't control the io");
	SET_STATUS(strlen(argv[3]) != write(fd, argv[3], strlen(argv[3])), "couldn't print to user");
	close(fd);
	return 0;

}