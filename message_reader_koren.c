#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define SUCCESS (0)
#include "message_slot_koren.h"

#define SET_STATUS(cond, message){							\
	if((cond)){												\
		perror((message));									\
		exit(1);											\
	}														\
}															\

int main(int argc, char ** argv){
	int fd = 0;
	int ret_val = 0;
	unsigned long channel = 0;
	char buf[MAX_BUF_SIZE];

	SET_STATUS(3 != argc, "invalid args num");
	fd = open(argv[1], O_RDONLY);
	SET_STATUS(0 > fd, "couldn't open file");
	channel = (unsigned long) atoi(argv[2]);
	SET_STATUS(SUCCESS != ioctl(fd, MSG_SLOT_CHANNEL, channel), "couldn't control the io");
	ret_val = read(fd, buf, MAX_BUF_SIZE);
	SET_STATUS(0 >= ret_val, "couldn't read");
	SET_STATUS(ret_val != write(STDOUT_FILENO, buf, ret_val), "couldn't print to user");
	close(fd);
	return 0;

}