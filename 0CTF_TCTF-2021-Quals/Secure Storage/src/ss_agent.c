#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/file.h>


#define PAGE_SIZE 4096

#define STORAGE_SLOT_COUNT (16)
#define STORAGE_SLOT_SIZE (16*PAGE_SIZE)

#define KEY_LEN 32

static char global_admin_key[KEY_LEN + 1];
static char *global_username;
static int global_user_registered = 0;


static int readlinen(char *buf, int n) {
	unsigned int i;
	for (i = 0; i < n; i++) {
		char c;
		read(0, &c, 1);
		if (c == '\n') {
			break;
		}
		buf[i] = c;
	}
	return i;
}

static int readint(void) {
	char buf[32] = {0};
	readlinen(buf, 32-1);
	return atoi(buf);
}

static inline int my_memcmp(void *buf1, void *buf2, unsigned int count) {
	if (count == 0) {
		return 0;
	}
	while (--count && *(unsigned char *)buf1 == *(unsigned char *)buf2) {
		buf1 = (unsigned char *)buf1 + 1;
		buf2 = (unsigned char *)buf2 + 1;
	}
	return (int)(char)( *((unsigned char *)buf1) - *((unsigned char *)buf2) );
}

static void *mmap_storage_slot(unsigned int slot_index) {
	void *result;
	int r;
	int fd = open("/dev/ss", O_RDWR);
	if (fd < 0) {
		return NULL;
	}
	r = ioctl(fd, 0, slot_index);
	if (r < 0) {
		close(fd);
		return NULL;
	}
	result = mmap(NULL, STORAGE_SLOT_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	r = close(fd);
	if (result == NULL || r < 0) {
		return NULL;
	}
	return result;
}

static int unmmap_storage_slot(void *mmap_address) {
	return munmap(mmap_address, STORAGE_SLOT_SIZE);
}

/* ========================================================================== */

static int check_valid_key(char *key) {    // 1 for valid, 0 for invalid
	size_t len = strlen(key);
	size_t i;
	if (len != KEY_LEN) {
		return 0;
	}
	for (i = 0; i < len; i++) {
		if (!( (('0'<=key[i])&&(key[i]<='9')) || (('A'<=key[i])&&(key[i]<='Z')) || (('a'<=key[i])&&(key[i]<='z')) )) {
		//if (!( (('0'<=key[i])&&(key[i]<='9')) )) {    // to make the brute force time shorter
			return 0;
		}
	}
	return 1;
}

static int write_a_message(unsigned int slot_index, void *message, unsigned long message_len, void *key) {
	int r;
	if (message_len >= STORAGE_SLOT_SIZE-sizeof(unsigned long)-KEY_LEN) {
		return -1;
	}
	void *slot_memory = mmap_storage_slot(slot_index);
	if (slot_memory == NULL) {
		return -1;
	}

	// slot: | message_len: 8 bytes | message: message_len bytes | key: KEY_LEN bytes |
	*(unsigned long *)slot_memory = message_len;
	memcpy((unsigned char *)slot_memory+sizeof(unsigned long), message, message_len);
	memcpy((unsigned char *)slot_memory+sizeof(unsigned long)+message_len, key, KEY_LEN);

	r = unmmap_storage_slot(slot_memory);
	if (r < 0) {
		return -1;
	}
	return 0;
}

void show_menu(void) {
	printf("1. register user\n");
	printf("2. store my data\n");
	printf("3. retrieve my data\n");
	printf("4. (admin only) kick out last registered user\n");
	printf("5. exit\n");
}

// menu 1. register user
void register_user(void) {
	printf("How long is your name ?\n");
	int namelen = readint();
	if (namelen <= 0 || namelen >= 10000) {
		printf("Error: name length error\n");
		return;
	}
	global_username = (char *)malloc(namelen);
	if (global_username == NULL) {
		printf("Error: unexpected\n");
		return;
	}
	printf("What is your name ?\n");
	readlinen(global_username, namelen);
	int r = write_a_message(0, global_username, namelen, global_admin_key);
	if (r < 0) {
		printf("Error: write to storage error\n");
		return;
	}
	global_user_registered = 1;
	
	printf("Hello ");
	write(1, global_username, namelen);
	printf("\n");
	printf("Successfully register\n");
}

// menu 2. store my data
void store_my_data(void) {
	char buf[KEY_LEN + 1] = {0};
	static char bigbuf[STORAGE_SLOT_SIZE];
	if (!global_user_registered) {
		printf("Error: user have not registered\n");
		return;
	}

	printf("Which slot ?\n");
	int slot_index = readint();
	if (!((1 <= slot_index) && (slot_index < STORAGE_SLOT_COUNT))) {
		printf("Error: slot index out of range\n");
		return;
	}

	printf("How long is your data ?\n");
	int data_len = readint();
	if ((data_len <= 0) || (data_len >= STORAGE_SLOT_SIZE-sizeof(unsigned long)-KEY_LEN)) {
		printf("Error: invalid data length\n");
		return;
	}

	printf("Now input your data:\n");
	readlinen(bigbuf, data_len-1);
	bigbuf[data_len-1] = '\0';
	
	printf("Input your key (remember it):\n");
	readlinen(buf, KEY_LEN + 1);
	if (strlen(buf) != KEY_LEN) {
                printf("Error: key length error\n");
                return;
	}
        if (!check_valid_key(buf)) {
                printf("Error: key contains illegal char\n");
                return;
        }

	int r = write_a_message(slot_index, bigbuf, data_len, buf);
	if (r < 0) {
		printf("Error: write to storage error\n");
		return;
	}

	printf("Successfully store\n");
}

// menu 3. retrieve my data
void retrieve_my_data(void) {
	char buf[KEY_LEN + 1] = {0};
	if (!global_user_registered) {
		printf("Error: user have not registered\n");
		return;
	}

	printf("Which slot ?\n");
	int slot_index = readint();
	if (!((1 <= slot_index) && (slot_index < STORAGE_SLOT_COUNT))) {
		printf("Error: slot index out of range\n");
		return;
	}

	printf("Input your key:\n");
	readlinen(buf, KEY_LEN + 1);
	if (strlen(buf) != KEY_LEN) {
                printf("Error: key length error\n");
                return;
	}
        if (!check_valid_key(buf)) {
                printf("Error: key contains illegal char\n");
                return;
        }

	void *slot_memory = mmap_storage_slot(slot_index);
	if (slot_memory == NULL) {
		printf("Error: cannot open storage\n");
		return;
	}

	unsigned long message_len = *((unsigned long *)slot_memory);
	printf("Checking...\n");
	if (my_memcmp((unsigned char *)slot_memory+sizeof(unsigned long)+message_len, buf, KEY_LEN) != 0) {
		printf("Error: key error\n");
		unmmap_storage_slot(slot_memory);
		return;
	}
	printf("Pass check\n");
	
	printf("Your data is ");
	write(1, (char *)slot_memory+sizeof(unsigned long), message_len);
	printf("\n");
	
	unmmap_storage_slot(slot_memory);

	printf("Finish\n");
}

// menu 4. (admin only) kick out last registered user
void kick_out_last_registered_user(void) {
	char buf[KEY_LEN + 1] = {0};

	printf("Input admin key:\n");
	readlinen(buf, KEY_LEN + 1);
	if (strlen(buf) != KEY_LEN) {
		printf("Error: key length error\n");
		return;
	}
	if (!check_valid_key(buf)) {
		printf("Error: key contains illegal char\n");
		return;
	}

	void *slot_memory = mmap_storage_slot(0);
	if (slot_memory == NULL) {
		printf("Error: cannot open storage\n");
		return;
	}

	unsigned long message_len = *((unsigned long *)slot_memory);
	printf("Checking...\n");
	if (my_memcmp((unsigned char *)slot_memory+sizeof(unsigned long)+message_len, buf, KEY_LEN) != 0) {
		printf("Error: key error\n");
		unmmap_storage_slot(slot_memory);
		return;
	}
	printf("Pass check\n");

	printf("Last registered user is ");
	write(1, (char *)slot_memory+sizeof(unsigned long), message_len);
	printf("\n");

	// XXX vuln here: forget the braces, so if key check passed, here can double free
	if (global_user_registered) // {
		global_user_registered = 0;
		free(global_username);
	// }
	
	unmmap_storage_slot(slot_memory);

	printf("User kicked out\n");
}

int main(void) {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	
	// avoid run multiple processes of this program
	//int lockfd = open("/challenge/ss_agent.lock", O_RDWR);
	int lockfd = open("/challenge/ss_agent", O_RDONLY);
	if (lockfd < 0) {
		printf("Error: open lock file error\n");
		return 0;
	}
	//int r = lockf(lockfd, F_TLOCK, 0);
	int r = flock(lockfd, LOCK_EX | LOCK_NB);
	if (r < 0) {
		printf("Error: another ss_agent is running\n");
		return 0;
	}
	
	int fd = open("/challenge/admin_key.txt", O_RDONLY);
	if (fd < 0) {
		printf("Error: open admin key file error\n");
		goto end;
	}
	read(fd, global_admin_key, KEY_LEN);
	close(fd);
	
	printf("This is user mode agent program for Secure Storage !\n");
	printf("What do you want to do ?\n");
	while (1) {
		show_menu();
		printf("Input your choice:\n");
		int choose = readint();
		switch (choose) {
			case 1:
				register_user();
				break;
			case 2:
				store_my_data();
				break;
			case 3:
				retrieve_my_data();
				break;
			case 4:
				kick_out_last_registered_user();
				break;
			case 5:
				goto end;
				break;
			default:
				printf("Error: invalid choose\n");
		}
		printf("\n");
	}
end:
	//lockf(lockfd, F_ULOCK, 0);
	flock(lockfd, LOCK_UN);
	close(lockfd);
	return 0;
}

