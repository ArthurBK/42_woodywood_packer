#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#define _GNU_SOURCE

void *encrypt(void *data, size_t size, void *key);
void *decrypt(void *data, size_t size, void *key);

int main(void)
{

/*
	unsigned int *buf;
	int i;
	syscall(318, buf, 16);
	for (i = 0; i < 16; ++i)
	{
		buf[i] = buf[i] % 75 + 48;
		if (buf[i] >= 58 && buf[i] <= 64)
			buf[i] -= 8;
		if (buf[i] >= 91 && buf[i] <= 96)
			buf[i] -= 6;
		printf("%c\n", buf[i]);

	}
		
 */	

	void *tmp;
	void *res;
	int i;
	char text[]= "Two One Nine Two three";
	char key[] = "Thats my Kung Fu";
	tmp = encrypt(text, 22, key);
	for(i = 0; i < 22; ++i)
		printf("%02X ", ((unsigned char*)tmp)[i]);
	printf("\n");
	printf("%s\n", (char *)tmp);
	res = decrypt(tmp, 22, key);
	printf("%s\n", (char *)res);
	
	return (0);
}


