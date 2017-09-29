#include <stdlib.h>
#include <stdio.h>

void *encrypt(void *data, size_t size, void *key);


int main(void)
{
	void *res;
	char test[]= "hey you what up ";
	res = encrypt(test, 16, "BBBBBBBBBBBBBBBB");
	printf("%s\n", (char *)res);
	return (0);
}

