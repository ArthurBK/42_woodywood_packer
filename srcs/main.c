
#include <woody.h>

void	generate_key(void *buf)
{	
	int i;
	unsigned char *buf2;

	buf2 = buf;
	syscall(SYS_getrandom, buf2, 16, 0);
	for (i = 0; i < 16; ++i)
	{
		buf2[i] = buf2[i] % 75 + 48;
		if (buf2[i] >= 58 && buf2[i] <= 64)
			buf2[i] -= 8;
		if (buf2[i] >= 91 && buf2[i] <= 96)
			buf2[i] -= 6;
	}

}

int					main(int ac, char **av)
{
	int				fd;
	void			*map;
	struct stat		statbuf;

	if (ac != 2)
	{
		printf("usage: %s [elf64-binary]\n", av[0]);
		return (1);
	}

	if ((fd = open(av[1], O_RDONLY)) < 0)
	{
		perror("[!]");
		return (1);
	}

	if (fstat(fd, &statbuf) < 0)
	{
		perror("[!]");
		return (1);
	}

	if ((map = mmap(0, statbuf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0))
			== MAP_FAILED)
	{
		perror("[!]");
		return (1);
	}
	// check ELF64

	// print_all(map);
	if (woodywood_pack(map, statbuf))
	{
		perror("[!]");
		return (1);
	}
	// free memory
	if (munmap(map, statbuf.st_size))
	{
		perror("[!]");
		return (1);
	}
	close(fd);

	return (0);
}
