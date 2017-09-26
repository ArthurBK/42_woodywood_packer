/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/11 11:45:13 by fventuri          #+#    #+#             */
/*   Updated: 2017/05/12 15:18:52 by abonneca         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <woody.h>

/*
#define EI_NIDENT 16

typedef struct {
	unsigned char e_ident[EI_NIDENT];
	uint16_t      e_type;
	uint16_t      e_machine;
	uint32_t      e_version;
	ElfN_Addr     e_entry;
	ElfN_Off      e_phoff;
	ElfN_Off      e_shoff;
	uint32_t      e_flags;
	uint16_t      e_ehsize;
	uint16_t      e_phentsize;
	uint16_t      e_phnum;
	uint16_t      e_shentsize;
	uint16_t      e_shnum;
	uint16_t      e_shstrndx;
} ElfN_Ehdr;
*/

/*
   struct stat {
   dev_t     st_dev;         * ID of device containing file *
   ino_t     st_ino;         * Inode number *
   mode_t    st_mode;        * File type and mode *
   nlink_t   st_nlink;       * Number of hard links *
   uid_t     st_uid;         * User ID of owner *
   gid_t     st_gid;         * Group ID of owner *
   dev_t     st_rdev;        * Device ID (if special file) *
   off_t     st_size;        * Total size, in bytes *
   blksize_t st_blksize;     * Block size for filesystem I/O *
   blkcnt_t  st_blocks;      * Number of 512B blocks allocated *

   struct timespec st_atim;  * Time of last access *
   struct timespec st_mtim;  * Time of last modification *
   struct timespec st_ctim;  * Time of last status change *
#define st_atime st_atim.tv_sec      * Backward compatibility *
#define st_mtime st_mtim.tv_sec
#define st_ctime st_ctim.tv_sec
};
*/

void				print_all(void *ptr)
{
	int				i;

	//	hdr = ptr;
	printf("Header:\n\te_ident: ");
	for (i = 0; i < EI_NIDENT; ++i) {
		printf("%02X ", ((Elf64_Ehdr *)ptr)->e_ident[i]);
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

	print_all(map);
	// Begin code injection
	//pack(m, &buf);

	// free memory
	if (munmap(map, statbuf.st_size))
	{
		perror("[!]");
		return (1);
	}
	close(fd);

	return (0);
}
