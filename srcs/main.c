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
} ElfN_Ehdr
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

Elf64_Shdr	*get_section64(Elf64_Ehdr *hdr, uint16_t index)
{
	Elf64_Shdr *shdr;
	int i;

	shdr = (void *)hdr + hdr->e_shoff;
	for(i = 0; i < hdr->e_shnum; ++i)
	{
		if (i == index)
			return(shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (NULL);
}

void print_Ehdr(Elf64_Ehdr *hdr)
{
	int i;

	printf("Header:\n\te_ident: ");
	for (i = 0; i < EI_NIDENT; ++i) {
		printf("%02X ", hdr->e_ident[i]);
	}
	printf("\n\te_type: %hu (Object file type)", hdr->e_type);
	printf("\n\te_machine: %hu (Machine type)", hdr->e_machine);
	printf("\n\te_version: %u (Object file version)", hdr->e_version);
	printf("\n\te_entry: %lu (Entry point address)", hdr->e_entry);
	printf("\n\te_phoff: %lu (Program header offset)", hdr->e_phoff);
	printf("\n\te_shoff: %lu (Section header offset)", hdr->e_shoff);
	printf("\n\te_flags: %u (Processor specific flags)", hdr->e_flags);
	printf("\n\te_ehsize: %hu (Elf header size)", hdr->e_ehsize);
	printf("\n\te_phentsize: %hu (Size of program header entry)", hdr->e_phentsize);
	printf("\n\te_phnum: %hu (Number of program header Entries)", hdr->e_phnum);
	printf("\n\te_shentsize: %hu (Size of section header entry)", hdr->e_shentsize);
	printf("\n\te_shnum: %hu (Number of section header entries)", hdr->e_shnum);
	printf("\n\te_shstrndx: %hu (Section name string table index)\n", hdr->e_shstrndx);

}
void print_Phdr(Elf64_Phdr *phdr)
{
	printf("\n\tp_type: %u (Segment type)", phdr->p_type);
	printf("\n\tp_flags: %u (Segment flags)", phdr->p_flags);
	printf("\n\tp_offset: %lu (First byte of Segment in program)", phdr->p_offset);
	printf("\n\tp_vaddr: %lu (First byte of Segment in memory)", phdr->p_vaddr);
	printf("\n\tp_paddr: %lu (Physical address if relevant)", phdr->p_paddr);
	printf("\n\tp_filesz: %lu (file image size of segment)", phdr->p_filesz);
	printf("\n\tp_memsz: %lu (memory image size of segment)", phdr->p_memsz);
	printf("\n\tp_align: %lu (memory alignment)\n", phdr->p_align);
}

void print_Shdr(Elf64_Shdr *shdr, Elf64_Shdr *sstr)
{
	printf("\n\tsh_name: %s (Section name)", (void *)sstr + shdr->sh_name);
	printf("\n\tsh_type: %u (Section type)", shdr->sh_type);
	printf("\n\tsh_flags: %lu (Section attributes)", shdr->sh_flags);
	printf("\n\tsh_addr: %lu (Virtual address in memory)", shdr->sh_addr);
	printf("\n\tsh_offset: %lu (Offset in file)", shdr->sh_offset);
	printf("\n\tsh_size: %lu (Size of section)", shdr->sh_size);
	printf("\n\tsh_link: %u (Link to other section)", shdr->sh_link);
	printf("\n\tsh_info: %u (Miscellaneous info)", shdr->sh_info);
	printf("\n\tsf_addralign: %lu (Address alignment boundary)", shdr->sh_addralign);
	printf("\n\tsh_entsize: %lu (Size of entries, if section has table)\n", shdr->sh_entsize);
}

void				print_all(void *ptr)
{
	int		i;
	Elf64_Ehdr	*hdr;
	Elf64_Shdr	*shdr;
	Elf64_Shdr	*sstr;
	Elf64_Phdr	*phdr;

	hdr = ptr;
	print_Ehdr(hdr);
	shdr = (void *)ptr + hdr->e_shoff;
	sstr = (void *)ptr + get_section64(hdr, hdr->e_shstrndx)->sh_offset;
	for (i = 0; i < hdr->e_shnum; ++i)
	{
		print_Shdr(shdr, sstr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	phdr = (void *)ptr + hdr->e_phoff;
	for (i = 0; i < hdr->e_phnum; ++i)
	{
		print_Phdr(phdr);
		phdr = (void *)phdr + sizeof(Elf64_Phdr);
	}

}

Elf64_Phdr	*find_last_segment(void *ptr)
{
	Elf64_Ehdr *hdr;
	Elf64_Phdr *phdr;
	Elf64_Phdr *last_Phdr;
	int i;

	hdr = ptr;
	phdr = (void *)hdr + hdr->e_phoff;
	for (i = 0; i < hdr->e_phnum; ++i)
	{
		if (phdr->p_type == PT_LOAD)
			last_Phdr = phdr;
		phdr = (void *)phdr + sizeof(Elf64_Phdr);
	}
	return(last_Phdr);

}

void	woodywood_pack(void *ptr, struct stat statbuf)
{
	Elf64_Phdr *last_Phdr;
	Elf64_Ehdr *hdr;
	Elf64_Shdr	*shdr;
	Elf64_Shdr	*sstr;
	int i;
	hdr = ptr;
	(void)statbuf;
	// find last Segment
	last_Phdr = find_last_segment(ptr);
	//print_Phdr(last_Phdr);
	shdr = (void *)ptr + hdr->e_shoff;
	sstr = (void *)ptr + get_section64(hdr, hdr->e_shstrndx)->sh_offset;
	for (i = 0; i < hdr->e_shnum; ++i)
	{
		if ((unsigned long)((void*)ptr + last_Phdr->p_offset) == (unsigned long)((void *)ptr + shdr->sh_offset))
			printf("it's a match...");
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	// insert new Shdr
	// followed by code that decrypts and point to old e_entry
	// update Phdr- Segment
	// encrypt data

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

	//print_all(map);
	woodywood_pack(map, statbuf);

	// free memory
	if (munmap(map, statbuf.st_size))
	{
		perror("[!]");
		return (1);
	}
	close(fd);

	return (0);
}
