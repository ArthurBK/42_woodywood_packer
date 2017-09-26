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

Elf64_Shdr			*get_section_64(Elf64_Ehdr *hdr, Elf64_Half index)
{
	Elf64_Shdr		*shdr;

	shdr = (void *)hdr + hdr->e_shoff;
	for (int i = 0; i < hdr->e_shnum; i++)
	{
		if (i == index)
			return (shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (NULL);
}

void				print_all(void *ptr)
{
	Elf64_Ehdr		*hdr;
	Elf64_Shdr		*shdr;
	Elf64_Shdr		*sh_strtable;
	char			*strtable;
	int				i;

	hdr = ptr;
	printf("Header:\n\te_ident: ");
	for (i = 0; i < EI_NIDENT; ++i) {
		printf("%02X ", hdr->e_ident[i]);
	}
	printf("\n\te_type: %hu (%hX)", hdr->e_type, hdr->e_type);
	printf("\n\te_machine: %hu (%hX)", hdr->e_machine, hdr->e_machine);
	printf("\n\te_version: %u (%X)", hdr->e_version, hdr->e_version);
	printf("\n\te_entry: %lu (%lX)", hdr->e_entry, hdr->e_entry);
	printf("\n\te_phoff: %lu (%lX)", hdr->e_phoff, hdr->e_phoff);
	printf("\n\te_shoff: %lu (%lX)", hdr->e_shoff, hdr->e_shoff);
	printf("\n\te_flags: %u (%X)", hdr->e_flags, hdr->e_flags);
	printf("\n\te_ehsize: %hu (%hX)", hdr->e_ehsize, hdr->e_ehsize);
	printf("\n\te_phentsize: %hu (%hX)", hdr->e_phentsize, hdr->e_phentsize);
	printf("\n\te_phnum: %hu (%hX)", hdr->e_phnum, hdr->e_phnum);
	printf("\n\te_shentsize: %hu (%hX)", hdr->e_shentsize, hdr->e_shentsize);
	printf("\n\te_shnum: %hu (%hX)", hdr->e_shnum, hdr->e_shnum);
	printf("\n\te_shstrndx: %hu (%hX)\n", hdr->e_shstrndx, hdr->e_shstrndx);

	shdr = (void *)hdr + hdr->e_shoff;
	// get shstrtable section
	sh_strtable = get_section_64(hdr, hdr->e_shstrndx);
	strtable = (void *)hdr + sh_strtable->sh_offset;
	printf("Sections:\n");
	for (int i = 0; i < hdr->e_shnum; i++)
	{
		printf("\n\n\t%s\n", strtable + shdr->sh_name);

		printf("sh_name: %u\n", shdr->sh_name);
		printf("sh_type: %u\n", shdr->sh_type);
		printf("sh_flags: %lu\n", shdr->sh_flags);
		printf("sh_addr: %#lx\n", shdr->sh_addr);
		printf("sh_offset: %lu\n", shdr->sh_offset);
		printf("sh_size: %lu\n", shdr->sh_size);
		printf("sh_link: %u\n", shdr->sh_link);
		printf("sh_info: %u\n", shdr->sh_info);
		printf("sh_addralign: %lu\n", shdr->sh_addralign);
		printf("sh_entsize: %lu\n", shdr->sh_entsize);

			shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
}

Elf64_Shdr				*get_section_bytype_64(Elf64_Ehdr *hdr, Elf64_Word type)
{
	Elf64_Shdr			*shdr;

	shdr = (void *)hdr + hdr->e_shoff;
	for (int i = 0; i < hdr->e_shnum; i++)
	{
		if (shdr->sh_type == type)
			return (shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (shdr);
}

void					pack(void *m, struct stat *buf)
{
	Elf64_Ehdr			*hdr;
	Elf64_Shdr			*shdr;
	void				*packed;
	size_t				packed_size;

	packed_size = buf->st_size + 4096;
	if (!(packed = (void *)malloc(packed_size)))
		return ;

	ft_bzero(packed, packed_size);
	// find bss section
	hdr = m;
	/* shdr = (void *)hdr + hdr->e_shoff;*/
	/* for (int i = 0; i < hdr->e_shnum - 1; i++)*/
	/* {*/
	/*     shdr = (void *)shdr + sizeof(Elf64_Shdr);*/
	/* }*/

	if (!(shdr = get_section_bytype_64(hdr, SHT_NOBITS)))
	{
		printf("[!] bss not found\n");
		return ;
	}
	// copy until end of bss section
	/* size_t to_copy = shdr->sh_offset + shdr->sh_size;*/
	ft_memcpy(packed, m, buf->st_size);
	// inject code
	//
	//
	// append rest
	/* ft_memcpy(packed + to_copy + 4096, m + to_copy, buf->st_size - to_copy);*/
	// change header entry point
	// change file size
	hdr = packed;
	hdr->e_ehsize += 4096;
	hdr->e_entry = 9296;
	// change nsects

	printf("[+] generating packed file\n");
	int fd;

	if ((fd = open("woody", O_RDWR | O_CREAT, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH )) < 0)
	{
		perror("[!]");
		return ;
	}
	write(fd, packed, packed_size);
	close(fd);
	free(packed);
}

int					main(int ac, char **av)
{
	int				fd;
	void			*m;
	unsigned char	*p;
	struct stat		buf;

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

	if (fstat(fd, &buf) < 0)
	{
		perror("[!]");
		return (1);
	}

	if ((m = mmap(0, buf.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0))
			== MAP_FAILED)
	{
		perror("[!]");
		return (1);
	}

	// check ELF64
	p = m;
	if (ft_memcmp(ELFMAG, m, SELFMAG) && p[EI_CLASS] != ELFCLASS64)
	{
		printf("[!] Provided binary file isn't an ELF64\n");
		return (1);
	}

	print_all(m);
	// Begin code injection
	//pack(m, &buf);

	// free memory
	if (munmap(m, buf.st_size))
	{
		perror("[!]");
		return (1);
	}
	close(fd);

	return (0);
}
