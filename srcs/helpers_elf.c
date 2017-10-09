#include <woody.h>

Elf64_Phdr	*find_last_segment(void *ptr)
{
	Elf64_Ehdr *hdr;
	Elf64_Phdr *phdr;
	Elf64_Phdr *last_Phdr;
	int i;

	hdr = ptr;
	last_Phdr = NULL;
	phdr = (void *)hdr + hdr->e_phoff;
	for (i = 0; i < hdr->e_phnum; ++i)
	{
		if (phdr->p_type == PT_LOAD)
		{
			last_Phdr = phdr;
			last_Phdr->p_flags = PF_X | PF_W | PF_R;
		}
		phdr = (void *)phdr + sizeof(Elf64_Phdr);
	}
	return(last_Phdr);
}


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


Elf64_Shdr	*get_section64_by_type(Elf64_Ehdr *hdr, uint32_t type)
{
	Elf64_Shdr *shdr;
	int i;

	shdr = (void *)hdr + hdr->e_shoff;
	for(i = 0; i < hdr->e_shnum; ++i)
	{
		if (shdr->sh_type == type)
			return(shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (NULL);
}


Elf64_Shdr	*get_section64_with_e(Elf64_Ehdr *hdr, Elf64_Addr entry)
{
	Elf64_Shdr *shdr;
	int i;

	shdr = (void *)hdr + hdr->e_shoff;
	for(i = 0; i < hdr->e_shnum; ++i)
	{
		if (entry >= shdr->sh_addr && entry < shdr->sh_addr + shdr->sh_size)
			return(shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (NULL);
}


Elf64_Shdr	*get_sym_strtab(Elf64_Ehdr *hdr)
{
	Elf64_Shdr *shdr;
	int i;

	shdr = (void *)hdr + hdr->e_shoff;
	for(i = 0; i < hdr->e_shnum; ++i)
	{
		if (i != hdr->e_shstrndx && shdr->sh_type == SHT_STRTAB)
			return(shdr);
		shdr = (void *)shdr + sizeof(Elf64_Shdr);
	}
	return (NULL);
}

