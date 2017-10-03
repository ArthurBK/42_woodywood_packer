#include <woody.h>

void	*open_shellcode(size_t *code_size)
{
	int		fd;
	void		*shellcode;
	struct stat	statbuf;

	if ((fd = open("./obj/decrypt.o", O_RDONLY)) < 0)
	{
		perror("[!]");
		return (0);
	}

	if (fstat(fd, &statbuf) < 0)
	{
		perror("[!]");
		return (0);
	}
	*code_size = statbuf.st_size;
	if ((shellcode = mmap(0, *code_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0))
			== MAP_FAILED)
	{
		perror("[!]");
		return (0);
	}
	return (shellcode);
}

void		alloc_malicious_code(void *woody_ptr, Elf64_Phdr *last_Phdr, void *ptr, size_t filesz, size_t code_size)
{

	size_t padding_len;

	padding_len = last_Phdr->p_memsz - last_Phdr->p_filesz;
	ft_memcpy(woody_ptr, ptr, last_Phdr->p_offset + last_Phdr->p_filesz);
	//ft_memcpy(woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len, code, C);
	ft_memcpy(woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len + code_size, 
			ptr + last_Phdr->p_offset + last_Phdr->p_filesz, 
			filesz - last_Phdr->p_offset - last_Phdr->p_filesz);
}

void		update_segment(Elf64_Phdr *phdr, int code_size)
{
	phdr->p_filesz += code_size;
	phdr->p_memsz += code_size;
}

void	insert_Shdr(Elf64_Ehdr *woody_Ehdr, Elf64_Shdr *woody_Shdr, Elf64_Ehdr *hdr, size_t padding_len, size_t code_size)
{	
	int i;
	Elf64_Phdr *last_Phdr;

	last_Phdr = find_last_segment((void *)hdr);
	for (i = 0; i < hdr->e_shnum; ++i)
	{
		if (woody_Shdr->sh_offset > last_Phdr->p_offset + last_Phdr->p_filesz)
			woody_Shdr->sh_offset += padding_len + code_size;
		woody_Shdr = (void *)woody_Shdr + sizeof(Elf64_Shdr);
	}
	woody_Shdr->sh_type = SHT_PROGBITS;
	woody_Shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
	woody_Shdr->sh_offset = last_Phdr->p_offset + last_Phdr->p_filesz + padding_len;
	woody_Shdr->sh_addr = (last_Phdr->p_vaddr - last_Phdr->p_offset) + woody_Shdr->sh_offset;
	woody_Shdr->sh_size = CODE_SIZE;
	woody_Shdr->sh_addralign = 16;
	woody_Ehdr->e_shnum++;
	// woody_Ehdr->e_entry = 0x0000000000601038;
}

int	insert_code(Elf64_Shdr *to_encrypt, void *woody_ptr, void *shellcode, Elf64_Ehdr *hdr)
{
	Elf64_Off	encr_offset;
	uint64_t	encr_size;
	Elf64_Shdr	*shell_symtab;
	Elf64_Shdr	*shell_exec;
	int i;
	hdr = NULL;
	woody_ptr = NULL;

	i = 0;
	encr_offset = to_encrypt->sh_offset;
	encr_size = to_encrypt->sh_size;
	shell_symtab = get_section64_by_type(shellcode, SHT_SYMTAB);
	shell_exec = get_section64_by_type(shellcode, SHT_PROGBITS);
	while (i < 10)
	{
	
		++i;
	}
	return (0);

}

int	woodywood_pack(void *ptr, struct stat statbuf)
{
	Elf64_Phdr 	*last_Phdr;
	Elf64_Ehdr 	*hdr;
	Elf64_Shdr	*to_encrypt;
	void		*key;
	size_t		packed_size;
	size_t		padding_len;
	size_t		code_size;
	void		*woody_ptr;
	void		*shellcode;
	int 		fd;

	hdr = ptr;
	// find last Segment
	last_Phdr = find_last_segment(ptr);
	if (!(shellcode = open_shellcode(&code_size)))
		return (1);
	padding_len = last_Phdr->p_memsz - last_Phdr->p_filesz;
	packed_size = statbuf.st_size + code_size + sizeof(Elf64_Shdr) + padding_len;
	if (!(fd = open("woody", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO)))
		return (1);
	if (!(woody_ptr = ft_memalloc(packed_size)))
		return (1);
	// encrpyt elf 
	if (!(to_encrypt = get_section64_with_e(hdr, hdr->e_entry)))
	{
		perror("[!]");
		return (1);
	}
	key = ft_memalloc(16);
	generate_key(key);
	encrypt((void *)hdr + to_encrypt->sh_offset, to_encrypt->sh_size, key);
	// alloc_malicious_code
	alloc_malicious_code(woody_ptr, last_Phdr, ptr, statbuf.st_size, code_size);
	// update last_segment info
	update_segment(find_last_segment(woody_ptr), code_size);
	// update header
	((Elf64_Ehdr *)woody_ptr)->e_shoff += code_size + padding_len;
	// insert new Shdr
	insert_Shdr(woody_ptr, (void *)woody_ptr + ((Elf64_Ehdr *)woody_ptr)->e_shoff, hdr, padding_len, code_size);
	// insert code
	if (insert_code(to_encrypt, woody_ptr, shellcode, hdr))
		return (1);
	// followed by code that decrypts and point to old e_entry

	//print_all(ptr);
	write(fd, woody_ptr, packed_size);
	return(0);
}

