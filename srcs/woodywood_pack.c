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
	ft_memcpy(woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len + code_size, 
			ptr + last_Phdr->p_offset + last_Phdr->p_filesz, 
			filesz - last_Phdr->p_offset - last_Phdr->p_filesz);
}

void		update_segment(Elf64_Phdr *phdr, int code_size)
{
	phdr->p_filesz += code_size;
	phdr->p_memsz += code_size;
}

Elf64_Addr	insert_Shdr(Elf64_Ehdr *woody_Ehdr, Elf64_Shdr *woody_Shdr, Elf64_Ehdr *hdr, size_t padding_len, size_t code_size)
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
	woody_Shdr->sh_size = code_size;
	woody_Shdr->sh_addralign = 16;
	woody_Ehdr->e_shnum++;
	return ((woody_Shdr->sh_addr));
}

int	insert_code(Elf64_Shdr *to_decrypt, void *target, void *shellcode, Elf64_Addr new_ep, void *key)
{
	Elf64_Off	decr_offset;
	Elf64_Sym	*shell_symtab;
	Elf64_Shdr	*shell_symtabhdr;
	Elf64_Shdr	*shell_exec;
	Elf64_Shdr	*shell_str;

	shell_symtabhdr = get_section64_by_type(shellcode, SHT_SYMTAB);
	shell_symtab = (void *)shellcode + shell_symtabhdr->sh_offset;
	shell_str = (void *)shellcode + (get_sym_strtab(shellcode))->sh_offset;
	shell_exec = get_section64_by_type(shellcode, SHT_PROGBITS);
	while  ((void *)shell_symtab < (void *)shellcode + shell_symtabhdr->sh_offset + shell_symtabhdr->sh_size)
	{

		if (!ft_strcmp((void *)shell_str + shell_symtab->st_name, "to_decrypt"))
		{		
			decr_offset = new_ep - to_decrypt->sh_size - shell_symtab->st_value + 100;

				//(new_ep + shell_symtab->st_value - to_decrypt->sh_addr);
			printf("to_decrypt: %ld\n", to_decrypt->sh_offset);
			printf("to_decrypt: %ld\n", to_decrypt->sh_addr);
			ft_memcpy((void *)shellcode + shell_exec->sh_offset + shell_symtab->st_value, &decr_offset, 16);
		}
		else if (!ft_strcmp((void *)shell_str + shell_symtab->st_name, "len"))
		{
			printf("SIZE: %ld\n", to_decrypt->sh_size);
			ft_memcpy((void *)shellcode + shell_exec->sh_offset + shell_symtab->st_value, &(to_decrypt->sh_size), 8);
		}
		else if (!ft_strcmp((void *)shell_str + shell_symtab->st_name, "key"))
		{
			printf("key: %c%c %c%c %c%c %c%c %c%c %c%c %c%c %c%c \n",\
						((unsigned char*)key)[0], ((unsigned char*)key)[1],\
						((unsigned char*)key)[2], ((unsigned char*)key)[3],\
						((unsigned char*)key)[4], ((unsigned char*)key)[5],\
						((unsigned char*)key)[6], ((unsigned char*)key)[7],\
						((unsigned char*)key)[8], ((unsigned char*)key)[9],\
						((unsigned char*)key)[10], ((unsigned char*)key)[11],\
						((unsigned char*)key)[12], ((unsigned char*)key)[13],\
						((unsigned char*)key)[14], ((unsigned char*)key)[15]);
			printf("key: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",\
						((unsigned char*)key)[0], ((unsigned char*)key)[1],\
						((unsigned char*)key)[2], ((unsigned char*)key)[3],\
						((unsigned char*)key)[4], ((unsigned char*)key)[5],\
						((unsigned char*)key)[6], ((unsigned char*)key)[7],\
						((unsigned char*)key)[8], ((unsigned char*)key)[9],\
						((unsigned char*)key)[10], ((unsigned char*)key)[11],\
						((unsigned char*)key)[12], ((unsigned char*)key)[13],\
						((unsigned char*)key)[14], ((unsigned char*)key)[15]);
			ft_memcpy((void*)shellcode + shell_exec->sh_offset + shell_symtab->st_value, key, 16);
		}
		else if (!ft_strcmp((void *)shell_str + shell_symtab->st_name, "to_jump"))
		{
			//decr_offset = new_ep -  shell_exec->sh_offset - code_offset;
			decr_offset = new_ep - to_decrypt->sh_size - shell_symtab->st_value + 132;
			//	(to_decrypt->sh_offset - code_offset - shell_symtab->st_value);
			ft_memcpy(shellcode + shell_exec->sh_offset + shell_symtab->st_value, &decr_offset, 8);
		}
		shell_symtab = (void *)shell_symtab + sizeof(Elf64_Sym);	
	}
	ft_memcpy(target, (void *)shellcode + shell_exec->sh_offset, shell_exec->sh_size);
	return (0);

}

int	woodywood_pack(void *ptr, struct stat statbuf)
{
	Elf64_Phdr 	*last_Phdr;
	Elf64_Ehdr 	*hdr;
	Elf64_Addr 	new_entrypoint;
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
	printf("%ld\n", padding_len);
	packed_size = statbuf.st_size + code_size + sizeof(Elf64_Shdr) + padding_len;
	if (!(fd = open("woody", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO)))
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
	new_entrypoint = insert_Shdr(woody_ptr, (void *)woody_ptr + ((Elf64_Ehdr *)woody_ptr)->e_shoff, hdr, padding_len, code_size);
	// insert code
	if (insert_code(to_encrypt, (void *)woody_ptr + last_Phdr->p_offset + last_Phdr->p_filesz + padding_len, \
				shellcode, new_entrypoint, key))
		return (1);
	((Elf64_Ehdr *)woody_ptr)->e_entry = new_entrypoint;
	//last_Phdr->p_offset + last_Phdr->p_filesz + padding_len;
	// followed by code that decrypts and point to old e_entry
	write(fd, woody_ptr, packed_size);
	//print_all(woody_ptr);
	return(0);
}

