#include <woody.h>

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
	printf("\n\tsh_name: %s (Section name)", (char *)((void *)sstr + shdr->sh_name));
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
