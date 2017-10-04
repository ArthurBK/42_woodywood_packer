/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   woody.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mguillau <mguillau@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/05/10 19:34:11 by mguillau          #+#    #+#             */
/*   Updated: 2017/05/11 13:26:34 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef WOODY_H
# define WOODY_H

# include <elf.h>
# include <errno.h>
# include <fcntl.h>
# include <stdio.h>
# include <sys/mman.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <unistd.h>
# include <stdlib.h>

# include <libft.h>

int	woodywood_pack(void *ptr, struct stat statbuf);
Elf64_Shdr	*get_section64(Elf64_Ehdr *hdr, uint16_t index);
Elf64_Shdr	*get_section64_by_type(Elf64_Ehdr *hdr, uint32_t type);
Elf64_Phdr	*find_last_segment(void *ptr);
void print_Ehdr(Elf64_Ehdr *hdr);
void print_Phdr(Elf64_Phdr *phdr);
void print_Shdr(Elf64_Shdr *shdr, Elf64_Shdr *sstr);
void	generate_key(void *buf);
void *encrypt(void *data, size_t size, void *key);
Elf64_Shdr	*get_section64_with_e(Elf64_Ehdr *hdr, Elf64_Addr entry);
Elf64_Shdr	*get_sym_strtab(Elf64_Ehdr *hdr);
void print_all(void *ptr);

#define CODE_SIZE 27
#endif
