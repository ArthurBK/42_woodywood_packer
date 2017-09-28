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
