/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putlnbr_base_fd.c                               :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/02 19:55:53 by fventuri          #+#    #+#             */
/*   Updated: 2015/01/06 10:25:02 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

void		ft_putlnbr_base_fd(unsigned long n, unsigned int base, int fd)
{
	if (n > base - 1)
	{
		ft_putlnbr_base_fd(n / base, base, fd);
		ft_putlnbr_base_fd(n % base, base, fd);
	}
	else
		ft_putdigit_base_fd(n, base, fd);
}
