/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putlnbr_base.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/02 19:44:44 by fventuri          #+#    #+#             */
/*   Updated: 2015/01/06 10:24:05 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

void		ft_putlnbr_base(unsigned long n, unsigned int base)
{
	if (n > base - 1)
	{
		ft_putlnbr_base(n / base, base);
		ft_putlnbr_base(n % base, base);
	}
	else
		ft_putdigit_base(n, base);
}
