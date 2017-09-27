/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ulitoa_base.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/03 15:01:36 by fventuri          #+#    #+#             */
/*   Updated: 2017/04/20 13:02:37 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

#include <stdio.h>

static int	ft_mag_base(unsigned long nb, unsigned int base, int mag)
{
	if (!nb && !mag)
		return (1);
	if (!nb)
		return (mag);
	return (ft_mag_base(nb / base, base, mag + 1));
}

static char	ft_getdigit_base(unsigned long n, unsigned int base)
{
	if (n > base || base > 62 || base < 2)
		return (0);
	if (n < 10)
		return (n + '0');
	else if (n < 36)
		return (n - 10 + 'a');
	else
		return (n - 36 + 'A');
}

char		*ft_ulitoa_base(unsigned long n, unsigned int base)
{
	char	*ret;
	int		size;

	size = ft_mag_base(n, base, 0);
	if (!(ret = ft_strnew(size)))
		return (NULL);
	ret[size] = 0;
	if (!n)
		ret[0] = '0';
	while (n)
	{
		ret[--size] = ft_getdigit_base(n % base, base);
		n /= base;
	}
	return (ret);
}
