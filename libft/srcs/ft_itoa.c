/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 18:10:03 by fventuri          #+#    #+#             */
/*   Updated: 2015/01/03 14:47:20 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>

static int	is_extrem(int n, char *ret)
{
	if (n == -2147483648)
	{
		ft_strcpy(ret, "-2147483648");
		return (1);
	}
	return (0);
}

char		*ft_itoa(int n)
{
	char	*ret;
	int		size;

	size = ft_magnitude(n, 0);
	ret = ft_strnew(size);
	if (is_extrem(n, ret))
		return (ret);
	else
	{
		if (n < 0)
		{
			ret[0] = '-';
			n *= -1;
		}
		ret[size] = 0;
		if (!n)
			ret[0] = '0';
		while (n)
		{
			ret[--size] = n % 10 + '0';
			n /= 10;
		}
	}
	return (ret);
}
