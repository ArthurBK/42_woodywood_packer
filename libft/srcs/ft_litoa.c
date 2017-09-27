/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_litoa.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 18:10:03 by fventuri          #+#    #+#             */
/*   Updated: 2015/01/17 15:32:55 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>
#include <limits.h>

static int	is_extrem(long n, char *ret)
{
	if (n == LONG_MIN)
	{
		ft_strcpy(ret, "-9223372036854775808");
		return (1);
	}
	return (0);
}

char		*ft_litoa(long n)
{
	char	*ret;
	int		size;

	size = ft_magnitude(n, 0);
	ret = ft_strnew(size);
	if (is_extrem(n, ret))
		return (ret);
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
	return (ret);
}
