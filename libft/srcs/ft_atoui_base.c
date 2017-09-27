/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoui_base.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/06 13:06:06 by fventuri          #+#    #+#             */
/*   Updated: 2015/02/21 12:22:42 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

static int		ft_isdigit_base(char c, int base)
{
	if (ft_isdigit(c) && base > (c - '0'))
		return (1);
	else if ((c > 96 && c < 123) && base > (c - 'a' + 9))
		return (1);
	else if ((c > 64 && c < 91) && base > (c - 'A' + 35))
		return (1);
	return (0);
}

static int		ft_getdigit_base(char c)
{
	if (!ft_isalnum(c))
		return (0);
	if (ft_isdigit(c))
		return (c - '0');
	else if (c < 123 && c > 96)
		return (c - 'a' + 10);
	else
		return (c - 'A' + 36);
}

unsigned int	ft_atoui_base(const char *str, unsigned int base)
{
	unsigned int	value;
	int				i;

	if (!str || base > 62 || base < 2)
		return (0);
	i = 0;
	value = 0;
	while (((str[i] > 8 && str[i] < 14) || str[i] == ' ') && str[i])
		i++;
	if (!(str[i]))
		return (0);
	if (str[i] == '-' || str[i] == '+')
		i++;
	while (str[i] && ft_isdigit_base(str[i], base))
		value = value * base + ft_getdigit_base(str[i++]);
	return (value);
}
