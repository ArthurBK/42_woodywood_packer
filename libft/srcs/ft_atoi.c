/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 11:25:51 by fventuri          #+#    #+#             */
/*   Updated: 2015/02/05 18:56:10 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

int		ft_atoi(const char *str)
{
	int		value;
	int		sign;
	int		i;

	if (!str)
		return (0);
	sign = 1;
	i = 0;
	value = 0;
	while (((str[i] > 8 && str[i] < 14) || str[i] == ' ') && str[i])
		i++;
	if (!(str[i]))
		return (0);
	if (str[i] == '-' || str[i] == '+')
	{
		if (str[i] == '-')
			sign = -1;
		i++;
	}
	while (str[i] && ft_isdigit((int)str[i]))
		value = value * 10 + (str[i++] - '0');
	return (sign * value);
}
