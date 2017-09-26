/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atof.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/03/31 16:06:57 by fventuri          #+#    #+#             */
/*   Updated: 2015/03/31 16:31:30 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

double	ft_atof(const char *str)
{
	double	value;
	int		ent;
	int		dec;
	int		sign;
	int		i;

	if (!str)
		return (0);
	i = 0;
	sign = 1;
	value = 0;
	while (((str[i] > 8 && str[i] < 14) || str[i] == ' ') && str[i])
		i++;
	if (!str[i])
		return (0);
	if (str[i] == '-' || str[i] == '+')
		sign = (str[i++] == '-') ? -1 : 1;
	ent = ft_atoi(str + i);
	while (str[i] && ft_isdigit(str[i]))
		++i;
	dec = (str[i] == '.') ? ft_atoi(str + i + 1) : 0;
	value = (double)ent + (double)dec / (double)(ft_magnitude(dec, 0) + 1);
	return (sign * value);
}
