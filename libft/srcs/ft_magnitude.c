/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_magnitude.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/02 21:18:08 by fventuri          #+#    #+#             */
/*   Updated: 2015/01/02 21:38:11 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

int		ft_magnitude(long nb, int mag)
{
	if (nb < 0)
	{
		mag++;
		nb *= -1;
	}
	if (!nb && mag == 0)
		return (1);
	if (!nb)
		return (mag);
	return (ft_magnitude(nb / 10, mag + 1));
}
