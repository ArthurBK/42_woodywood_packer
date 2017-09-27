/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtoupper.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/06 14:15:29 by fventuri          #+#    #+#             */
/*   Updated: 2015/03/31 16:58:00 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

char	*ft_strtoupper(char *str)
{
	int		i;

	i = -1;
	if (!str)
		return (NULL);
	while (str[++i])
		str[i] = ft_toupper(str[i]);
	return (str);
}
