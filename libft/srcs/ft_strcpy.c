/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 12:19:18 by fventuri          #+#    #+#             */
/*   Updated: 2014/12/13 17:07:20 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

char	*ft_strcpy(char *dst, const char *src)
{
	int		i;

	if (src && dst)
	{
		i = -1;
		while (src[++i])
			dst[i] = src[i];
		dst[i] = 0;
	}
	return (dst);
}
