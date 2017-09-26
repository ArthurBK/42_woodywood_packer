/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 13:27:38 by fventuri          #+#    #+#             */
/*   Updated: 2017/04/26 12:43:20 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strncpy(char *dst, const char *src, size_t n)
{
	size_t	i;

	if (dst && src)
	{
		i = -1;
		while (++i < n && src[i])
			dst[i] = src[i];
		i--;
		while (++i < n)
			dst[i] = 0;
	}
	return (dst);
}
