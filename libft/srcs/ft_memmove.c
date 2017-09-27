/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/03 16:26:01 by fventuri          #+#    #+#             */
/*   Updated: 2014/12/13 16:56:59 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	unsigned char	*buffer;
	size_t			i;

	i = -1;
	buffer = (unsigned char *)malloc(sizeof(unsigned char) * len);
	while (++i < len)
		buffer[i] = *(unsigned char *)(src + i);
	i = -1;
	while (++i < len)
		*(unsigned char *)(dst + i) = buffer[i];
	free(buffer);
	return (dst);
}
