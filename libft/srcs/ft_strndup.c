/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strndup.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/26 12:40:44 by fventuri          #+#    #+#             */
/*   Updated: 2017/04/27 11:20:55 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strndup(const char *str, size_t len)
{
	char	*ret;

	if (!(ret = ft_strnew(len)))
		return (NULL);
	ret = ft_strncpy(ret, str, len);
	ret[len] = 0;
	return (ret);
}
