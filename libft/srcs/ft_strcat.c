/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strcat.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 13:41:11 by fventuri          #+#    #+#             */
/*   Updated: 2014/12/13 17:02:43 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

char	*ft_strcat(char *s1, const char *s2)
{
	int		i;
	int		j;

	if (!s1)
		return (NULL);
	if (s2)
	{
		i = 0;
		j = 0;
		while (s1[i])
			i++;
		while (s2[j])
			s1[i++] = s2[j++];
		s1[i] = 0;
	}
	return (s1);
}
