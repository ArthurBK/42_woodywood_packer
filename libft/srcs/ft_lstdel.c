/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/08 14:12:18 by fventuri          #+#    #+#             */
/*   Updated: 2014/12/13 16:48:22 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>

void	ft_lstdel(t_list **alst, void (*del)(void *, size_t))
{
	t_list	*elem;
	t_list	*temp;

	if (!alst || !(*alst))
		return ;
	elem = *alst;
	temp = elem->next;
	while (elem)
	{
		del(elem->content, elem->content_size);
		free(elem);
		elem = temp;
		if (!elem)
			*alst = NULL;
		else
			temp = elem->next;
	}
}
