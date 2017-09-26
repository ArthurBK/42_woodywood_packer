/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/09 18:52:44 by fventuri          #+#    #+#             */
/*   Updated: 2014/12/13 16:47:56 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>

t_list	*ft_lstcpy(t_list *elem)
{
	t_list	*new;

	if (!elem)
		return (NULL);
	if (!elem->next)
	{
		new = ft_lstnew(elem->content, elem->content_size);
		return (new);
	}
	new = ft_lstnew(elem->content, elem->content_size);
	new->next = ft_lstcpy(elem->next);
	return (new);
}
