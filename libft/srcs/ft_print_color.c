/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_print_color.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/04/20 17:12:54 by fventuri          #+#    #+#             */
/*   Updated: 2017/04/20 17:36:07 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_print_color(const char *str, const char *color)
{
	ft_putstr(color);
	ft_putstr(str);
	ft_putstr(NC);
}
