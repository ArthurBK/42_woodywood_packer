/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putdigit_base.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2015/01/02 19:47:13 by fventuri          #+#    #+#             */
/*   Updated: 2016/11/23 11:25:25 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"

void	ft_putdigit_base(unsigned long n, unsigned int base)
{
	if (n > base || base > 62 || base < 2)
		return ;
	if (n < 10)
		ft_putchar(n + '0');
	else if (n < 36)
		ft_putchar(n - 10 + 'A');
	else
		ft_putchar(n - 36 + 'a');
}
