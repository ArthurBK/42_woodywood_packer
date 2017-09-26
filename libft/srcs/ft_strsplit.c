/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strsplit.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/07 15:14:09 by fventuri          #+#    #+#             */
/*   Updated: 2015/03/31 17:17:46 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../includes/libft.h"
#include <stdlib.h>

static int	ft_get_wpos(const char *str, char c, int word)
{
	int		i;
	int		act_w;

	i = -1;
	act_w = 1;
	while (str[++i] && act_w < word)
		if (str[i] == c && str[i + 1] && str[i + 1] != c)
			++act_w;
	return (i);
}

static int	ft_get_wsize(const char *str, char c, int word)
{
	int		i;
	int		act_w;
	int		len;

	i = -1;
	act_w = 1;
	len = 0;
	while (str[++i] && act_w < word)
		if (str[i] == c && str[i + 1] && str[i + 1] != c)
			++act_w;
	--i;
	while (str[++i] && str[i] != c)
		++len;
	return (len);
}

static char	*ft_get_word(const char *str, char c, int word)
{
	char	*ret;
	int		w_size;
	int		i;
	int		j;

	i = -1;
	j = ft_get_wpos(str, c, word) - 1;
	w_size = ft_get_wsize(str, c, word);
	ret = ft_strnew(w_size);
	while (str[++j] && str[j] != c)
		ret[++i] = str[j];
	ret[++i] = 0;
	return (ret);
}

static int	ft_count_w(const char *str, char c)
{
	int		nb_w;
	int		i;

	nb_w = 0;
	i = -1;
	while (str[++i])
		if (i && (!str[i] || str[i] == c) && str[i - 1] != c)
			++nb_w;
	return (nb_w + 1);
}

char		**ft_strsplit(const char *str, char c)
{
	char	**split;
	int		nb_w;
	int		i;

	nb_w = ft_count_w(str, c);
	split = (char **)malloc(sizeof(char *) * (nb_w + 1));
	i = -1;
	while (++i < nb_w)
		split[i] = ft_get_word(str, c, i + 1);
	split[i] = NULL;
	return (split);
}
