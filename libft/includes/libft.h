/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft.h                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2014/11/04 10:49:41 by fventuri          #+#    #+#             */
/*   Updated: 2017/04/26 12:44:37 by fventuri         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H

# include <string.h>
# include <libft_structs.h>

# define NC "\033[0m"
# define BLACK "\033[0;30m"
# define RED "\033[0;31m"
# define GREEN "\033[0;32m"
# define ORANGE "\033[0;33m"
# define BLUE "\033[0;34m"
# define PURPLE "\033[0;35m"
# define CYAN "\033[0;36m"
# define LGRAY "\033[0;37m"
# define DGRAY "\033[1;30m"
# define LRED "\033[1;31m"
# define LGREEN "\033[1;32m"
# define YELLOW "\033[1;33m"
# define LBLUE "\033[1;34m"
# define LPURPLE "\033[1;35m"
# define LCYAN "\033[1;36m"
# define WHITE "\033[1;37m"

double			ft_atof(const char *str);
int				ft_atoi(const char *str);
long			ft_atoli(const char *str);
unsigned int	ft_atoui_base(const char *str, unsigned int base);
void			ft_bzero(void *s, size_t n);
int				ft_isalnum(int c);
int				ft_isalpha(int c);
int				ft_isascii(int c);
int				ft_isdigit(int c);
int				ft_isprint(int c);
char			*ft_itoa(int n);
char			*ft_litoa(long n);
void			ft_lstadd(t_list **alst, t_list *new);
void			ft_lstadd_back(t_list **begin, t_list *new);
t_list			*ft_lstcpy(t_list *elem);
void			ft_lstdel(t_list **alst, void(*del)(void *, size_t));
void			ft_lstdelone(t_list **alst, void (*del)(void *, size_t));
void			ft_lstiter(t_list *lst, void (*f)(t_list *elem));
t_list			*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem));
t_list			*ft_lstnew(void const *content, size_t content_size);
int				ft_magnitude(long nb, int mag);
void			*ft_memalloc(size_t size);
void			*ft_memccpy(void *dst, const void *src, int c, size_t n);
void			*ft_memchr(const void *s, int c, size_t n);
int				ft_memcmp(const void *s1, const void *s2, size_t n);
void			*ft_memcpy(void *dst, const void *src, size_t n);
void			ft_memdel(void **ap);
void			*ft_memmove(void *dst, const void *src, size_t len);
void			*ft_memset(void *b, int c, size_t len);
void			ft_print_color(const char *str, const char *color);
void			ft_putchar(char c);
void			ft_putchar_fd(char c, int fd);
void			ft_putdigit_base(unsigned long n, unsigned int base);
void			ft_putdigit_base_fd(unsigned long n, unsigned int base, int fd);
void			ft_putendl(char const *s);
void			ft_putendl_fd(char const *s, int fd);
void			ft_putlnbr_base(unsigned long n, unsigned int base);
void			ft_putlnbr_base_fd(unsigned long n, unsigned int base, int fd);
void			ft_putnbr(int n);
void			ft_putnbr_base(unsigned int n, unsigned int base);
void			ft_putnbr_base_fd(unsigned int n, unsigned int base, int fd);
void			ft_putnbr_fd(int n, int fd);
void			ft_putstr(char const *s);
void			ft_putstr_fd(char const *s, int fd);
void			*ft_realloc(void *ptr, size_t size, size_t new_size);
char			*ft_strcat(char *s1, const char *s2);
char			*ft_strchr(const char *s, int c);
void			ft_strclr(char *s);
int				ft_strcmp(const char *s1, const char *s2);
char			*ft_strcpy(char *dst, const char *src);
void			ft_strdel(char **as);
char			*ft_strdup(const char *s1);
int				ft_strequ(char const *s1, char const *s2);
void			ft_striter(char *s, void (*f)(char *));
void			ft_striteri(char *s, void (*f)(unsigned int, char *));
char			*ft_strjoin(char const *s1, char const *s2);
size_t			ft_strlcat(char *dst, const char *src, size_t size);
int				ft_strlen(const char *s);
char			*ft_strmap(char const *s, char (*f)(char));
char			*ft_strmapi(char const *s, char (*f)(unsigned int, char));
char			*ft_strncat(char *s1, const char *s2, size_t n);
int				ft_strncmp(const char *s1, const char *s2, size_t n);
char			*ft_strncpy(char *dst, const char *src, size_t n);
char			*ft_strndup(const char *str, size_t len);
int				ft_strnequ(char const *s1, char const *s2, size_t n);
char			*ft_strnew(size_t size);
char			*ft_strnstr(const char *s1, const char *s2, size_t n);
char			*ft_strrchr(const char *s, int c);
char			**ft_strsplit(char const *s, char c);
char			*ft_strstr(const char *s1, const char *s2);
char			*ft_strsub(char const *s, unsigned int start, size_t len);
char			*ft_strtolower(char *str);
char			*ft_strtoupper(char *str);
char			*ft_strtrim(char const *s);
int				ft_tolower(int c);
int				ft_toupper(int c);
char			*ft_uitoa_base(unsigned int n, unsigned int base);
char			*ft_ulitoa_base(unsigned long n, unsigned int base);

#endif
