# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: fventuri <fventuri@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2014/11/05 19:19:08 by fventuri          #+#    #+#              #
#    Updated: 2017/04/28 16:08:13 by fventuri         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = libft.a
CC = clang
CFLAGS = -Wall -Wextra -Werror
C_FILES = ft_atof.c \
		  ft_atoi.c \
		  ft_atoli.c \
		  ft_atoui_base.c \
		  ft_bzero.c \
		  ft_isalnum.c \
		  ft_isalpha.c \
		  ft_isascii.c \
		  ft_isdigit.c \
		  ft_isprint.c \
		  ft_itoa.c \
		  ft_litoa.c \
		  ft_lstadd.c \
		  ft_lstadd_back.c \
		  ft_lstcpy.c \
		  ft_lstdel.c \
		  ft_lstdelone.c \
		  ft_lstiter.c \
		  ft_lstmap.c \
		  ft_lstnew.c \
		  ft_magnitude.c \
		  ft_memalloc.c \
		  ft_memccpy.c \
		  ft_memchr.c \
		  ft_memcmp.c \
		  ft_memcpy.c \
		  ft_memdel.c \
		  ft_memmove.c \
		  ft_memset.c \
		  ft_print_color.c \
		  ft_putchar.c \
		  ft_putchar_fd.c \
		  ft_putdigit_base.c \
		  ft_putdigit_base_fd.c \
		  ft_putendl.c \
		  ft_putendl_fd.c \
		  ft_putlnbr_base.c \
		  ft_putlnbr_base_fd.c \
		  ft_putnbr.c \
		  ft_putnbr_base.c \
		  ft_putnbr_base_fd.c \
		  ft_putnbr_fd.c \
		  ft_putstr.c \
		  ft_putstr_fd.c \
		  ft_realloc.c \
		  ft_strcat.c \
		  ft_strchr.c \
		  ft_strclr.c \
		  ft_strcmp.c \
		  ft_strcpy.c \
		  ft_strdel.c \
		  ft_strdup.c \
		  ft_strequ.c \
		  ft_striter.c \
		  ft_striteri.c \
		  ft_strjoin.c \
		  ft_strlcat.c \
		  ft_strlen.c \
		  ft_strmap.c \
		  ft_strmapi.c \
		  ft_strncat.c \
		  ft_strncmp.c \
		  ft_strncpy.c \
		  ft_strndup.c \
		  ft_strnequ.c \
		  ft_strnew.c \
		  ft_strnstr.c \
		  ft_strrchr.c \
		  ft_strsplit.c \
		  ft_strstr.c \
		  ft_strsub.c \
		  ft_strtoupper.c \
		  ft_strtrim.c \
		  ft_tolower.c \
		  ft_toupper.c \
		  ft_uitoa_base.c \
		  ft_ulitoa_base.c
SRCS = $(addprefix srcs/,$(C_FILES))
O_FILES = $(C_FILES:.c=.o)
OBJ = $(addprefix obj/,$(O_FILES))
H_FILES = libft.h \
		  libft_structs.h
INCLUDES = $(addprefix includes/,$(H_FILES))

#### COLORS ####
NC		= \033[0m
BLACK	= \033[0;30m
RED		= \033[0;31m
GREEN	= \033[0;32m
ORANGE	= \033[0;33m
BLUE	= \033[0;34m
PURPLE	= \033[0;35m
CYAN	= \033[0;36m
LGRAY	= \033[0;37m
DGRAY	= \033[1;30m
LRED	= \033[1;31m
LGREEN	= \033[1;32m
YELLOW	= \033[1;33m
LBLUE	= \033[1;34m
LPURPLE	= \033[1;35m
LCYAN	= \033[1;36m
WHITE	= \033[1;37m

.PHONY: clean fclean re

all: $(NAME)

$(NAME): $(OBJ)
	@printf "[$(DGRAY)LIBFT$(NC)]: Compiling $(GREEN)$(NAME)$(NC)... "
	@ar rc $(NAME) $(OBJ)
	@ranlib $(NAME)
	@printf "$(LGREEN)OK$(NC)\n"
	@printf "[$(DGRAY)LIBFT$(NC)]: $(RED)ALL DONE$(NC)\n"

obj/%.o: srcs/%.c $(INCLUDES)
	@mkdir -p obj
	@printf "[$(DGRAY)LIBFT$(NC)]: Compiling $(BLUE)$<$(NC) --> $(BLUE)$@$(NC)... "
	@$(CC) $(CFLAGS) -o $@ -c $< -I includes/
	@printf "$(LGREEN)OK$(NC)\n"

clean:
	@if [ -d obj ]; then \
		printf "[$(DGRAY)LIBFT$(NC)]: Removing $(PURPLE).o files$(NC)... "; \
		rm -rf obj; \
		printf "$(LGREEN)OK$(NC)\n"; \
	fi;

fclean: clean
	@printf "[$(DGRAY)LIBFT$(NC)]: Removing $(PURPLE)$(NAME)$(NC)... "
	@rm -f $(NAME)
	@printf "$(LGREEN)OK$(NC)\n"

re: fclean all
