
#### COMPILATION VARS ####
NAME = woody_woodpacker
CC = gcc
NASM = nasm

AFLAGS = -f elf64
CFLAGS = -Wall -Wextra -Werror
C_FILES = main.c\
	  print_elf.c\
	  helpers_elf.c\
	  woodywood_pack.c
SRCS = $(addprefix srcs/,$(C_FILES))
O_FILES = $(C_FILES:.c=.o)
OBJ = $(addprefix obj/,$(O_FILES))
H_FILES = woody.h
INCLUDES = $(addprefix includes/,$(H_FILES))
LIBFT = -L libft -lft
COMPILE_FLAGS = -I includes -I libft/includes

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

.PHONY: clean fclean re libft

all: $(NAME)

$(NAME): libft $(OBJ)
	@printf "[WOODY_WOODPACKER]: Compiling $(GREEN)$(NAME)$(NC)... "
	@$(NASM) $(AFLAGS) srcs/encrypt.s -o obj/encrypt.o
	@$(NASM) $(AFLAGS) srcs/decrypt.s -o obj/decrypt.o
	@$(CC) $(CFLAGS) -o $(NAME) $(OBJ) obj/encrypt.o libft/libft.a 
	@printf "$(LGREEN)OK$(NC)\n"
	@printf "[WOODY_WOODPACKER]: $(RED)ALL DONE$(NC)\n"

libft:
	@make -s -C libft/

obj/%.o: srcs/%.c $(INCLUDES)
	@mkdir -p obj
	@printf "[WOODY_WOODPACKER]: Compiling $(BLUE)$<$(NC) --> $(BLUE)$@$(NC)... "
	@$(CC) $(CFLAGS) -o $@ -c $< $(COMPILE_FLAGS)
	@printf "$(LGREEN)OK$(NC)\n"

clean:
	@make -s -C libft/ clean
	@if [ -d obj ]; then \
		printf "[WOODY_WOODPACKER]: Removing $(PURPLE).o files$(NC)... "; \
		rm -rf obj; \
		printf "$(LGREEN)OK$(NC)\n"; \
	fi;

fclean: clean
	@make -s -C libft/ fclean
	@printf "[WOODY_WOODPACKER]: Removing $(PURPLE)$(NAME)$(NC)... "
	@rm -f $(NAME)
	@printf "$(LGREEN)OK$(NC)\n"

re: fclean all
