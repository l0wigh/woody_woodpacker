BLU			= \033[0;34m
GRN			= \033[0;32m
RED			= \033[0;31m
RST			= \033[0m
END			= \e[0m
TOTEM 		= 🦁

FILES = woody

SRCS = $(FILES:%=srcs/%.c)
NAME		= woody_woodpacker
OBJS_DIR	= objs/
PROJECT_H	= srcs/woody.h
OBJS		= $(SRCS:.c=.o)
OBJECTS_PREFIXED = $(addprefix $(OBJS_DIR), $(OBJS))
CC			= gcc
CC_FLAGS	= -Wall -Werror -Wextra -g3 -fsanitize=address
LIBS		=

$(OBJS_DIR)%.o : %.c $(PROJECT_H)
	@mkdir -p $(OBJS_DIR)
	@mkdir -p $(OBJS_DIR)srcs
	@$(CC) $(CC_FLAGS) -c $< -o $@
	@printf	"\033[2K\r${BLU}${TOTEM} [BUILD]${RST} '$<' $(END)"

$(NAME): $(OBJECTS_PREFIXED)
	@$(CC) -o $(NAME) $(OBJECTS_PREFIXED) $(CC_FLAGS) $(LIBS) # Program
	@printf "\033[2K\r\033[0;32m${TOTEM} [END]\033[0m $(NAME)$(END)\n"

all: $(NAME)

tests:
	@./tests/clean_bin.sh
	@printf "\033[2K\r${GRN}${TOTEM} [TESTS]${RST} done$(END)\n"

stub:
	@cd stub; fasm stub.s stub.bin; xxd -i stub.bin > ../srcs/stub.h
	@make re
	@printf "\033[2K\r${GRN}${TOTEM} [STUB]${RST} done$(END)\n"

clean:
	@rm -rf $(OBJS_DIR)
	@printf "\033[2K\r${GRN}${TOTEM} [CLEAN]${RST} done$(END)\n"

fclean: clean
	@rm -f $(NAME)
	@rm -rf $(OBJS_DIR)
	@printf "\033[2K\r${GRN}${TOTEM} [FCLEAN]${RST} done$(END)\n"

re: fclean all

.PHONY:		all clean fclean re tests stub
