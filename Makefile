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
LIBS		= -lcrypto

ifdef DEBUG
CC_FLAGS += -DDEBUG
endif

ifdef STUB_OFFSET
CC_FLAGS += -DSTUB_OFFSET=$(STUB_OFFSET)
endif

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

debug:
	@make re DEBUG=1

help:
	@printf "Usage: make [target] <DEFINE>\n\n"
	@printf "Targets:\n"
	@printf "${GRN}  all  ${RST}     - Compile the project\n"
	@printf "${GRN}  clean  ${RST}   - Remove object files\n"
	@printf "${GRN}  fclean  ${RST}  - Remove object files and the executable\n"
	@printf "${GRN}  re  ${RST}      - Clean and compile the project\n"
	@printf "${GRN}  tests  ${RST}   - Run the tests\n"
	@printf "${GRN}  stub  ${RST}    - Compile the stub\n"
	@printf "${GRN}  help  ${RST}    - Display this help message\n\n"
	@printf "You can also set the STUB_OFFSET environment variable to specify the stub offset.\n"
	@printf "You can also set the DEBUG environment variable to enable debug mode.\n\n"
	@printf "${BLU}Example: make all DEBUG=1 STUB_OFFSET=0xC0000000\n${RST}"
	@printf "\n"

.PHONY:		all clean fclean re tests stub help
