NAME=victim-openssl
C=gcc
LNK=gcc
CFLAGS=-c -Wall -ggdb3
LNKFLAGS=-lcrypto
BIN=bin
OBJ=obj

.PHONY: default clean
default: $(BIN)/$(NAME)
clean:
	rm -rf $(BIN) $(OBJ)

$(OBJ):
	@mkdir -p $(OBJ)
$(BIN):
	@mkdir -p $(BIN)

$(OBJ)/main.o: main.c | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(BIN)/$(NAME): $(OBJ)/main.o | $(BIN)
	$(LNK) -o $@ $(LNKFLAGS) $^
