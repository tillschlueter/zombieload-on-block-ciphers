NAME=simulator
C=gcc
LNK=gcc
CFLAGS=-c -Wall -ggdb3
LNKFLAGS=
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

$(OBJ)/aes-min.o: aes-min/aes-min.c aes-min/aes-min.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(OBJ)/main.o: main.c aes-min/aes-min.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(BIN)/$(NAME): $(OBJ)/main.o $(OBJ)/aes-min.o | $(BIN)
	$(LNK) -o $@ $(LNKFLAGS) $^
