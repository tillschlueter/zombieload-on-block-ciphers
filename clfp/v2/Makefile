NAME=leak
C=gcc
LNK=gcc
CFLAGS=-c -Os
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

$(OBJ)/main.o: main.c cacheutils.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(BIN)/$(NAME): $(OBJ)/main.o | $(BIN)
	$(LNK) -o $@ $(LNKFLAGS) $^
