NAME=clfp_attacker_v1
C=gcc
LNK=gcc
CFLAGS=-c -Wall -ggdb3 -Os -std=gnu99
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
$(OBJ)/cacheutils.o: cacheutils.c cacheutils.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(OBJ)/utils.o: utils.c utils.h main.h aes-min/aes-min.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(OBJ)/zombieload.o: zombieload.c zombieload.h utils.h main.h cacheutils.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(OBJ)/main.o: main.c main.h zombieload.h utils.h | $(OBJ)
	$(C) -o $@ $(CFLAGS) $<
$(BIN)/$(NAME): $(OBJ)/aes-min.o $(OBJ)/main.o $(OBJ)/cacheutils.o $(OBJ)/utils.o $(OBJ)/zombieload.o | $(BIN)
	$(LNK) -o $@ $(LNKFLAGS) $^
