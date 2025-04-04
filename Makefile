CC = gcc
CFLAGS = -Wall -I./lib/cJSON -I./src
LDFLAGS = -lcurl

SRC = src/main.c src/ip_filter.c src/shodan_api.c src/html_writer.c src/utils.c lib/cJSON/cJSON.c
OBJ = $(SRC:.c=.o)

BIN = build/shodan_tool

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(BIN)

.PHONY: all clean
