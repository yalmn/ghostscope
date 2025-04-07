CC = gcc
CFLAGS = -Wall -I./lib/cJSON -I./src
LDFLAGS = -lcurl

SRC = src/main.c src/ip_filter.c src/shodan_api.c src/html_writer.c \
      src/utils.c src/eol_check.c lib/cJSON/cJSON.c

OBJ = $(SRC:.c=.o)
BIN = build/ghostscope

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(BIN) ./build/result.html ./build/filtered.txt

.PHONY: all clean

