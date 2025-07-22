# Compiler and Flags
CC = /usr/bin/gcc
CFLAGS = -g -Wall -Wextra -O3 -std=c99 -Wconversion -Wmissing-prototypes -I$(INC_DIR) # -Wpedantic
LDFLAGS = -Llib -loqs -lcrypto -lpthread
CONFIG = sha2_256f_simple

# Directories
BIN_DIR = bin
SRC_DIR = src
INC_DIR = inc

# Source and Header Files
SOURCES = $(INC_DIR)/fprintbstr.c
HEADERS = $(INC_DIR)/fprintbstr.h

# Targets
TARGETS = sign_heap sign_stack key_gen sign_verify sign_heap_v2 

# Default target
default: $(TARGETS)

# Ensure bin directory exists
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Build all targets
all: $(TARGETS)

# Generic build rule
$(TARGETS): %: $(SRC_DIR)/%.c $(SOURCES) $(HEADERS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$@ $(SOURCES) $< $(LDFLAGS)

# Clean target
clean:
	-$(RM) $(BIN_DIR)/*
	-rmdir --ignore-fail-on-non-empty $(BIN_DIR)

