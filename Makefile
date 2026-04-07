# Makefile for libHandle2 library
# Build for MSYS2 (32-bit or 64-bit)

CC = gcc
CFLAGS = -O2 -Wall -DUNICODE -D_UNICODE -DHANDLE2_EXPORTS -Wno-cast-function-type -D_WIN32_WINNT=0x0600
LIBS = -lpsapi -ladvapi32

SRC_DIR = src
TEST_DIR = testApp
RELEASE_DIR = Release

SRCS = $(SRC_DIR)/ntapi.c $(SRC_DIR)/process.c $(SRC_DIR)/handle.c \
       $(SRC_DIR)/libHandle2.c $(SRC_DIR)/memory.c $(SRC_DIR)/scanner.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(RELEASE_DIR)/%.o)

TARGET_DLL = $(RELEASE_DIR)/libHandle2.dll
TARGET_TEST = $(RELEASE_DIR)/test_dll.exe

.PHONY: all clean help tree

all: $(RELEASE_DIR) $(TARGET_DLL) $(TARGET_TEST)

$(RELEASE_DIR):
	mkdir -p $(RELEASE_DIR)

$(RELEASE_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(TARGET_DLL): $(OBJS)
	$(CC) -shared -o $@ $^ $(LIBS)

$(TARGET_TEST): $(TEST_DIR)/test_dll.c
	$(CC) $(CFLAGS) -o $@ $< -I$(SRC_DIR) -L$(RELEASE_DIR) -lHandle2

clean:
	rm -rf $(RELEASE_DIR)

tree:
	@echo "Project tree:"
	@echo " "
	@echo "├── Makefile"
	@echo "├── src"
	@echo "│   ├── libHandle2.h"
	@echo "│   ├── private.h"
	@echo "│   ├── ntapi.c"
	@echo "│   ├── process.c"
	@echo "│   ├── handle.c"
	@echo "│   ├── libHandle2.c"
	@echo "│   ├── memory.c"
	@echo "│   └── scanner.c"
	@echo "├── testApp"
	@echo "│   └── test_dll.c"
	@echo "└── Release"
	@echo "    ├── libHandle2.dll"
	@echo "    └── test_dll.exe"

help:
	@echo "Available targets:"
	@echo "  make              - Build release version (default)"
	@echo "  make clean        - Remove build files"
	@echo "  make tree         - Show directory structure"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Copyright (c) 2026 playtester"