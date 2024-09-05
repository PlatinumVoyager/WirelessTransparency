CC = gcc

CFLAGS = -std=c11 -Wall -fcommon
SECURITY_FLAGS = -fstack-protector-all -Wstack-protector -D_FORTIFY_SOURCE=2 -Wformat-security -Wl,-z,relro

SRCDIR = src
BINDIR = bin
OBJDIR = obj

SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(SRC:$(SRCDIR)/%.c = $(OBJDIR)/%.o)

TARGET = $(BINDIR)/WIRELESSTRANSPARENCY

object: $(OBJ)
build: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(SRC) -I./include -o $@ -lpcap

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
