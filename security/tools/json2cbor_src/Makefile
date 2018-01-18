.SUFFIXES : .c .o

CC = gcc

INC = ./include
LIBS =
CFLAGS = -I $(INC)

TARGET = json2cbor

SRCS = $(wildcard ./src/*.c) json2cbor.c
OBJS = $(SRCS:.c=.o)

all : $(TARGET)

dep :
	gccmakedep $(INC) $(SRCS)

$(TARGET) : $(OBJS)
	echo $(SRCS)
	$(CC) -o $@ $(CFLAGS) $(OBJS)

clean :
	rm -rf $(OBJS) $(TARGET)
