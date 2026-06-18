CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter
INCS     = -Ivendor
# mongoose + sqlite need pthread, dl, math
LIBS     = -lpthread -ldl -lm

SRCS = src/main.c vendor/mongoose.c vendor/sqlite3.c
BIN  = chan

# sqlite amalgamation is huge; keep its warnings quiet and build it fast.
SQLITE_FLAGS = -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION
# mongoose caps the recv buffer at 3 MiB by default; raise it for 8 MiB uploads.
# MG_ENABLE_DIRLIST=0 disables directory listings (no enumerating /uploads/).
# MG_ENABLE_EPOLL=1 uses epoll instead of select (scales past FD_SETSIZE ~1024).
MG_FLAGS = -DMG_MAX_RECV_SIZE=12582912 -DMG_ENABLE_DIRLIST=0 -DMG_ENABLE_EPOLL=1

.PHONY: all run clean

all: $(BIN)

$(BIN): $(SRCS)
	$(CC) $(CFLAGS) $(INCS) $(SQLITE_FLAGS) $(MG_FLAGS) -o $(BIN) $(SRCS) $(LIBS)

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) chan.db chan.db-wal chan.db-shm
