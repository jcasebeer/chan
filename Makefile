CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -DCLOUDFLARED
INCS     = -Ivendor
# mongoose + sqlite need pthread, dl, math
LIBS     = -lpthread -ldl -lm

BIN  = chan
OBJS = main.o mongoose.o sqlite3.o

# sqlite amalgamation is huge; keep its warnings quiet and build it fast.
SQLITE_FLAGS = -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION
# mongoose caps the recv buffer at 3 MiB by default; raise it for 8 MiB uploads.
# MG_ENABLE_DIRLIST=0 disables directory listings (no enumerating /uploads/).
# MG_ENABLE_EPOLL=1 uses epoll instead of select (scales past FD_SETSIZE ~1024).
MG_FLAGS = -DMG_MAX_RECV_SIZE=12582912 -DMG_ENABLE_DIRLIST=0 -DMG_ENABLE_EPOLL=1

.PHONY: all run clean

all: $(BIN)

# The vendored amalgamations (sqlite ~250k lines, mongoose large) are compiled
# once into their own objects, so editing src/main.c only recompiles main.o and
# relinks -- seconds instead of recompiling everything every build.
$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJS) $(LIBS)

main.o: src/main.c vendor/md5.h vendor/mongoose.h vendor/sqlite3.h
	$(CC) $(CFLAGS) $(INCS) $(MG_FLAGS) $(SQLITE_FLAGS) -c src/main.c -o $@

mongoose.o: vendor/mongoose.c vendor/mongoose.h
	$(CC) $(CFLAGS) $(INCS) $(MG_FLAGS) -c vendor/mongoose.c -o $@

sqlite3.o: vendor/sqlite3.c vendor/sqlite3.h
	$(CC) $(CFLAGS) $(INCS) $(SQLITE_FLAGS) -c vendor/sqlite3.c -o $@

run: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) $(OBJS) chan.db chan.db-wal chan.db-shm
