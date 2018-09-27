CFLAGS = -Wall -Wextra -g -ggdb -std=c99

sessions: sessions.c
	gcc $(CFLAGS) -o sessions sessions.c

clean:
	rm -f sessions
