gem_alert: main.c
	cc -ggdb -o gem_alert main.c -lssl `pkg-config --cflags --libs gtk+-3.0`

