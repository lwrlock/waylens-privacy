CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE

.PHONY: all test clean

all: waylens-probe

waylens-probe: src/native/vault_sensor.c
	$(CC) $(CFLAGS) -o $@ $<

test: all
	/usr/bin/python3 -m py_compile src/waylens/*.py
	./waylens-probe --json >/dev/null
	PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v

clean:
	rm -f waylens-probe
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
