# Host unit tests (Ubuntu/Linux CI). Uses system OpenSSL, not iOS OpenSSL.
ROOT     := $(abspath ..)
SSTP     := $(ROOT)/sstp
CC       ?= gcc
CFLAGS   ?= -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-deprecated-declarations -O2
# Sources are compiled from $(BUILD)/ so quoted "sstp-private.h" resolves via -Istubs
# instead of picking up the real iOS/libevent private header next to sstp/*.c.
CPPFLAGS := -I. -Istubs -I$(SSTP) -DHAVE_CONFIG_H
LDFLAGS  ?=
LDLIBS_CRYPTO := -lcrypto

BUILD := build

HOST_SRCS := sstp-fcs.c sstp-buff.c sstp-util.c
HOST_OBJS := $(addprefix $(BUILD)/,$(HOST_SRCS:.c=.o))

.PHONY: all test clean

all: $(BUILD)/test_mschapv2 $(BUILD)/test_fcs $(BUILD)/test_buff $(BUILD)/test_url

$(BUILD):
	mkdir -p $(BUILD)

# Copy SSTP sources into build/ so #include "sstp-private.h" uses -Istubs.
$(BUILD)/%.c: $(SSTP)/%.c | $(BUILD)
	cp $< $@

$(BUILD)/%.o: $(BUILD)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BUILD)/test_mschapv2: test_mschapv2.c $(SSTP)/sstp-mschapv2.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_mschapv2.c $(SSTP)/sstp-mschapv2.c \
		$(LDFLAGS) $(LDLIBS_CRYPTO)

$(BUILD)/test_fcs: test_fcs.c $(BUILD)/sstp-fcs.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_fcs.c $(BUILD)/sstp-fcs.o $(LDFLAGS)

$(BUILD)/test_buff: test_buff.c $(BUILD)/sstp-buff.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_buff.c $(BUILD)/sstp-buff.o $(LDFLAGS)

$(BUILD)/test_url: test_url.c $(BUILD)/sstp-util.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ test_url.c $(BUILD)/sstp-util.o $(LDFLAGS)

test: all
	@fail=0; \
	for t in test_mschapv2 test_fcs test_buff test_url; do \
	  echo "==> $$t"; \
	  $(BUILD)/$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -rf $(BUILD)
