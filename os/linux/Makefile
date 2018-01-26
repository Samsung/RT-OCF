.SUFFIXES : .c .o

CC = gcc

RT_OCF_ROOT = ../..
DEPEND_FILE = .depend
CSRCS =
include $(RT_OCF_ROOT)/Make.defs

LIBS = -pthread -lm
CFLAGS = $(INC) -g
CFLAGS += -DCONFIG_LIBC_NETDB

ifeq ($(MAKECMDGOALS), cov) 
	CFLAGS+=-fprofile-arcs -ftest-coverage
else ifdef WITH_COVERAGE
	CFLAGS+=-fprofile-arcs -ftest-coverage
endif

ARCHWARNINGS = -Wall -Werror -Wstrict-prototypes -Wshadow -Wundef \
	-Wno-implicit-function-declaration -Wno-unused-function \
	-Wno-unused-but-set-variable

CFLAGS += $(ARCHWARNINGS)

CMOCK_DIR=$(RT_OCF_ROOT)/extlibs/CMock
UNITY_DIR=$(CMOCK_DIR)/vendor/unity

UNITY_SRCS = $(UNITY_DIR)/src/unity.c \
	$(UNITY_DIR)/extras/fixture/src/unity_fixture.c \
	$(CMOCK_DIR)/src/cmock.c

INC += -I$(RT_OCF_ROOT)/os/linux \
    -I$(UNITY_DIR)/src \
	-I$(UNITY_DIR)/extras/fixture/src/ \
	-I$(CMOCK_DIR)/src

TEST_COMMON = $(wildcard $(RT_OCF_ROOT)/test/utils/*.c)
TEST_COMMON_INC = -I$(RT_OCF_ROOT)/test/include

MOCK_INC = -I$(RT_OCF_ROOT)/os/linux/mocks
MOCK_SRC = $(wildcard $(RT_OCF_ROOT)/os/linux/mocks/*.c)

OBJS =  $(notdir $(CSRCS:.c=.o))

LIB_NAME = libiotivity-rt.a

SAMPLE_MAIN = ctt_server \
	simple_client \
	simple_server

SETDEFS = $(shell ($(RT_OCF_ROOT)/tools/mkconfig . | sed -e 's/\"/\\\"/g' -e 's/\ /\\\ /g'))

CFLAGS += $(SETDEFS)

TEST_BINS = $(addprefix test/bin/,$(basename $(notdir $(TESTCASE_SRCS))))
TEST_OBJS =  $(notdir $(TESTCASE_SRCS:.c=.o))

all : dep $(LIB_NAME) $(SAMPLE_MAIN)

$(LIB_NAME) : .config $(OBJS)
	$(AR) rcv $@ $(OBJS)
	ranlib $@

menuconfig : distclean
	kconfig-mconf OCF_Kconfig

.config :
	$(error "Run 'make menuconfig' first. Exit")

dep :
	$(CC) -MM $(INC) $(MOCK_INC) $(CSRCS)  > $(DEPEND_FILE)

clean :
	rm -rf  $(OBJS) $(TESTGROUP_BIN) $(LIB_NAME) $(SAMPLE_MAIN) *.gcno *.gcda *.cov covhtml test $(TEST_OBJS)
	find $(RT_OCF_ROOT) -name '*.o' -exec rm -rf {} \;

test : testsetup $(TEST_BINS)
	for TEST_BIN in $(TEST_BINS) ; do \
		./$$TEST_BIN -v | tee $$TEST_BIN.result ; \
	done
	UNITY_DIR=$(UNITY_DIR) ruby ${RT_OCF_ROOT}/tools/internal/test_summary.rb

testsetup :
	mkdir -p test/bin
	cp $(TESTCASE_SRCS) test

testbinary : testsetup $(TEST_BINS)

$(TEST_BINS) : $(OBJS) $(TESTCASE_SRCS)
	$(CC) $(CFLAGS) $(TEST_COMMON_INC) $(MOCK_INC) -o $@ \
		./test/$(notdir $@).c $(shell ../../tools/find_mock_list.py ./test/$(notdir $@).c $(OBJS)) \
		$(UNITY_SRCS) $(TEST_COMMON) $(LIBS) -DUNITY_INCLUDE_DOUBLE

cov : clean testbinary
	for TEST_BIN in $(TEST_BINS) ; do \
		./$$TEST_BIN ; \
	done
	@lcov -c -d ./ -o $(abspath lcov.cov)
	@lcov -r $(abspath lcov.cov)  \*extlibs/\* \*mocks\* /usr/\* \*/test/\* \*/os/linux/\* --no-external -o $(abspath filtered-lcov.cov)
	@genhtml $(abspath filtered-lcov.cov) -o covhtml

new :
	$(MAKE) distclean
	$(MAKE)

$(SAMPLE_MAIN) :
	$(CC) $(CFLAGS) -o $@ sample/$@.c $(LIB_NAME) $(LIBS)

distclean: clean
	rm -rf $(DEPEND_FILE)

ifeq ($(DEPEND_FILE),$(wildcard $(DEPEND_FILE)))
-include $(DEPEND_FILE)
endif# DO NOT DELETE
