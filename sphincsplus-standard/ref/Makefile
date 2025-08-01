# PARAMS = sphincs-haraka-128s
# THASH = simple
# PARAMS = sphincs-haraka-128f
# THASH = robust
# PARAMS = sphincs-haraka-256f
# THASH = robust
# PARAMS = sphincs-sha2-192s
# THASH = simple

PARAMS = sphincs-sha2-256f
THASH = simple

CC=/usr/bin/gcc
CFLAGS=-Wall -g -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

SOURCES = address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c fprintbstr.c wots_forge.c extras.c
HEADERS = params.h address.h randombytes.h merkle.h wots.h wotsx1.h utils.h utilsx1.h fors.h api.h  hash.h thash.h context.h fprintbstr.h wots_forge.h extras.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += fips202.c hash_shake.c thash_shake_$(THASH).c
	HEADERS += fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += haraka.c hash_haraka.c thash_haraka_$(THASH).c
	HEADERS += haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += sha2.c hash_sha2.c thash_sha2_$(THASH).c
	HEADERS += sha2.h
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS =         test/fors \
		test/spx \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark


# default: forge
# all: forge
# forge: forge.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: forge_256f
# all: forge_256f
# forge_256f: forge_256f.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: forge_192s
# all: forge_192s
# forge_192s: forge_192s.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: forge_128f
# all: forge_128f
# forge_128f: forge_128f.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: sign_a_message
# all: sign_a_message
# sign_a_message: sign_a_message.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

default: sign_sha2_256f
all: sign_sha2_256f sign_sha2_256f_v2 
sign_sha2_256f: sign_sha2_256f.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto
sign_sha2_256f_v2: sign_sha2_256f_v2.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: make_results_each_layer
# all: make_results_each_layer
# make_results_each_layer: make_results_each_layer.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# default: sign_192s
# all: sign_192s
# sign_192s: sign_192s.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto


# default: test2
# all: test2
# test2: test2.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto


# default: rough
# all: rough
# rough: rough.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto



# default: rough_forR
# all: rough_forR
# rough_forR: rough_forR.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto


# default: sk_test
# all: sk_test
# sk_test: sk_test.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto



# default: PQCgenKAT_sign
# all: PQCgenKAT_sign tests benchmarks
# tests: $(TESTS)

# test: $(TESTS:=.exec)

# benchmarks: $(BENCHMARK)

# benchmark: $(BENCHMARK:=.exec)
# PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

# test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
# 	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

# test/%: test/%.c $(SOURCES) $(HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

# test/haraka: test/haraka.c $(filter-out haraka.c,$(SOURCES)) $(HEADERS)
# 	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(SOURCES)) $< $(LDLIBS)

# test/%.exec: test/%
# 	@$<


clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
	-$(RM) rough*.txt
	-$(RM) rough
	# -$(RM) sign_a_message
	-$(RM) sign_256	
