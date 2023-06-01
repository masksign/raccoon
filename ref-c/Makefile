#	Makefile

XBIN	?=	xtest
CC		?=	gcc
CFLAGS	+=	-Iinc $(RACCF)
CFLAGS	+=	-Wall -Wextra -Ofast -march=native -fstack-usage
#	slower instrumentation flags
#CFLAGS	=	-Wall -Wextra -Wshadow -fsanitize=address,undefined -O2 -g 
#	options
#CFLAGS	+=	-DPOLYR_Q32
#CFLAGS	+=	-DMASK_RANDOM_ASCON
CSRC	+= 	$(wildcard *.c util/*.c)
OBJS	= 	$(CSRC:.c=.o)
SUFILES	= 	$(CSRC:.c=.su)
LDLIBS	+=

#	Standard Linux C compile
$(XBIN): $(OBJS)
	$(CC) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

%.o:	%.[cS]
	$(CC) $(CFLAGS) -c $^ -o $@

#	Cleanup
obj-clean:
	$(RM) -f $(XBIN) $(OBJS) $(SUFILES) nist/*.o nist/*.su

clean:	obj-clean
	$(RM) -f bench_*
	$(RM) -rf kat

