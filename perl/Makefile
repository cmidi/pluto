#
# Define some Makefile variables for the compiler and compiler flags
# to use Makefile variables later in the Makefile: $()
#
#  -g    adds debugging information to the executable file
#  -Wall turns on most, but not all, compiler warnings
#
CC = gcc
CFLAGS  = -g -Wall -lpcap -lpthread

# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
#
default: sd_listener

# Create sd_listener executable and change group and permissions.
sd_listener:    sd_listener.o
		$(CC) $(CFLAGS) -o sd_listener sd_listener.o
	   	sudo chown root:root sd_listener
		sudo chmod 6755 sd_listener

# To create the object file sd_listener.o, we need the source
# files sd_listener.c:
#
sd_listener.o:  sd_listener.c
		$(CC) $(CFLAGS) -c sd_listener.c

# To start over from scratch, type 'make clean'.  This
# removes the executable file, as well as old .o object
# files and *~ backup files:
#
clean:
		rm -f count *.o *~
		rm -f sd_listener

