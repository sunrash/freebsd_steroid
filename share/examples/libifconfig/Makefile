# $FreeBSD: releng/12.0/share/examples/libifconfig/Makefile 329853 2018-02-23 03:11:43Z asomers $
default:
	$(CC) -Wall -fPIC -lifconfig -g -o example_setdescription setdescription.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_setmtu setmtu.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_ifdestroy ifdestroy.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_ifcreate ifcreate.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_ifcreatevlan ifcreatevlan.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_ifchanagevlan ifchanagevlan.c
	$(CC) -Wall -fPIC -lifconfig -g -o example_status status.c
clean:
	rm -f example_*
