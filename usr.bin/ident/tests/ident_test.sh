# $FreeBSD: releng/12.0/usr.bin/ident/tests/ident_test.sh 315776 2017-03-23 03:28:24Z ngie $

atf_test_case ident
ident_body() {
	atf_check -o file:$(atf_get_srcdir)/test.out \
		ident < $(atf_get_srcdir)/test.in
	atf_check -o match:'Foo.*' -s exit:1 \
		-e inline:"ident warning: no id keywords in $(atf_get_srcdir)/testnoid\n" \
		ident $(atf_get_srcdir)/test.in $(atf_get_srcdir)/testnoid
	atf_check -o match:'Foo.*' -s exit:1 \
		ident -q $(atf_get_srcdir)/test.in $(atf_get_srcdir)/testnoid
}
atf_init_test_cases()
{
	atf_add_test_case ident
}
