# $FreeBSD: releng/12.0/tools/tools/locale/tools/extract-colldef.awk 310198 2016-12-18 02:02:33Z bapt $

BEGIN {
	print "# Warning: Do not edit. This is automatically extracted"
	print "# from CLDR project data, obtained from http://cldr.unicode.org/"
	print "# -----------------------------------------------------------------------------"
}
$1 == "comment_char" { print }
$1 == "escape_char" { print }
$1 == "LC_COLLATE" { doprint = 1 }
doprint == 1 { print }
$1 == "END" && $2 == "LC_COLLATE" { exit 0 }
