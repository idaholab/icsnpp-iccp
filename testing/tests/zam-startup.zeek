# @TEST-DOC: Verify that loading the ICCP package with ZAM optimization
# @TEST-DOC: completes within a bounded startup interval.
#
# @TEST-EXEC: timeout --kill-after=5s 60s zeek -O ZAM ${PACKAGE}/__load__.zeek /dev/null
