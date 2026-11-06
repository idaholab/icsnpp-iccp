# @TEST-DOC: Verify through the real TCP stack that an unknown MMS service is
# @TEST-DOC: bounded and unlabeled and a private object remains private/unknown.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap unknown.pcap unknown-service
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap private.pcap private-object
# @TEST-EXEC: mkdir unknown-run private-run
# @TEST-EXEC: cd unknown-run && zeek -Cr ../unknown.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: cd private-run && zeek -Cr ../private.pcap ${PACKAGE}/__load__.zeek
# @TEST-EXEC: zeek-cut layer message_type status operation service_tag object_name object_category name_model provenance < unknown-run/iccp.log > output
# @TEST-EXEC: zeek-cut layer message_type status operation service_tag object_name object_category name_model provenance < private-run/iccp.log >> output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: zeek-cut observation_kind association_kind operation object_scope object_domain object_name object_category name_model domain_kind provenance < private-run/iccp_objects.log > objects
# @TEST-EXEC: btest-diff objects
