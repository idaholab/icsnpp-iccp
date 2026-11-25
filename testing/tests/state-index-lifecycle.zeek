# @TEST-DOC: Per-association state indexes keep counts isolated, do not grow
# @TEST-DOC: on invoke reuse, and retire indexed state on connection cleanup
# @TEST-DOC: while active learned state survives beyond the association timeout.
#
# @TEST-EXEC: bash ${SCRIPTS}/generate-synthetic-pcap input.pcap initiate > /dev/null
# @TEST-EXEC: zeek -b -Cr input.pcap ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

redef association_state_timeout = 1msec;
redef table_expire_interval = 1msec;
redef table_expire_delay = 0secs;

global inspect_removed_state: event(first: connection, second: connection);

function indexed_connection(uid: string, orig_port: port): connection
    {
    return [
        $id=[$orig_h=192.0.2.10, $orig_p=orig_port,
             $resp_h=192.0.2.20, $resp_p=102/tcp],
        $orig=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $resp=[$size=0, $state=TCP_ESTABLISHED, $flow_label=0],
        $start_time=network_time(), $duration=0secs,
        $service=set("iccp"), $history="", $uid=uid
    ];
    }

function seed_indexed_state(c: connection, invoke: count)
    {
    pending_confirmed[c$uid, T, invoke] = [
        $service_tag=4, $operation=2, $request_is_orig=T
    ];
    update_directional_processing_state(
        c$uid, T, invoke, PROCESSING_PENDING_CONFIRMED, T);

    local name_list: PendingNameList = [
        $object_class_choice=0, $object_class=2, $scope=0,
        $domain="", $continue_after=""
    ];
    retain_name_list(c$uid, T, invoke, name_list);

    known_variable_types[c$uid, F, 0, "", "INDEXED_POINT"] =
        "Data_Discrete";
    update_object_processing_state(
        c$uid, F, 0, "", "INDEXED_POINT",
        PROCESSING_KNOWN_VARIABLE_TYPE, T);
    }

function print_indexed_counts(c: connection, label: string)
    {
    print fmt("%s confirmed=%d names=%d known_types=%d",
              label, pending_confirmed_count(c$uid),
              pending_name_list_count(c$uid),
              known_variable_type_count(c$uid));
    }

event inspect_removed_state(first: connection, second: connection)
    {
    print_indexed_counts(first, "removed");
    print_indexed_counts(second, "retained");
    print fmt("removed tables confirmed=%s names=%s known_type=%s",
              [first$uid, T, 7] in pending_confirmed,
              [first$uid, T, 7] in pending_name_lists,
              [first$uid, F, 0, "", "INDEXED_POINT"] in
                  known_variable_types);

    }

event zeek_done()
    {
    local uid = "Cstate-expiring";
    local retained = indexed_connection(uid, 49154/tcp);
    print fmt("retained indexes processing=%s evidence=%s",
              uid in processing_state_indexes,
              uid in evidence_state_indexes);
    print fmt("retained tables confirmed=%s names=%s known_type=%s learned=%s",
              [uid, T, 9] in pending_confirmed,
              [uid, T, 9] in pending_name_lists,
              [uid, F, 0, "", "INDEXED_POINT"] in
                  known_variable_types,
              learned_variable_type_name(
                  retained, F, 0, "", "INDEXED_POINT"));
    }

event zeek_init()
    {
    local first = indexed_connection("Cstate-first", 49152/tcp);
    local second = indexed_connection("Cstate-second", 49153/tcp);
    local expiring = indexed_connection("Cstate-expiring", 49154/tcp);
    seed_indexed_state(first, 7);
    seed_indexed_state(second, 7);
    seed_indexed_state(expiring, 9);
    print_indexed_counts(first, "seeded-first");
    print_indexed_counts(second, "seeded-second");

    seed_indexed_state(first, 7);
    print_indexed_counts(first, "invoke-reused");
    print_indexed_counts(expiring, "retention-seeded");

    event connection_state_remove(first);
    schedule 1msec { inspect_removed_state(first, second) };
    }
