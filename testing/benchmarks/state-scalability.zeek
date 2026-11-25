module ICCP;

event zeek_init()
    {
    local configured = getenv("ICCP_STATE_BENCHMARK_ASSOCIATIONS");
    local association_count = configured == "" ?
        10000 : to_count(configured);
    local name_list: PendingNameList = [
        $object_class_choice=0, $object_class=2, $scope=0,
        $domain="", $continue_after=""
    ];

    local index: count = 0;
    local benchmark_uid = "";
    while ( index < association_count )
        {
        benchmark_uid = fmt("Cstate-benchmark-%d", index);
        pending_confirmed[benchmark_uid, T, 1] = [
            $service_tag=4, $operation=2, $request_is_orig=T
        ];
        update_directional_processing_state(
            benchmark_uid, T, 1, PROCESSING_PENDING_CONFIRMED, T);
        retain_name_list(benchmark_uid, T, 1, name_list);
        ++index;
        }

    local retained: count = 0;
    index = 0;
    while ( index < association_count )
        {
        benchmark_uid = fmt("Cstate-benchmark-%d", index);
        retained += pending_confirmed_count(benchmark_uid);
        retained += pending_name_list_count(benchmark_uid);
        ++index;
        }

    index = 0;
    while ( index < association_count )
        {
        benchmark_uid = fmt("Cstate-benchmark-%d", index);
        clear_confirmed_processing_state(benchmark_uid);
        clear_evidence_state(benchmark_uid);
        delete processing_state_indexes[benchmark_uid];
        ++index;
        }

    print fmt("associations=%d retained=%d processing_indexes=%d evidence_indexes=%d",
              association_count, retained, |processing_state_indexes|,
              |evidence_state_indexes|);
    }
