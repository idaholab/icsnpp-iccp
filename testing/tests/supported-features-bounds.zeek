# @TEST-DOC: Oversized or malformed Supported_Features values remain bounded
# @TEST-DOC: evidence and never reach bytestring_to_count as a wide integer.
#
# @TEST-EXEC: zeek -b ${PACKAGE}/__load__.zeek %INPUT > output
# @TEST-EXEC: btest-diff output

module ICCP;

event zeek_init() &priority=-5
    {
    print fmt("short valid=%s decoded=%s",
              supported_features_value_is_valid("\x04\xa0"),
              decode_supported_features("\x04\xa0"));
    print fmt("full valid=%s decoded=%s",
              supported_features_value_is_valid("\x04\xc0\x30"),
              decode_supported_features("\x04\xc0\x30"));
    print fmt("missing-block1 valid=%s decoded=%s",
              supported_features_value_is_valid("\x04\x20"),
              decode_supported_features("\x04\x20"));
    print fmt("unused-bits valid=%s decoded=%s",
              supported_features_value_is_valid("\x04\xa1"),
              decode_supported_features("\x04\xa1"));
    print fmt("oversized valid=%s decoded=%s",
              supported_features_value_is_valid(
                  "\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"),
              decode_supported_features(
                  "\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00"));
    }
