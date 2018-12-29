// This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.conn;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class Conn : Parser {
    struct Record {
        double ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        string proto;
        string service;
        double duration;
        int orig_bytes;
        int resp_bytes;
        string conn_state;
        Nullable!(bool) local_orig;
        Nullable!(bool) local_resp;
        int missed_bytes;
        string history;
        int orig_pkts;
        int orig_ip_bytes;
        int resp_pkts;
        int resp_ip_bytes;
        string[] tunnel_parents;
    };

    public Record[int] parse_file(Header header, File log_file) {
        Record[int] contents;
        int rec_num = 0;
        string[] line;

        while (!log_file.eof()) {
            line = strip(log_file.readln()).split(header.seperator);

            // Skip empty lines
            if (line == [] || startsWith(line[0], "#"))
                continue;

            // Populate our record
            Record cur_record;
            cur_record.ts = to!double(line[0]);
            cur_record.uid = line[1];
            cur_record.orig_h = parseAddress(line[2]);
            cur_record.orig_p = to!int(line[3]);
            cur_record.resp_h = parseAddress(line[4]);
            cur_record.resp_p = to!int(line[5]);
            cur_record.proto = line[6];

            if (line[7] != header.unset_field)
                cur_record.service = line[7];

            cur_record.duration = to!double(line[8]);
            cur_record.orig_bytes = to!int(line[9]);
            cur_record.resp_bytes = to!int(line[10]);
            cur_record.conn_state = line[11];

            // Convert 0 and 1 to bool
            if (line[12] != header.unset_field) {
                if (line[12] == "0") {
                    cur_record.local_orig = false;
                } else {
                    cur_record.local_orig = true;
                }

            }

            if (line[13] != header.unset_field) {
                if (line[13] == "0") {
                    cur_record.local_resp = false;
                } else {
                    cur_record.local_resp = true;
                }
            }

            cur_record.missed_bytes = to!int(line[14]);

            if (line[15] != header.unset_field) {
                cur_record.history = line[15];
            }

            cur_record.orig_pkts = to!int(line[16]);
            cur_record.orig_ip_bytes = to!int(line[17]);
            cur_record.resp_pkts = to!int(line[18]);
            cur_record.resp_ip_bytes = to!int(line[19]);

            if (line[20] != header.empty_field)
                cur_record.tunnel_parents = line[20].split(header.set_seperator);

            ++rec_num;
            contents[rec_num] = cur_record;
        }

        return contents;
    }
}


version(unittest) {
    import unit_threaded;
    Parser.Header header;
    Conn.Record[int] results;

    @Setup 
    void before() {
        File file = File("tests/logs/conn.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto conn_test = new Conn;
        results = conn_test.parse_file(header, file);
    }

    @("conn_read_header")
    @safe unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
    }

    @("conn_record_count")
    @safe unittest
    {
        results.length.should == 6;
    }

    @("conn_read_record_1")
    @safe unittest
    {
        results[1].ts.should == 1531687176.789848;
        results[1].uid.should == "CI3wQF1KHxU6G7VmTj";
        results[1].orig_h.toAddrString().should == "10.0.0.2";
        results[1].orig_p.should == 60716;
        results[1].resp_h.toAddrString().should == "192.168.1.4";
        results[1].resp_p.should == 443;
        results[1].proto.should == "tcp";
        results[1].service.should == null;
        results[1].duration.should == 0.170522;
        results[1].orig_bytes.should == 1859;
        results[1].resp_bytes.should == 524;
        results[1].conn_state.should == "RSTRH";
        assert(results[1].local_orig.isNull);
        assert(results[1].local_resp.isNull);
        results[1].missed_bytes.should == 0;
        results[1].history.should == "^dADar";
        results[1].orig_pkts.should == 4;
        results[1].orig_ip_bytes.should == 2498;
        results[1].resp_pkts.should == 3;
        results[1].resp_ip_bytes.should == 668;
        results[1].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_2")
    @safe unittest
    {
        results[2].ts.should == 1531687179.369649;
        results[2].uid.should == "CseN5l3TT2T9wz29gd";
        results[2].orig_h.toAddrString().should == "10.0.0.2";
        results[2].orig_p.should == 49228;
        results[2].resp_h.toAddrString().should == "192.168.8.2";
        results[2].resp_p.should == 443;
        results[2].proto.should == "tcp";
        results[2].service.should == "ssl";
        results[2].duration.should == 5.226249;
        results[2].orig_bytes.should == 636;
        results[2].resp_bytes.should == 191;
        results[2].conn_state.should == "SF";
        assert(results[2].local_orig.isNull);
        assert(results[2].local_resp.isNull);
        results[2].missed_bytes.should == 0;
        results[2].history.should == "ShADadFRfR";
        results[2].orig_pkts.should == 10;
        results[2].orig_ip_bytes.should == 1128;
        results[2].resp_pkts.should == 8;
        results[2].resp_ip_bytes.should == 615;
        results[2].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_3")
    @safe unittest
    {
        results[3].ts.should == 1531687180.264430;
        results[3].uid.should == "CF9cy31JmjzAbGWlXb";
        results[3].orig_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[3].orig_p.should == 48804;
        results[3].resp_h.toAddrString().should == "fe80:f8b0:4004:805::200e";
        results[3].resp_p.should == 443;
        results[3].proto.should == "tcp";
        results[3].service.should == null;
        results[3].duration.should == 16.770906;
        results[3].orig_bytes.should == 16375;
        results[3].resp_bytes.should == 728861;
        results[3].conn_state.should == "OTH";
        assert(results[3].local_orig.isNull);
        assert(results[3].local_resp.isNull);
        results[3].missed_bytes.should == 0;
        results[3].history.should == "DadAc";
        results[3].orig_pkts.should == 194;
        results[3].orig_ip_bytes.should == 30355;
        results[3].resp_pkts.should == 221;
        results[3].resp_ip_bytes.should == 524307;
        results[3].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_4")
    @safe unittest
    {
        results[4].ts.should == 1531687185.282211;
        results[4].uid.should == "CuVIzg2991yFw6ZZl";
        results[4].orig_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[4].orig_p.should == 45548;
        results[4].resp_h.toAddrString().should == "fe80:f8b0:4004:805::200e";
        results[4].resp_p.should == 80;
        results[4].proto.should == "tcp";
        results[4].service.should == "http";
        results[4].duration.should == 10.129878;
        results[4].orig_bytes.should == 435;
        results[4].resp_bytes.should == 705;
        results[4].conn_state.should == "S1";
        assert(results[4].local_orig.isNull);
        assert(results[4].local_resp.isNull);
        results[4].missed_bytes.should == 0;
        results[4].history.should == "ShADad";
        results[4].orig_pkts.should == 5;
        results[4].orig_ip_bytes.should == 803;
        results[4].resp_pkts.should == 4;
        results[4].resp_ip_bytes.should == 1001;
        results[4].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_5")
    @safe unittest
    {
        results[5].ts.should == 1531687174.944154;
        results[5].uid.should == "CTs6Ib3G1SsnrfuJak";
        results[5].orig_h.toAddrString().should == "fe80::250:f1ff:fe80:0";
        results[5].orig_p.should == 134;
        results[5].resp_h.toAddrString().should == "fe80::1";
        results[5].resp_p.should == 133;
        results[5].proto.should == "icmp";
        results[5].service.should == null;
        results[5].duration.should == 24.268761;
        results[5].orig_bytes.should == 896;
        results[5].resp_bytes.should == 0;
        results[5].conn_state.should == "OTH";
        assert(results[5].local_orig.isNull);
        assert(results[5].local_resp.isNull);
        results[5].missed_bytes.should == 0;
        results[5].history.should == null;
        results[5].orig_pkts.should == 8;
        results[5].orig_ip_bytes.should == 1280;
        results[5].resp_pkts.should == 0;
        results[5].resp_ip_bytes.should == 0;
        results[5].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_6")
    @safe unittest
    {
        results[6].ts.should == 1531687188.273921;
        results[6].uid.should == "Cjo73l2bKMuyYcFUH";
        results[6].orig_h.toAddrString().should == "fe80::250:f1ff:fe80:0";
        results[6].orig_p.should == 135;
        results[6].resp_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[6].resp_p.should == 136;
        results[6].proto.should == "icmp";
        results[6].service.should == null;
        results[6].duration.should == 0.000027;
        results[6].orig_bytes.should == 24;
        results[6].resp_bytes.should == 16;
        results[6].conn_state.should == "OTH";
        assert(results[6].local_orig.isNull);
        assert(results[6].local_resp.isNull);
        results[6].missed_bytes.should == 0;
        results[6].history.should == null;
        results[6].orig_pkts.should == 1;
        results[6].orig_ip_bytes.should == 72;
        results[6].resp_pkts.should == 1;
        results[6].resp_ip_bytes.should == 64;
        results[6].tunnel_parents.shouldBeEmpty();
    }
}
