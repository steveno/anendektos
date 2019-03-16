// This Source Code Form is subject to the terms of the Mozilla Public
//  License, v. 2.0. If a copy of the MPL was not distributed with this
//  file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.conn;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;
import std.experimental.logger;

import parser;


/**
 * Conn object to parse conn log files
 */
class Conn : Parser {
    /**
     * Struct to hold the information for a line in conn log file.
     */
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

    /**
     * Parse a conn log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = a conn log file to be parsed
     *
     * Returns: Generator expression which returns Conn.Record struct.
     */
    public auto parse_file(Header header, File log_file) {
        int line_num = 0;
        auto range = log_file.byLine();
        return new Generator!(Record)({
            foreach (line; range) {
                string[] cur_line = strip(to!string(line)).split(header.seperator);
                line_num++;

                // Skip empty lines
                if (cur_line == [] || startsWith(cur_line[0], "#"))
                    continue;

                // Populate our record
                Record cur_record;

                try {
                    cur_record.ts = to!double(cur_line[0]);
                } catch (Exception e) {
                    errorf("Processing ts on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.uid = cur_line[1];
                cur_record.orig_h = parseAddress(cur_line[2]);

                try {
                    cur_record.orig_p = to!int(cur_line[3]);
                } catch (Exception e) {
                    errorf("Processing orig_p on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.resp_h = parseAddress(cur_line[4]);

                try {
                    cur_record.resp_p = to!int(cur_line[5]);
                } catch (Exception e) {
                    errorf("Processing resp_p on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.proto = cur_line[6];

                if (cur_line[7] != header.unset_field)
                    cur_record.service = cur_line[7];

                if (cur_line[8] != header.unset_field) {
                    try {
                        cur_record.duration = to!double(cur_line[8]);
                    } catch (Exception e) {
                        errorf("Processing duration on line %d: %s", line_num, e.msg);
                        continue;
                    }
                }

                if (cur_line[9] != header.unset_field) {
                    try {
                        cur_record.orig_bytes = to!int(cur_line[9]);
                    } catch (Exception e) {
                        errorf("Processing orig_bytes on line %d: %s", line_num, e.msg);
                        continue;
                    }
                }

                if (cur_line[10] != header.unset_field) {
                    try {
                        cur_record.resp_bytes = to!int(cur_line[10]);
                    } catch (Exception e) {
                        errorf("Processing resp_bytes on line %d: %s", line_num, e.msg);
                        continue;
                    }
                }

                cur_record.conn_state = cur_line[11];

                // Convert 0 and 1 to bool
                if (cur_line[12] != header.unset_field) {
                    if (cur_line[12] == "0") {
                        cur_record.local_orig = false;
                    } else {
                        cur_record.local_orig = true;
                    }

                }

                if (cur_line[13] != header.unset_field) {
                    if (cur_line[13] == "0") {
                        cur_record.local_resp = false;
                    } else {
                        cur_record.local_resp = true;
                    }
                }

                try {
                    cur_record.missed_bytes = to!int(cur_line[14]);
                } catch (Exception e) {
                    errorf("Processing missed_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[15] != header.unset_field) {
                    cur_record.history = cur_line[15];
                }


                try {
                    cur_record.orig_pkts = to!int(cur_line[16]);
                } catch (Exception e) {
                    errorf("Processing orig_pkts on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.orig_ip_bytes = to!int(cur_line[17]);
                } catch (Exception e) {
                    errorf("Processing orig_ip_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.resp_pkts = to!int(cur_line[18]);
                } catch (Exception e) {
                    errorf("Processing resp_pkts on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.resp_ip_bytes = to!int(cur_line[19]);
                } catch (Exception e) {
                    errorf("Processing resp_ip_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[20] != header.empty_field)
                    cur_record.tunnel_parents = cur_line[20].split(header.set_seperator);

                yield(cur_record);
            }
        });
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

        auto gen = conn_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            Conn.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
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
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CI3wQF1KHxU6G7VmTj")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687176.789848;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 60716;
        results[entry].resp_h.toAddrString().should == "192.168.1.4";
        results[entry].resp_p.should == 443;
        results[entry].proto.should == "tcp";
        results[entry].service.should == null;
        results[entry].duration.should == 0.170522;
        results[entry].orig_bytes.should == 1859;
        results[entry].resp_bytes.should == 524;
        results[entry].conn_state.should == "RSTRH";
        assert(results[entry].local_orig.isNull);
        assert(results[entry].local_resp.isNull);
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == "^dADar";
        results[entry].orig_pkts.should == 4;
        results[entry].orig_ip_bytes.should == 2498;
        results[entry].resp_pkts.should == 3;
        results[entry].resp_ip_bytes.should == 668;
        results[entry].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_2")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CseN5l3TT2T9wz29gd")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687179.369649;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 49228;
        results[entry].resp_h.toAddrString().should == "192.168.8.2";
        results[entry].resp_p.should == 443;
        results[entry].proto.should == "tcp";
        results[entry].service.should == "ssl";
        results[entry].duration.should == 5.226249;
        results[entry].orig_bytes.should == 636;
        results[entry].resp_bytes.should == 191;
        results[entry].conn_state.should == "SF";
        results[entry].local_orig.should == true;
        assert(results[entry].local_resp.isNull);
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == "ShADadFRfR";
        results[entry].orig_pkts.should == 10;
        results[entry].orig_ip_bytes.should == 1128;
        results[entry].resp_pkts.should == 8;
        results[entry].resp_ip_bytes.should == 615;
        results[entry].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_3")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CF9cy31JmjzAbGWlXb")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687180.264430;
        results[entry].orig_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[entry].orig_p.should == 48804;
        results[entry].resp_h.toAddrString().should == "fe80:f8b0:4004:805::200e";
        results[entry].resp_p.should == 443;
        results[entry].proto.should == "tcp";
        results[entry].service.should == null;
        results[entry].duration.should == 16.770906;
        results[entry].orig_bytes.should == 16375;
        results[entry].resp_bytes.should == 728861;
        results[entry].conn_state.should == "OTH";
        results[entry].local_orig.should == false;
        assert(results[entry].local_resp.isNull);
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == "DadAc";
        results[entry].orig_pkts.should == 194;
        results[entry].orig_ip_bytes.should == 30355;
        results[entry].resp_pkts.should == 221;
        results[entry].resp_ip_bytes.should == 524307;
        results[entry].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_4")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CuVIzg2991yFw6ZZl")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687185.282211;
        results[entry].orig_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[entry].orig_p.should == 45548;
        results[entry].resp_h.toAddrString().should == "fe80:f8b0:4004:805::200e";
        results[entry].resp_p.should == 80;
        results[entry].proto.should == "tcp";
        results[entry].service.should == "http";
        results[entry].duration.should == 10.129878;
        results[entry].orig_bytes.should == 435;
        results[entry].resp_bytes.should == 705;
        results[entry].conn_state.should == "S1";
        assert(results[entry].local_orig.isNull);
        results[entry].local_resp.should == true;
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == "ShADad";
        results[entry].orig_pkts.should == 5;
        results[entry].orig_ip_bytes.should == 803;
        results[entry].resp_pkts.should == 4;
        results[entry].resp_ip_bytes.should == 1001;
        results[entry].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_5")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CTs6Ib3G1SsnrfuJak")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687174.944154;
        results[entry].orig_h.toAddrString().should == "fe80::250:f1ff:fe80:0";
        results[entry].orig_p.should == 134;
        results[entry].resp_h.toAddrString().should == "fe80::1";
        results[entry].resp_p.should == 133;
        results[entry].proto.should == "icmp";
        results[entry].service.should == null;
        results[entry].duration.should == 24.268761;
        results[entry].orig_bytes.should == 896;
        results[entry].resp_bytes.should == 0;
        results[entry].conn_state.should == "OTH";
        assert(results[entry].local_orig.isNull);
        results[entry].local_resp.should == false;
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == null;
        results[entry].orig_pkts.should == 8;
        results[entry].orig_ip_bytes.should == 1280;
        results[entry].resp_pkts.should == 0;
        results[entry].resp_ip_bytes.should == 0;
        results[entry].tunnel_parents.shouldBeEmpty();
    }

    @("conn_read_record_6")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "Cjo73l2bKMuyYcFUH")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687188.273921;
        results[entry].orig_h.toAddrString().should == "fe80::250:f1ff:fe80:0";
        results[entry].orig_p.should == 135;
        results[entry].resp_h.toAddrString().should == "fe80:541:4303:db20:9db7:490b:983b:62ca";
        results[entry].resp_p.should == 136;
        results[entry].proto.should == "icmp";
        results[entry].service.should == null;
        results[entry].duration.should == 0.000027;
        results[entry].orig_bytes.should == 24;
        results[entry].resp_bytes.should == 16;
        results[entry].conn_state.should == "OTH";
        assert(results[entry].local_orig.isNull);
        assert(results[entry].local_resp.isNull);
        results[entry].missed_bytes.should == 0;
        results[entry].history.should == null;
        results[entry].orig_pkts.should == 1;
        results[entry].orig_ip_bytes.should == 72;
        results[entry].resp_pkts.should == 1;
        results[entry].resp_ip_bytes.should == 64;
        results[entry].tunnel_parents.shouldBeEmpty();
    }
}
