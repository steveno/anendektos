// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.


module parsers.dns;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;
import std.experimental.logger;

import parser;


class Dns : Parser {
    /**
     * Struct to hold the information for a line in dns log file.
     */
    struct Record {
        double ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        string proto;
        int trans_id;
        Nullable!(double) rtt;
        string query;
        int qclass;
        string qclass_name;
        int qtype;
        string qtype_name;
        int rcode;
        string rcode_name;
        bool AA;
        bool TC;
        bool RD;
        bool RA;
        int Z;
        string[] answers;
        double[] TTLs;
        bool rejected;
    };

    /**
     * Parse a dns log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = a dns log file to be parsed
     *
     * Returns: Generator expression which returns a Dns.Record struct.
     */
    public auto parse_file(Header header, File log_file) {
        int line_num = 0;
        auto range = log_file.byLine();
        return new Generator!(Record)({
            foreach (line; range) {
                string[] cur_line = strip(to!string(line)).split(header.seperator);
                line_num++;

                // Skip empty lines
                if (line == [] || startsWith(cur_line[0], "#"))
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
                    errorf("Processing on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.resp_h = parseAddress(cur_line[4]);
               
                try {
                    cur_record.resp_p = to!int(cur_line[5]);
                } catch (Exception e) {
                    errorf("Processing on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.proto = cur_line[6];

                try {
                    cur_record.trans_id = to!int(cur_line[7]);
                } catch (Exception e) {
                    errorf("Processing on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[8] != header.unset_field)
                    cur_record.rtt = to!double(cur_line[8]);

                cur_record.query = cur_line[9];
                
                try {
                    cur_record.qclass = to!int(cur_line[10]);
                } catch (Exception e) {
                    errorf("Processing on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.qclass_name = cur_line[11];

                try {
                    cur_record.qtype = to!int(cur_line[12]);
                } catch (Exception e) {
                    errorf("Processing on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.qtype_name = cur_line[13];

                if (cur_line[14] != header.unset_field) {
                    try {
                        cur_record.rcode = to!int(cur_line[14]);
                    } catch (Exception e) {
                        errorf("Processing on line %d: %s", line_num, e.msg);
                        continue;
                    }
                }

                cur_record.rcode_name = cur_line[15];

                if (cur_line[16] != header.unset_field) {
                    if (cur_line[16] == "F") {
                        cur_record.AA = false;
                    } else {
                        cur_record.AA = true;
                    }
                }

                if (cur_line[17] != header.unset_field) {
                    if (cur_line[17] == "F") {
                        cur_record.TC = false;
                    } else {
                        cur_record.TC = true;
                    }
                }

                if (cur_line[18] != header.unset_field) {
                    if (cur_line[18] == "F") {
                        cur_record.RD = false;
                    } else {
                        cur_record.RD = true;
                    }
                }

                if (cur_line[19] != header.unset_field) {
                    if (cur_line[19] == "F") {
                        cur_record.RA = false;
                    } else {
                        cur_record.RA = true;
                    }
                }

                try {
                    cur_record.Z = to!int(cur_line[20]);
                } catch (Exception e) {
                    errorf("Processing  on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[21] != header.unset_field)
                    cur_record.answers = cur_line[21].split(header.set_seperator);

                if (cur_line[22] != header.unset_field) {
                    cur_record.TTLs.length = cur_line[22].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[22].split(header.set_seperator).length) {
                        cur_record.TTLs[i] = to!double(cur_line[22].split(header.set_seperator)[i]);
                    }
                }

                if (cur_line[23] != header.unset_field) {
                    if (cur_line[23] == "F") {
                        cur_record.rejected = false;
                    } else {
                        cur_record.rejected = true;
                    }
                }

                yield(cur_record);
            }
        });
    }
}


version(unittest) {
    import unit_threaded;
    Parser.Header header;
    Dns.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/dns.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto dns_test = new Dns;

        auto gen = dns_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            Dns.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
    }

    @("dns_read_header")
    @safe unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "dns";
    }

    @("dns_record_count")
    @safe unittest
    {
        results.length.should == 4;
    }

    @("dns_read_record_1")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "COac2a2ZLGZJSbS2r5")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687175.438281;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 33136;
        results[entry].resp_h.toAddrString().should == "192.168.5.20";
        results[entry].resp_p.should == 53;
        results[entry].proto.should == "udp";
        results[entry].trans_id.should == 6396;
        results[entry].rtt.should == 0.016022;
        results[entry].query.should == "fakewebsite.net";
        results[entry].qclass.should == 1;
        results[entry].qclass_name.should == "C_INTERNET";
        results[entry].qtype.should == 1;
        results[entry].qtype_name.should == "A";
        results[entry].rcode.should == 0;
        results[entry].rcode_name.should == "NOERROR";
        results[entry].AA.should == true;
        results[entry].TC.should == false;
        results[entry].RD.should == true;
        results[entry].RA.should == true;
        results[entry].Z.should == 0;
        results[entry].answers.should == ["192.169.17.3"];
        results[entry].TTLs.should == [4.000000];
        results[entry].rejected.should == false;
    }

    @("dns_read_record_2")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CNjL5d4o5z2c92Dm9j")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687175.598301;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 54396;
        results[entry].resp_h.toAddrString().should == "192.168.5.20";
        results[entry].resp_p.should == 53;
        results[entry].proto.should == "udp";
        results[entry].trans_id.should == 55477;
        assert(results[entry].rtt.isNull);
        results[entry].query.should == "another_fakewebsite.org";
        results[entry].qclass.should == 1;
        results[entry].qclass_name.should == "C_INTERNET";
        results[entry].qtype.should == 28;
        results[entry].qtype_name.should == "AAAA";
        results[entry].rcode.should == 0;
        results[entry].rcode_name.should == "NOERROR";
        results[entry].AA.should == false;
        results[entry].TC.should == true;
        results[entry].RD.should == true;
        results[entry].RA.should == false;
        results[entry].Z.should == 0;
        results[entry].answers.shouldBeEmpty();
        results[entry].TTLs.shouldBeEmpty();
        results[entry].rejected.should == false;
    }

    @("dns_read_record_3")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "Ck8RXy3A5mMYpuaMPl")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687177.554304;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 54580;
        results[entry].resp_h.toAddrString().should == "192.168.5.20";
        results[entry].resp_p.should == 53;
        results[entry].proto.should == "udp";
        results[entry].trans_id.should == 53805;
        results[entry].rtt.should == 0.015983;
        results[entry].query.should == "doesnotexist.com";
        results[entry].qclass.should == 1;
        results[entry].qclass_name.should == "C_INTERNET";
        results[entry].qtype.should == 28;
        results[entry].qtype_name.should == "AAAA";
        results[entry].rcode.should == 0;
        results[entry].rcode_name.should == "NOERROR";
        results[entry].AA.should == false;
        results[entry].TC.should == false;
        results[entry].RD.should == false;
        results[entry].RA.should == true;
        results[entry].Z.should == 0;
        results[entry].answers.should == ["services.fake.com"];
        results[entry].TTLs.should == [28.000000];
        results[entry].rejected.should == false;
    }

    @("dns_read_record_4")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CQPWD5kcGNGECLpQe")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687177.886294;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 43739;
        results[entry].resp_h.toAddrString().should == "192.168.5.20";
        results[entry].resp_p.should == 53;
        results[entry].proto.should == "udp";
        results[entry].trans_id.should == 1917;
        assert(results[entry].rtt.isNull);
        results[entry].query.should == "imageoninternet.net";
        results[entry].qclass.should == 1;
        results[entry].qclass_name.should == "C_INTERNET";
        results[entry].qtype.should == 28;
        results[entry].qtype_name.should == "AAAA";
        results[entry].rcode.should == 0;
        results[entry].rcode_name.should == "NOERROR";
        results[entry].AA.should == false;
        results[entry].TC.should == false;
        results[entry].RD.should == true;
        results[entry].RA.should == false;
        results[entry].Z.should == 0;
        results[entry].answers.shouldBeEmpty();
        results[entry].TTLs.shouldBeEmpty();
        results[entry].rejected.should == true;
    }
}
