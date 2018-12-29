// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.


module parsers.dns;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class Dns : Parser {
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
            cur_record.trans_id = to!int(line[7]);

            if (line[8] != header.unset_field)
                cur_record.rtt = to!double(line[8]);

            cur_record.query = line[9];
            cur_record.qclass = to!int(line[10]);
            cur_record.qclass_name = line[11];
            cur_record.qtype = to!int(line[12]);
            cur_record.qtype_name = line[13];
            cur_record.rcode = to!int(line[14]);
            cur_record.rcode_name = line[15];

            // Convert 0 and 1 to bool
            if (line[16] != header.unset_field) {
                if (line[16] == "F") {
                    cur_record.AA = false;
                } else {
                    cur_record.AA = true;
                }
            }

            if (line[17] != header.unset_field) {
                if (line[17] == "F") {
                    cur_record.TC = false;
                } else {
                    cur_record.TC = true;
                }
            }

            if (line[18] != header.unset_field) {
                if (line[18] == "F") {
                    cur_record.RD = false;
                } else {
                    cur_record.RD = true;
                }
            }

            if (line[19] != header.unset_field) {
                if (line[19] == "F") {
                    cur_record.RA = false;
                } else {
                    cur_record.RA = true;
                }
            }

            cur_record.Z = to!int(line[20]);

            if (line[21] != header.unset_field)
                cur_record.answers = line[21].split(header.set_seperator);

            if (line[22] != header.unset_field) {
                cur_record.TTLs.length = line[22].split(header.set_seperator).length;
                foreach (i; 0 .. line[22].split(header.set_seperator).length) {
                    cur_record.TTLs[i] = to!double(line[22].split(header.set_seperator)[i]);
                }
            }

            if (line[23] != header.unset_field) {
                if (line[23] == "F") {
                    cur_record.rejected = false;
                } else {
                    cur_record.rejected = true;
                }
            }

            ++rec_num;
            contents[rec_num] = cur_record;
        }

        return contents;
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
        results = dns_test.parse_file(header, file);
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
        results[1].ts.should == 1531687175.438281;
        results[1].uid.should == "COac2a2ZLGZJSbS2r5";
        results[1].orig_h.toAddrString().should == "10.0.0.2";
        results[1].orig_p.should == 33136;
        results[1].resp_h.toAddrString().should == "192.168.5.20";
        results[1].resp_p.should == 53;
        results[1].proto.should == "udp";
        results[1].trans_id.should == 6396;
        results[1].rtt.should == 0.016022;
        results[1].query.should == "fakewebsite.net";
        results[1].qclass.should == 1;
        results[1].qclass_name.should == "C_INTERNET";
        results[1].qtype.should == 1;
        results[1].qtype_name.should == "A";
        results[1].rcode.should == 0;
        results[1].rcode_name.should == "NOERROR";
        results[1].AA.should == false;
        results[1].TC.should == false;
        results[1].RD.should == true;
        results[1].RA.should == true;
        results[1].Z.should == 0;
        results[1].answers.should == ["192.169.17.3"];
        results[1].TTLs.should == [4.000000];
        results[1].rejected.should == false;
    }

    @("dns_read_record_2")
    @safe unittest
    {
        results[2].ts.should == 1531687175.598301;
        results[2].uid.should == "CNjL5d4o5z2c92Dm9j";
        results[2].orig_h.toAddrString().should == "10.0.0.2";
        results[2].orig_p.should == 54396;
        results[2].resp_h.toAddrString().should == "192.168.5.20";
        results[2].resp_p.should == 53;
        results[2].proto.should == "udp";
        results[2].trans_id.should == 55477;
        assert(results[2].rtt.isNull);
        results[2].query.should == "another_fakewebsite.org";
        results[2].qclass.should == 1;
        results[2].qclass_name.should == "C_INTERNET";
        results[2].qtype.should == 28;
        results[2].qtype_name.should == "AAAA";
        results[2].rcode.should == 0;
        results[2].rcode_name.should == "NOERROR";
        results[2].AA.should == false;
        results[2].TC.should == false;
        results[2].RD.should == true;
        results[2].RA.should == false;
        results[2].Z.should == 0;
        results[2].answers.shouldBeEmpty();
        results[2].TTLs.shouldBeEmpty();
        results[2].rejected.should == false;
    }

    @("dns_read_record_3")
    @safe unittest
    {
        results[3].ts.should == 1531687177.554304;
        results[3].uid.should == "Ck8RXy3A5mMYpuaMPl";
        results[3].orig_h.toAddrString().should == "10.0.0.2";
        results[3].orig_p.should == 54580;
        results[3].resp_h.toAddrString().should == "192.168.5.20";
        results[3].resp_p.should == 53;
        results[3].proto.should == "udp";
        results[3].trans_id.should == 53805;
        results[3].rtt.should == 0.015983;
        results[3].query.should == "doesnotexist.com";
        results[3].qclass.should == 1;
        results[3].qclass_name.should == "C_INTERNET";
        results[3].qtype.should == 28;
        results[3].qtype_name.should == "AAAA";
        results[3].rcode.should == 0;
        results[3].rcode_name.should == "NOERROR";
        results[3].AA.should == false;
        results[3].TC.should == false;
        results[3].RD.should == true;
        results[3].RA.should == true;
        results[3].Z.should == 0;
        results[3].answers.should == ["services.fake.com"];
        results[3].TTLs.should == [28.000000];
        results[3].rejected.should == false;
    }

    @("dns_read_record_4")
    @safe unittest
    {
        results[4].ts.should == 1531687177.886294;
        results[4].uid.should == "CQPWD5kcGNGECLpQe";
        results[4].orig_h.toAddrString().should == "10.0.0.2";
        results[4].orig_p.should == 43739;
        results[4].resp_h.toAddrString().should == "192.168.5.20";
        results[4].resp_p.should == 53;
        results[4].proto.should == "udp";
        results[4].trans_id.should == 1917;
        assert(results[4].rtt.isNull);
        results[4].query.should == "imageoninternet.net";
        results[4].qclass.should == 1;
        results[4].qclass_name.should == "C_INTERNET";
        results[4].qtype.should == 28;
        results[4].qtype_name.should == "AAAA";
        results[4].rcode.should == 0;
        results[4].rcode_name.should == "NOERROR";
        results[4].AA.should == false;
        results[4].TC.should == false;
        results[4].RD.should == true;
        results[4].RA.should == false;
        results[4].Z.should == 0;
        results[4].answers.shouldBeEmpty();
        results[4].TTLs.shouldBeEmpty();
        results[4].rejected.should == false;
    }
}
