/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

module parsers.dns;

import std.conv;
import std.socket;
import std.stdio;
import std.string;

import parser;


class Dns : Parser {
    struct Record {
        float ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        string proto;
        string trans_id;
        float rtt;
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
        float[] TTLs;
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
            cur_record.ts = to!float(line[0]);
            cur_record.uid = line[1];
            cur_record.orig_h = parseAddress(line[2]);
            cur_record.orig_p = to!int(line[3]);
            cur_record.resp_h = parseAddress(line[4]);
            cur_record.resp_p = to!int(line[5]);
            cur_record.proto = line[6];
            cur_record.trans_id = line[7];

            if (line[8] != header.unset_field)
                cur_record.rtt = to!float(line[8]);

            cur_record.query = line[9];
            cur_record.qclass = to!int(line[10]);
            cur_record.qclass_name = line[11];
            cur_record.qtype = to!int(line[12]);
            cur_record.qtype_name = line[13];
            cur_record.rcode = to!int(line[14]);
            cur_record.rcode_name = line[15];

            // Convert 0 and 1 to bool
            if (line[16] != header.unset_field) {
                if (line[16] == "0") {
                    cur_record.AA = false;
                } else {
                    cur_record.AA = true;
                }
            }

            if (line[17] != header.unset_field) {
                if (line[17] == "0") {
                    cur_record.TC = false;
                } else {
                    cur_record.TC = true;
                }
            }

            if (line[18] != header.unset_field) {
                if (line[18] == "0") {
                    cur_record.RD = false;
                } else {
                    cur_record.RD = true;
                }
            }

            if (line[19] != header.unset_field) {
                if (line[19] == "0") {
                    cur_record.RA = false;
                } else {
                    cur_record.RA = true;
                }
            }

            cur_record.Z = to!int(line[20]);

            if (line[21] != header.empty_field)
                cur_record.answers = line[21].split(header.set_seperator);

            if (line[22] != header.empty_field)
                foreach (i; 0 .. line[22].split(header.set_seperator).length - 1) {
                    cur_record.TTLs[i] = to!float(line[22].split(header.set_seperator)[i]);
                }

            if (line[23] != header.unset_field) {
                if (line[23] == "0") {
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

    @("dns_read_test_1")
    unittest
    {
        File file = File("tests/logs/dns.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto dns_test = new Dns;
        Dns.Record[int] results;
        results = dns_test.parse_file(header, file);

        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "dns";

        results.length.should == 4;
        results[1].uid.should == "COac2a2ZLGZJSbS2r5";
        results[2].uid.should == "CNjL5d4o5z2c92Dm9j";
        results[3].uid.should == "Ck8RXy3A5mMYpuaMPl";
        results[4].uid.should == "CQPWD5kcGNGECLpQe";
    }
}
