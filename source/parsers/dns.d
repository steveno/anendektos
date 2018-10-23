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
        int rtt;
        float query;
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
