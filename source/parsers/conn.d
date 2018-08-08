/* Copyright 2018 Steven Oliver <oliver.steven@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

module parsers.conn;

import std.conv;
import std.socket;
import std.stdio;
import std.string;

import parser;


class Conn : Parser {
    struct Record {
        float ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        string proto;
        string service;
        float duration;
        int orig_bytes;
        int resp_bytes;
        string conn_state;
        bool local_orig;
        bool local_resp;
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
            cur_record.ts = to!float(line[0]);
            cur_record.uid = line[1];
            cur_record.orig_h = parseAddress(line[2]);
            cur_record.orig_p = to!int(line[3]);
            cur_record.resp_h = parseAddress(line[4]);
            cur_record.resp_p = to!int(line[5]);
            cur_record.proto = line[6];

            if (line[7] != header.unset_field)
                cur_record.service = line[7];

            cur_record.duration = to!float(line[8]);
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
            cur_record.history = line[15];
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

    @("conn_read_test_1")
    unittest
    {
        File file = File("tests/logs/conn.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto conn_test = new Conn;
        Conn.Record[int] results;
        results = conn_test.parse_file(header, file);

        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        results.length.should == 12;
    }
}
