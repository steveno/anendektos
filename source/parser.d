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

module parser;

import std.conv;
import std.file;
import std.parallelism;
import std.stdio;
import std.string;

import parsers.conn;
import parsers.dns;


class Parser {
    string log_path;
    string out_path;
    immutable string log_suffix = ".log";
    struct Header {
        string seperator;
        string set_seperator;
        string empty_field;
        string unset_field;
        string path;
        string[] fields;
    };

    public void parse_logs() {
        auto log_files = dirEntries(this.log_path, SpanMode.shallow);
        File file;
        Header header;
        foreach (d; parallel(log_files, 1)) {
            string log_file;
            if (!d.name.endsWith(this.log_suffix))
                continue;
            else
                log_file = d.name.stripRight(this.log_suffix);

            file = File(log_file, "r");
            header = parse_log_header(file);
            if (header.path == "conn") {
                auto conn = new Conn();
                conn.parse_file(header, file);
            } else if (header.path == "dns") {
                auto dns = new Dns();
                dns.parse_file(header, file);
            } else if (header.path == "http") {
                writeln("ERROR: NOT IMPLEMENTED");
            } else if (header.path == "packet_filter") {
                writeln("ERROR: NOT IMPLEMENTED");
            } else if (header.path == "reporter") {
                writeln("ERROR: NOT IMPLEMENTED");
            } else if (header.path == "ssl") {
                writeln("ERROR: NOT IMPLEMENTED");
            } else if (header.path == "weird") {
                writeln("ERROR: NOT IMPLEMENTED");
            } else if (header.path == "x509") {
                writeln("ERROR: NOT IMPLEMENTED");
            }
        }
    }

    public Header parse_log_header(File file) {
        Header header;

        string line;
        while (!file.eof()) {
            line = strip(file.readln());

            if (!startsWith(line, "#")) {
                file.rewind();
                return header;
            }

            // Parse out neccessary fields, otherwise skip commented lines
            if (startsWith(line, "#separator")) {
                string tmp = split(line, " ")[1];
                if (tmp.startsWith("\\x")) {
                    header.seperator = convHex(tmp);
                } else {
                    header.seperator = tmp;
                }

                continue;
            }

            if (startsWith(line, "#set_separator")) {
                header.set_seperator = split(line, header.seperator)[1];
                continue;
            }

            if (startsWith(line, "#empty_field")) {
                header.empty_field = split(line, header.seperator)[1];
                continue;
            }

            if (startsWith(line, "#unset_field")) {
                header.unset_field = split(line, header.seperator)[1];
                continue;
            }

            if (startsWith(line, "#path")) {
                header.path = split(line, header.seperator)[1];
                continue;
            }

            if (startsWith(line, "#fields")) {
                header.fields = split(line, header.seperator)[1..$];
                continue;
            }
        }

        assert(false);
    }

    private static @safe pure string convHex(string hexData) {
        int cnt = 0;
        char[] result; result.length = 2; foreach (char c; hexData)
        {
            cnt += 1;
            if (cnt > 2) {
                result[cnt-3] = c;
            }
        }

        return to!string(cast(char)to!int(result, 16));
    }
}


version(unittest) {
    import unit_threaded;

    @("conn_header_default")
    unittest
    {
        File file = File("tests/headers/tab_sep.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);

        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("conn_header_with_space_sep")
    unittest
    {
        File file = File("tests/headers/space_sep.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);

        header.seperator.should == " ";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("convert_hex_to_string")
    unittest
    {
        Parser.convHex("\\x09").should == "\t";
        Parser.convHex("\\x20").should == " ";
    }
}
