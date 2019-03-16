// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parser;

import std.conv;
import std.datetime;
import std.file;
import std.stdio;
import std.string;
import std.experimental.logger;

import config;
import parsers.conn;
import parsers.dns;
import parsers.files;
import parsers.http;
import parsers.ssl;
import parsers.x509;


/**
 * The parser class reads in the logs files then shells
 * out the actual parsing to the individual parsers.
 */
class Parser {
    private immutable string log_suffix = ".log";
    private config.Config options;

    /**
     * Struct to hold header information from log files.
     */
    struct Header {
        string seperator;
        string set_seperator;
        string empty_field;
        string unset_field;
        DateTime open;
        string path;
        string[] fields;
    };

    /**
     * Default constructor
     */
    this() {
        this.options = config.Config.get();
    }

    /**
     * Parses all of the log files in a bro_path.
     *
     * Will write warning messages to the log when files it doesn't know how
     * to parse are encountered.
     */
    public void parse_logs() {
        DirIterator log_files;
        try {
            log_files = dirEntries(this.options.ini["application"].getKey("bro_path"), SpanMode.shallow);
        } catch (Exception e) {
            fatalf("bro_path %s does not exist", this.options.ini["application"].getKey("bro_path"));
        }
        File file;
        Header header;

        foreach (d; log_files) {
            file = File(d.name, "r");
            header = parse_log_header(file);

            try {
                if (header.path == "conn") {
                    summarize(new Conn(), header, file);
                } else if (header.path == "dns") {
                    summarize(new Dns(), header, file);
                } else if (header.path == "http") {
                    summarize(new Http(), header, file);
                } else if (header.path == "files") {
                    summarize(new Files(), header, file);
                } else if (header.path == "ssl") {
                    summarize(new Ssl(), header, file);
                } else if (header.path == "x509") {
                    summarize(new X509(), header, file);
                } else {
                    warningf("%s has not been implemented", header.path);
                }
            } catch (Exception e) {
                errorf("%s - %s", d.name, e.msg);
            }
        }
    }

    /**
     * Parse a log's header information storing all the relavent parts.
     */
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

            if (startsWith(line, "#open")) {
                const int year = to!int(split(split(line, header.seperator)[1], "-")[0]);
                const int month = to!int(split(split(line, header.seperator)[1], "-")[1]);
                const int day = to!int(split(split(line, header.seperator)[1], "-")[2]);
                const int hour = to!int(split(split(line, header.seperator)[1], "-")[3]);
                const int minute = to!int(split(split(line, header.seperator)[1], "-")[4]);
                const int second = to!int(split(split(line, header.seperator)[1], "-")[5]);
                header.open = DateTime(year, month, day, hour, minute, second);
                continue;
            }

            if (startsWith(line, "#fields")) {
                header.fields = split(line, header.seperator)[1..$];
                continue;
            }

            if (startsWith(line, "#types")) {
                continue;
            }

            fatal("Invalid or unknown entry \"%s\" in %s header", line, file);
        }

        // dmd complains without this here
        assert(0);
    }

    /**
     * Summarize each log file type
     */
    public void summarize(P)(P parser_type, Header header, File file) {
        parser_type.Record[int] res;
        auto gen = parser_type.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            parser_type.Record record = gen.front();
            res[i] = record;
            gen.popFront();
            i++;
        }
    }

    /**
     * Convert a hex character to its string representation
     *
     * Example: The string "//09x" will become the string " ".
     */
    private static @safe pure string convHex(string hexData) {
        int cnt = 0;
        char[] result;
        result.length = 2;

        foreach (char c; hexData)
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
    unittest {
        File file = File("tests/headers/tab_sep.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);

        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        header.open.toISOString().should == "20180715T163941";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("conn_header_with_space_sep")
    unittest {
        File file = File("tests/headers/space_sep.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);

        header.seperator.should == " ";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        header.open.toISOString().should == "20180724T131650";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("conn_header_with_pipe")
    unittest {
        File file = File("tests/headers/pipe_sep.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        header = parser.parse_log_header(file);

        header.seperator.should == "|";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "conn";
        header.open.toISOString().should == "20180715T163941";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
            "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes",
            "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("conn_header_invalid_entry")
    unittest {
        File file = File("tests/headers/invalid_entry.log", "r");
        Parser.Header header;
        auto parser = new Parser();
        parser.parse_log_header(file).shouldThrow!(object.Error);
    }

    @("convert_hex_to_string")
    @safe pure unittest {
        Parser.convHex("\\x09").should == "\t";
        Parser.convHex("\\x20").should == " ";
    }
}
