// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parser;

import std.conv;
import std.datetime;
import std.file;
import std.stdio;
import std.string;

import config;
import logging;
import parsers.conn;
import parsers.dns;
import parsers.files;
import parsers.http;
import parsers.ssl;
import parsers.x509;

class Parser {
    private immutable string log_suffix = ".log";
    private config.Config options;
    private logging.Log log;

    struct Header {
        string seperator;
        string set_seperator;
        string empty_field;
        string unset_field;
        DateTime open;
        string path;
        string[] fields;
    };

    this() {
        this.options = config.Config.get();
        this.log = logging.Log(stderrLogger, stdoutLogger(LogLevel.Info), fileLogger(options.ini["application"].getKey("log_file")));
    }

    public void parse_logs() {
        auto log_files = dirEntries(this.options.ini["application"].getKey("bro_path"), SpanMode.shallow);
        File file;
        Header header;

        validate_summarize_config();

        foreach (d; log_files) {
            file = File(d.name, "r");
            header = parse_log_header(file);
            try {
                if (header.path == "conn") {
                    auto conn = new Conn();
                    summarize(conn, header, file);
                } else if (header.path == "dns") {
                    auto dns = new Dns();
                    summarize(dns, header, file);
                } else if (header.path == "http") {
                    auto http = new Http();
                    summarize(http, header, file);
                } else if (header.path == "files") {
                    auto files = new Files();
                    summarize(files, header, file);
                } else if (header.path == "ssl") {
                    auto ssl = new Ssl();
                    summarize(ssl, header, file);
                } else if (header.path == "x509") {
                    auto x509 = new X509();
                    summarize(x509, header, file);
                } else {
                    this.log.warn("%s has not been implemented", header.path);
                }
            } catch (Exception e) {
                this.log.error("%s - %s", d.name, e.msg);
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

            if (startsWith(line, "#open")) {
                int year = to!int(split(split(line, header.seperator)[1], "-")[0]);
                int month = to!int(split(split(line, header.seperator)[1], "-")[1]);
                int day = to!int(split(split(line, header.seperator)[1], "-")[2]);
                int hour = to!int(split(split(line, header.seperator)[1], "-")[3]);
                int minute = to!int(split(split(line, header.seperator)[1], "-")[4]);
                int second = to!int(split(split(line, header.seperator)[1], "-")[5]);
                header.open = DateTime(year, month, day, hour, minute, second);
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

    public void summarize(P, H, F)(P parser_type, H header, F file) {
        parser_type.Record[int] res;
        auto gen = parser_type.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            parser_type.Record record = gen.front();
            res[i] = record;
            gen.popFront();
            i++;
        }

        /* TODO Summarize records
        import std.container.rbtree;
        import std.typecons;

        auto value = tuple([1, 3], "t");
        auto rbt = redBlackTree(value);
        rbt.insert(tuple([1, 3], "b"));
        rbt.insert(tuple([1, 3], "b"));
        rbt.insert(tuple([2, 2], "p"));
        */
    }

    private void validate_summarize_config() {
        bool valid;

        foreach(key, value; this.options.ini["summarize_by"].keys)
        {
            switch (key) {
                default:
                    log.fatal("Invalid configuration key summarize_by[%s]", key);
                    throw new Exception("Invalid configuration key. Check log.");
                case "conn":
                    valid = validate_record_member(new Conn(), value);
                    break;
                case "dns":
                    valid = validate_record_member(new Dns(), value);
                    break;
                case "files":
                    valid = validate_record_member(new Files(), value);
                    break;
                case "http":
                    valid = validate_record_member(new Http(), value);
                    break;
                case "ssl":
                    valid = validate_record_member(new Ssl(), value);
                    break;
                case "x509":
                    valid = validate_record_member(new X509(), value);
                    break;
            }

            if (!valid) {
                log.fatal("Invalid configuration value summarize_by[%s] = %s", key, value);
                throw new Exception("Invalid configuration value. Check log");
            }
        }
    }

    private bool validate_record_member(T)(T parser, string value) {
        foreach(member; __traits(allMembers, parser.Record))
            if (member == value)
                return true;

        return false;
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
        header.open.toISOString().should == "20180715T163941";
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
        header.open.toISOString().should == "20180724T131650";
        header.fields.should == ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"];
    }

    @("convert_hex_to_string")
    @safe pure unittest
    {
        Parser.convHex("\\x09").should == "\t";
        Parser.convHex("\\x20").should == " ";
    }
}
