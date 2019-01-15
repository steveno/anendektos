// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.http;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;

import parser;


class Http : Parser {
    /**
     * Struct to hold the information for a line in http log file.
     */
    struct Record {
        double ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        int trans_depth;
        string method;
        string host;
        string uri;
        Nullable!(string) referrer;
        string http_version;
        string user_agent;
        int request_body_len;
        int response_body_len;
        int status_code;
        string status_msg;
        Nullable!(int) info_code;
        Nullable!(string) info_msg;
        string[] tags;
        Nullable!(string) username;
        Nullable!(string) password;
        string[] proxied;
        string[] orig_fuids;
        string[] orig_filenames;
        string[] orig_mime_types;
        string[] resp_fuids;
        string[] resp_filenames;
        string[] resp_mime_types;
    };

    /**
     * Parse an http log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = an http log file to be parsed
     *
     * Returns: Generator expression which returns an Http.Record struct.
     */
    public auto parse_file(Header header, File log_file) {
        auto range = log_file.byLine();
        return new Generator!(Record)({
            foreach (line; range) {
                string[] cur_line = strip(to!string(line)).split(header.seperator);

                // Skip empty lines
                if (line == [] || startsWith(cur_line[0], "#"))
                    continue;

                // Populate our record
                Record cur_record;
                cur_record.ts = to!double(cur_line[0]);
                cur_record.uid = cur_line[1];
                cur_record.orig_h = parseAddress(cur_line[2]);
                cur_record.orig_p = to!int(cur_line[3]);
                cur_record.resp_h = parseAddress(cur_line[4]);
                cur_record.resp_p = to!int(cur_line[5]);
                cur_record.trans_depth = to!int(cur_line[6]);
                cur_record.method = cur_line[7];
                cur_record.host = cur_line[8];
                cur_record.uri = cur_line[9];

                if (cur_line[10] != header.unset_field)
                    cur_record.referrer = cur_line[10];

                cur_record.http_version = cur_line[11];
                cur_record.user_agent = cur_line[12];
                cur_record.request_body_len = to!int(cur_line[13]);
                cur_record.response_body_len = to!int(cur_line[14]);
                cur_record.status_code = to!int(cur_line[15]);
                cur_record.status_msg = cur_line[16];

                if (cur_line[17] != header.unset_field)
                    cur_record.info_code = to!int(cur_line[17]);

                if (cur_line[18] != header.unset_field)
                    cur_record.info_msg = cur_line[18];

                if (cur_line[19] != header.empty_field) {
                    cur_record.tags.length = cur_line[19].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[19].split(header.set_seperator).length) {
                        cur_record.tags[i] = cur_line[19].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[20] != header.unset_field)
                    cur_record.username = cur_line[20];

                if (cur_line[21] != header.unset_field)
                    cur_record.password = cur_line[21];

                if (cur_line[22] != header.unset_field) {
                    cur_record.proxied.length = cur_line[22].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[22].split(header.set_seperator).length) {
                        cur_record.proxied [i] = cur_line[22].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[23] != header.unset_field) {
                    cur_record.orig_fuids.length = cur_line[23].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[23].split(header.set_seperator).length) {
                        cur_record.orig_fuids [i] = cur_line[23].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[24] != header.unset_field) {
                    cur_record.orig_filenames.length = cur_line[24].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[24].split(header.set_seperator).length) {
                        cur_record.orig_filenames [i] = cur_line[24].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[25] != header.unset_field) {
                    cur_record.orig_mime_types.length = cur_line[25].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[25].split(header.set_seperator).length) {
                        cur_record.orig_mime_types [i] = cur_line[25].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[26] != header.unset_field) {
                    cur_record.resp_fuids.length = cur_line[26].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[26].split(header.set_seperator).length) {
                        cur_record.resp_fuids[i] = cur_line[26].split(header.set_seperator)[i];
                    }
                }
                if (cur_line[27] != header.unset_field) {
                    cur_record.resp_filenames.length = cur_line[27].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[27].split(header.set_seperator).length) {
                        cur_record.resp_filenames[i] = cur_line[27].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[28] != header.unset_field) {
                    cur_record.resp_mime_types.length = cur_line[28].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[28].split(header.set_seperator).length) {
                        cur_record.resp_mime_types[i] = cur_line[28].split(header.set_seperator)[i];
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
    Http.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/http.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto http_test = new Http;

        auto gen = http_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            Http.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
    }

    @("http_read_header")
    unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "http";
    }

    @("http_record_count")
    unittest
    {
        results.length.should == 3;
    }

    @("http_read_test_1")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CuVIzg2991yFw6ZZl")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687185.306279;
        results[entry].orig_h.toAddrString().should == "10.0.0.3";
        results[entry].orig_p.should == 45548;
        results[entry].resp_h.toAddrString().should == "127.0.0.2";
        results[entry].resp_p.should == 80;
        results[entry].trans_depth.should == 1;
        results[entry].method.should == "POST";
        results[entry].host.should == "test.domain";
        results[entry].uri.should == "/GTSGIAG3";
        results[entry].referrer.should == "example.com";
        results[entry].http_version.should == "1.1";
        results[entry].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[entry].request_body_len.should == 75;
        results[entry].response_body_len.should == 463;
        results[entry].status_code.should == 200;
        results[entry].status_msg.should == "OK";
        assert(results[entry].info_code.isNull);
        assert(results[entry].info_msg.isNull);
        results[entry].tags.shouldBeEmpty;
        assert(results[entry].username.isNull);
        assert(results[entry].password.isNull);
        results[entry].proxied.shouldBeEmpty;
        results[entry].orig_fuids.should == ["FFRgqxygVeipwAvKl"];
        results[entry].orig_filenames.shouldBeEmpty;
        results[entry].orig_mime_types.should == ["application/ocsp-request"];
        results[entry].resp_fuids.should == ["Fae9Lt3uIEEOVtrGre"];
        results[entry].resp_filenames.shouldBeEmpty();
        results[entry].resp_mime_types.should == ["application/ocsp-response"];
    }

    @("http_read_test_2")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CBlWr94sL2KePoCqz7")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687185.314280;
        results[entry].orig_h.toAddrString().should == "10.0.0.3";
        results[entry].orig_p.should == 45546;
        results[entry].resp_h.toAddrString().should == "127.0.0.2";
        results[entry].resp_p.should == 80;
        results[entry].trans_depth.should == 1;
        results[entry].method.should == "POST";
        results[entry].host.should == "test.domain";
        results[entry].uri.should == "/GTSGIAG3";
        assert(results[entry].referrer.isNull);
        results[entry].http_version.should == "1.1";
        results[entry].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[entry].request_body_len.should == 75;
        results[entry].response_body_len.should == 463;
        results[entry].status_code.should == 200;
        results[entry].status_msg.should == "OK";
        assert(results[entry].info_code.isNull);
        assert(results[entry].info_msg.isNull);
        results[entry].tags.shouldBeEmpty;
        assert(results[entry].username.isNull);
        assert(results[entry].password.isNull);
        results[entry].proxied.shouldBeEmpty();
        results[entry].orig_fuids.should == ["F4MT931ov6qLvRD8Ne"];
        results[entry].orig_filenames.shouldBeEmpty();
        results[entry].orig_mime_types.should == ["application/ocsp-request"];
        results[entry].resp_fuids.should == ["F5F5oA1q4IXwFANwk8"];
        results[entry].resp_filenames.shouldBeEmpty();
        results[entry].resp_mime_types.should == ["application/ocsp-response"];
    }

    @("http_read_test_3")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "Czi9O3kaUI8DpgVCd")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687191.158275;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 43422;
        results[entry].resp_h.toAddrString().should == "10.12.1.2";
        results[entry].resp_p.should == 80;
        results[entry].trans_depth.should == 1;
        results[entry].method.should == "POST";
        results[entry].host.should == "testdomain.com";
        results[entry].uri.should == "/";
        assert(results[entry].referrer.isNull);
        results[entry].http_version.should == "1.1";
        results[entry].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[entry].request_body_len.should == 83;
        results[entry].response_body_len.should == 471;
        results[entry].status_code.should == 200;
        results[entry].status_msg.should == "OK";
        assert(results[entry].info_code.isNull);
        assert(results[entry].info_msg.isNull);
        results[entry].tags.shouldBeEmpty;
        assert(results[entry].username.isNull);
        assert(results[entry].password.isNull);
        results[entry].proxied.shouldBeEmpty();
        results[entry].orig_fuids.should == ["FHDk0m2U0SNRGPYN5g"];
        results[entry].orig_filenames.shouldBeEmpty() ;
        results[entry].orig_mime_types.should == ["application/ocsp-request"];
        results[entry].resp_fuids.should == ["F6sICI3IY4vu5U4ys1"];
        results[entry].resp_filenames.shouldBeEmpty();
        results[entry].resp_mime_types.should == ["application/ocsp-response"];
    }
}
