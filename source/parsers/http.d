// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.http;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class Http : Parser {
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
            cur_record.trans_depth = to!int(line[6]);
            cur_record.method = line[7];
            cur_record.host = line[8];
            cur_record.uri = line[9];

            if (line[10] != header.unset_field)
                cur_record.referrer = line[10];

            cur_record.http_version = line[11];
            cur_record.user_agent = line[12];
            cur_record.request_body_len = to!int(line[13]);
            cur_record.response_body_len = to!int(line[14]);
            cur_record.status_code = to!int(line[15]);
            cur_record.status_msg = line[16];

            if (line[17] != header.unset_field)
                cur_record.info_code = to!int(line[17]);

            if (line[18] != header.unset_field)
                cur_record.info_msg = line[18];

            if (line[19] != header.empty_field) {
                cur_record.tags.length = line[19].split(header.set_seperator).length;
                foreach (i; 0 .. line[19].split(header.set_seperator).length) {
                    cur_record.tags[i] = line[19].split(header.set_seperator)[i];
                }
            }

            if (line[20] != header.unset_field)
                cur_record.username = line[20];

            if (line[21] != header.unset_field)
                cur_record.password = line[21];

            if (line[22] != header.unset_field) {
                cur_record.proxied.length = line[22].split(header.set_seperator).length;
                foreach (i; 0 .. line[22].split(header.set_seperator).length) {
                    cur_record.proxied [i] = line[22].split(header.set_seperator)[i];
                }
            }

            if (line[23] != header.unset_field) {
                cur_record.orig_fuids.length = line[23].split(header.set_seperator).length;
                foreach (i; 0 .. line[23].split(header.set_seperator).length) {
                    cur_record.orig_fuids [i] = line[23].split(header.set_seperator)[i];
                }
            }

            if (line[24] != header.unset_field) {
                cur_record.orig_filenames.length = line[24].split(header.set_seperator).length;
                foreach (i; 0 .. line[24].split(header.set_seperator).length) {
                    cur_record.orig_filenames [i] = line[24].split(header.set_seperator)[i];
                }
            }

            if (line[25] != header.unset_field) {
                cur_record.orig_mime_types.length = line[25].split(header.set_seperator).length;
                foreach (i; 0 .. line[25].split(header.set_seperator).length) {
                    cur_record.orig_mime_types [i] = line[25].split(header.set_seperator)[i];
                }
            }

            if (line[26] != header.unset_field) {
                cur_record.resp_fuids.length = line[26].split(header.set_seperator).length;
                foreach (i; 0 .. line[26].split(header.set_seperator).length) {
                    cur_record.resp_fuids[i] = line[26].split(header.set_seperator)[i];
                }
            }
            if (line[27] != header.unset_field) {
                cur_record.resp_filenames.length = line[27].split(header.set_seperator).length;
                foreach (i; 0 .. line[27].split(header.set_seperator).length) {
                    cur_record.resp_filenames[i] = line[27].split(header.set_seperator)[i];
                }
            }

            if (line[28] != header.unset_field) {
                cur_record.resp_mime_types.length = line[28].split(header.set_seperator).length;
                foreach (i; 0 .. line[28].split(header.set_seperator).length) {
                    cur_record.resp_mime_types[i] = line[28].split(header.set_seperator)[i];
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
    Http.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/http.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto http_test = new Http;
        results = http_test.parse_file(header, file);
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
        results[1].ts.should == 1531687185.306279;
        results[1].uid.should == "CuVIzg2991yFw6ZZl";
        results[1].orig_h.toAddrString().should == "10.0.0.3";
        results[1].orig_p.should == 45548;
        results[1].resp_h.toAddrString().should == "127.0.0.2";
        results[1].resp_p.should == 80;
        results[1].trans_depth.should == 1;
        results[1].method.should == "POST";
        results[1].host.should == "test.domain";
        results[1].uri.should == "/GTSGIAG3";
        assert(results[1].referrer.isNull);
        results[1].http_version.should == "1.1";
        results[1].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[1].request_body_len.should == 75;
        results[1].response_body_len.should == 463;
        results[1].status_code.should == 200;
        results[1].status_msg.should == "OK";
        assert(results[1].info_code.isNull);
        assert(results[1].info_msg.isNull);
        results[1].tags.shouldBeEmpty;
        assert(results[1].username.isNull);
        assert(results[1].password.isNull);
        results[1].proxied.shouldBeEmpty;
        results[1].orig_fuids.should == ["FFRgqxygVeipwAvKl"];
        results[1].orig_filenames.shouldBeEmpty;
        results[1].orig_mime_types.should == ["application/ocsp-request"];
        results[1].resp_fuids.should == ["Fae9Lt3uIEEOVtrGre"];
        results[1].resp_filenames.shouldBeEmpty();
        results[1].resp_mime_types.should == ["application/ocsp-response"];
    }

    @("http_read_test_2")
    unittest
    {
        results[2].ts.should == 1531687185.314280;
        results[2].uid.should == "CBlWr94sL2KePoCqz7";
        results[2].orig_h.toAddrString().should == "10.0.0.3";
        results[2].orig_p.should == 45546;
        results[2].resp_h.toAddrString().should == "127.0.0.2";
        results[2].resp_p.should == 80;
        results[2].trans_depth.should == 1;
        results[2].method.should == "POST";
        results[2].host.should == "test.domain";
        results[2].uri.should == "/GTSGIAG3";
        assert(results[2].referrer.isNull);
        results[2].http_version.should == "1.1";
        results[2].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[2].request_body_len.should == 75;
        results[2].response_body_len.should == 463;
        results[2].status_code.should == 200;
        results[2].status_msg.should == "OK";
        assert(results[2].info_code.isNull);
        assert(results[2].info_msg.isNull);
        results[2].tags.shouldBeEmpty;
        assert(results[2].username.isNull);
        assert(results[2].password.isNull);
        results[2].proxied.shouldBeEmpty();
        results[2].orig_fuids.should == ["F4MT931ov6qLvRD8Ne"];
        results[2].orig_filenames.shouldBeEmpty();
        results[2].orig_mime_types.should == ["application/ocsp-request"];
        results[2].resp_fuids.should == ["F5F5oA1q4IXwFANwk8"];
        results[2].resp_filenames.shouldBeEmpty();
        results[2].resp_mime_types.should == ["application/ocsp-response"];
    }

    @("http_read_test_3")
    unittest
    {
        results[3].ts.should == 1531687191.158275;
        results[3].uid.should == "Czi9O3kaUI8DpgVCd";
        results[3].orig_h.toAddrString().should == "10.0.0.2";
        results[3].orig_p.should == 43422;
        results[3].resp_h.toAddrString().should == "10.12.1.2";
        results[3].resp_p.should == 80;
        results[3].trans_depth.should == 1;
        results[3].method.should == "POST";
        results[3].host.should == "testdomain.com";
        results[3].uri.should == "/";
        assert(results[3].referrer.isNull);
        results[3].http_version.should == "1.1";
        results[3].user_agent.should == "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0";
        results[3].request_body_len.should == 83;
        results[3].response_body_len.should == 471;
        results[3].status_code.should == 200;
        results[3].status_msg.should == "OK";
        assert(results[3].info_code.isNull);
        assert(results[3].info_msg.isNull);
        results[3].tags.shouldBeEmpty;
        assert(results[3].username.isNull);
        assert(results[3].password.isNull);
        results[3].proxied.shouldBeEmpty();
        results[3].orig_fuids.should == ["FHDk0m2U0SNRGPYN5g"];
        results[3].orig_filenames.shouldBeEmpty() ;
        results[3].orig_mime_types.should == ["application/ocsp-request"];
        results[3].resp_fuids.should == ["F6sICI3IY4vu5U4ys1"];
        results[3].resp_filenames.shouldBeEmpty();
        results[3].resp_mime_types.should == ["application/ocsp-response"];
    }
}
