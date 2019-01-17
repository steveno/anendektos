// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at ssl://mozilla.org/MPL/2.0/.

module parsers.ssl;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;

import parser;


class Ssl : Parser {
    /**
     * Struct to hold the information for a line in ssl log file.
     */
    struct Record {
        double ts;
        string uid;
        Address orig_h;
        int orig_p;
        Address resp_h;
        int resp_p;
        Nullable!(string) ssl_version;
        Nullable!(string) cipher;
        Nullable!(string) curve;
        string server_name;
        bool resumed;
        Nullable!(string) last_alert;
        Nullable!(string) next_protocol;
        bool established;
        string[] cert_chain_fuids;
        string[] client_cert_chain_fuids;
        Nullable!(string) subject;
        Nullable!(string) issuer;
        Nullable!(string) client_subject;
        Nullable!(string) client_issuer;
    };

    /**
     * Parse an ssl log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = an ssl log file to be parsed
     *
     * Returns: Generator expression which returns an Ssl.Record struct.
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
                    super.log.error("Processing ts on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.uid = cur_line[1];
                cur_record.orig_h = parseAddress(cur_line[2]);

                try {
                    cur_record.orig_p = to!int(cur_line[3]);
                } catch (Exception e) {
                    super.log.error("Processing orig_p on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.resp_h = parseAddress(cur_line[4]);

                try {
                    cur_record.resp_p = to!int(cur_line[5]);
                } catch (Exception e) {
                    super.log.error("Processing resp_p on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[6] != header.unset_field)
                    cur_record.ssl_version = cur_line[6];

                if (cur_line[7] != header.unset_field)
                    cur_record.cipher = cur_line[7];

                if (cur_line[8] != header.unset_field)
                    cur_record.curve = cur_line[8];

                cur_record.server_name = cur_line[9];

                if (cur_line[10] != header.unset_field) {
                    if (cur_line[10] == "F") {
                        cur_record.resumed = false;
                    } else {
                        cur_record.resumed = true;
                    }
                }

                if (cur_line[11] != header.unset_field)
                    cur_record.last_alert = cur_line[11];

                if (cur_line[12] != header.unset_field)
                    cur_record.next_protocol = cur_line[12];

                if (cur_line[13] != header.unset_field) {
                    if (cur_line[13] == "F") {
                        cur_record.established = false;
                    } else {
                        cur_record.established = true;
                    }
                }

                if (cur_line[14] != header.empty_field && cur_line[14] != header.unset_field)
                    cur_record.cert_chain_fuids = cur_line[14].split(header.set_seperator);

                if (cur_line[15] != header.empty_field && cur_line[15] != header.unset_field)
                    cur_record.client_cert_chain_fuids = cur_line[15].split(header.set_seperator);

                if (cur_line[16] != header.unset_field)
                    cur_record.subject = cur_line[16];

                if (cur_line[17] != header.unset_field)
                    cur_record.issuer = cur_line[17];

                if (cur_line[19] != header.unset_field)
                    cur_record.client_subject = cur_line[18];

                if (cur_line[19] != header.unset_field)
                    cur_record.client_issuer = cur_line[19];

                yield(cur_record);
            }
        });
    }
}

version(unittest) {
    import unit_threaded;
    Parser.Header header;
    Ssl.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/ssl.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto ssl_test = new Ssl;

        auto gen = ssl_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            Ssl.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
    }

    @("ssl_read_header")
    unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "ssl";
    }

    @("ssl_record_count")
    unittest
    {
        results.length.should == 4;
    }

    @("ssl_read_test_1")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "C49NlPigbiwRa1aJ3")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687175.6463;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 49204;
        results[entry].resp_h.toAddrString().should == "10.0.202.133";
        results[entry].resp_p.should == 443;
        results[entry].ssl_version.should == "TLSv12";
        results[entry].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        results[entry].curve.should == "x25519";
        results[entry].server_name.should == "avatars.content.com";
        results[entry].resumed.should == false;
        assert(results[entry].last_alert.isNull);
        results[entry].next_protocol.should == "http/1.1";
        results[entry].established.should == true;
        results[entry].cert_chain_fuids.should == ["FqxvGx22DT6AwxHGPl", "FwwOhm4iR4jYQbaAS"];
        results[entry].client_cert_chain_fuids.shouldBeEmpty();
        results[entry].subject.should == "CN=www.content.com,O=Content\\\\, Inc.,L=Hometown,ST=California,C=US";
        results[entry].issuer.should == "CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US";
        assert(results[entry].client_subject.isNull);
        assert(results[entry].client_issuer.isNull);
    }

    @("ssl_read_test_2")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "C4nlzv2oCPsTUEf7bb")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687177.91832;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 40748;
        results[entry].resp_h.toAddrString().should == "10.2.4.3";
        results[entry].resp_p.should == 443;
        results[entry].ssl_version.should == "TLSv12";
        results[entry].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        assert(results[entry].curve.isNull);
        results[entry].server_name.should == "img-site.cdn.example.net";
        results[entry].resumed.should == true;
        assert(results[entry].last_alert.isNull);
        results[entry].next_protocol.should == "h2";
        results[entry].established.should == true;
        results[entry].cert_chain_fuids.shouldBeEmpty();
        results[entry].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[entry].subject.isNull);
        assert(results[entry].issuer.isNull);
        assert(results[entry].client_subject.isNull);
        assert(results[entry].client_issuer.isNull);
    }

    @("ssl_read_test_3")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CuMGVfUkGoFTcia6g")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687190.02632;
        results[entry].orig_h.toAddrString().should == "10.0.0.2";
        results[entry].orig_p.should == 37590;
        results[entry].resp_h.toAddrString().should == "10.2.4.3";
        results[entry].resp_p.should == 443;
        assert(results[entry].ssl_version.isNull);
        assert(results[entry].cipher.isNull);
        assert(results[entry].curve.isNull);
        results[entry].server_name.should == "random.domain.com";
        results[entry].resumed.should == false;
        assert(results[entry].last_alert.isNull);
        assert(results[entry].next_protocol.isNull);
        results[entry].established.should == false;
        results[entry].cert_chain_fuids.shouldBeEmpty();
        results[entry].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[entry].subject.isNull);
        assert(results[entry].issuer.isNull);
        assert(results[entry].client_subject.isNull);
        assert(results[entry].client_issuer.isNull);
    }

    @("ssl_read_test_4")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].uid == "CLPKPi2rWL4e1J8mN7")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687185.2183;
        results[entry].orig_h.toAddrString().should == "fe80:541:4303:db20:5d47:492b:981b:6bc3";
        results[entry].orig_p.should == 51434;
        results[entry].resp_h.toAddrString().should == "fe80:f6b0:a0b4:84a::10b6";
        results[entry].resp_p.should == 443;
        results[entry].ssl_version.should == "TLSv12";
        results[entry].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        assert(results[entry].curve.isNull);
        results[entry].server_name.should == "i.ytimg.com";
        results[entry].resumed.should == false;
        assert(results[entry].last_alert.isNull);
        results[entry].next_protocol.should == "h2";
        results[entry].established.should == false;
        results[entry].cert_chain_fuids.shouldBeEmpty();
        results[entry].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[entry].subject.isNull);
        assert(results[entry].issuer.isNull);
        assert(results[entry].client_subject.isNull);
        assert(results[entry].client_issuer.isNull);
    }
}
