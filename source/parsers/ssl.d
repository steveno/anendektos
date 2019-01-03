// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at ssl://mozilla.org/MPL/2.0/.

module parsers.ssl;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class Ssl : Parser {
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

            if (line[6] != header.unset_field)
                cur_record.ssl_version = line[6];

            if (line[7] != header.unset_field)
                cur_record.cipher = line[7];

            if (line[8] != header.unset_field)
                cur_record.curve = line[8];

            cur_record.server_name = line[9];
  
            if (line[10] != header.unset_field) {
                if (line[10] == "F") {
                    cur_record.resumed = false;
                } else {
                    cur_record.resumed = true;
                }
            }

            if (line[11] != header.unset_field)
                cur_record.last_alert = line[11];

            if (line[12] != header.unset_field)
                cur_record.next_protocol = line[12];

            if (line[13] != header.unset_field) {
                if (line[13] == "F") {
                    cur_record.established = false;
                } else {
                    cur_record.established = true;
                }
            }

            if (line[14] != header.empty_field && line[14] != header.unset_field)
                cur_record.cert_chain_fuids = line[14].split(header.set_seperator);

            if (line[15] != header.empty_field && line[15] != header.unset_field)
                cur_record.client_cert_chain_fuids = line[15].split(header.set_seperator);

            if (line[16] != header.unset_field)
                cur_record.subject = line[16];

            if (line[17] != header.unset_field)
                cur_record.issuer = line[17];

            if (line[19] != header.unset_field)
                cur_record.client_subject = line[18];


            if (line[19] != header.unset_field)
                cur_record.client_issuer = line[19];

            ++rec_num;
            contents[rec_num] = cur_record;
        }

        return contents;
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
        results = ssl_test.parse_file(header, file);
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
        results[1].ts.should == 1531687175.6463;
        results[1].uid.should == "C49NlPigbiwRa1aJ3";
        results[1].orig_h.toAddrString().should == "10.0.0.2";
        results[1].orig_p.should == 49204;
        results[1].resp_h.toAddrString().should == "10.0.202.133";
        results[1].resp_p.should == 443;
        results[1].ssl_version.should == "TLSv12";
        results[1].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        results[1].curve.should == "x25519";
        results[1].server_name.should == "avatars.content.com";
        results[1].resumed.should == false;
        assert(results[1].last_alert.isNull);
        results[1].next_protocol.should == "http/1.1";
        results[1].established.should == true;
        results[1].cert_chain_fuids.should == ["FqxvGx22DT6AwxHGPl", "FwwOhm4iR4jYQbaAS"];
        results[1].client_cert_chain_fuids.shouldBeEmpty();
        results[1].subject.should == "CN=www.content.com,O=Content\\\\, Inc.,L=Hometown,ST=California,C=US";
        results[1].issuer.should == "CN=DigiCert SHA2 High Assurance Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US";
        assert(results[1].client_subject.isNull);
        assert(results[1].client_issuer.isNull);
    }

    @("ssl_read_test_2")
    unittest
    { 
        results[2].ts.should == 1531687177.91832;
        results[2].uid.should == "C4nlzv2oCPsTUEf7bb";
        results[2].orig_h.toAddrString().should == "10.0.0.2";
        results[2].orig_p.should == 40748;
        results[2].resp_h.toAddrString().should == "10.2.4.3";
        results[2].resp_p.should == 443;
        results[2].ssl_version.should == "TLSv12";
        results[2].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        assert(results[2].curve.isNull);
        results[2].server_name.should == "img-site.cdn.example.net";
        results[2].resumed.should == true;
        assert(results[2].last_alert.isNull);
        results[2].next_protocol.should == "h2";
        results[2].established.should == true;
        results[2].cert_chain_fuids.shouldBeEmpty();
        results[2].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[2].subject.isNull);
        assert(results[2].issuer.isNull);
        assert(results[2].client_subject.isNull);
        assert(results[2].client_issuer.isNull);
    }

    @("ssl_read_test_3")
    unittest
    { 
        results[3].ts.should == 1531687190.02632;
        results[3].uid.should == "CuMGVfUkGoFTcia6g";
        results[3].orig_h.toAddrString().should == "10.0.0.2";
        results[3].orig_p.should == 37590;
        results[3].resp_h.toAddrString().should == "10.2.4.3";
        results[3].resp_p.should == 443;
        assert(results[3].ssl_version.isNull);
        assert(results[3].cipher.isNull);
        assert(results[3].curve.isNull);
        results[3].server_name.should == "random.domain.com";
        results[3].resumed.should == false;
        assert(results[3].last_alert.isNull);
        assert(results[3].next_protocol.isNull);
        results[3].established.should == false;
        results[3].cert_chain_fuids.shouldBeEmpty();
        results[3].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[3].subject.isNull);
        assert(results[3].issuer.isNull);
        assert(results[3].client_subject.isNull);
        assert(results[3].client_issuer.isNull);
    }

    @("ssl_read_test_4")
    unittest
    { 
        results[4].ts.should == 1531687185.2183;
        results[4].uid.should == "CLPKPi2rWL4e1J8mN7";
        results[4].orig_h.toAddrString().should == "fe80:541:4303:db20:5d47:492b:981b:6bc3";
        results[4].orig_p.should == 51434;
        results[4].resp_h.toAddrString().should == "fe80:f6b0:a0b4:84a::10b6";
        results[4].resp_p.should == 443;
        results[4].ssl_version.should == "TLSv12";
        results[4].cipher.should == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        assert(results[4].curve.isNull);
        results[4].server_name.should == "i.ytimg.com";
        results[4].resumed.should == false;
        assert(results[4].last_alert.isNull);
        results[4].next_protocol.should == "h2";
        results[4].established.should == false;
        results[4].cert_chain_fuids.shouldBeEmpty();
        results[4].client_cert_chain_fuids.shouldBeEmpty();
        assert(results[4].subject.isNull);
        assert(results[4].issuer.isNull);
        assert(results[4].client_subject.isNull);
        assert(results[4].client_issuer.isNull);
    }
}
