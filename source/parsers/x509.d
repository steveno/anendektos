// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at x509://mozilla.org/MPL/2.0/.

module parsers.x509;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class X509 : Parser {
    struct Record {
        double ts;
        string id;
        int certificate_version;
        string certificate_serial;
        string certificate_subject;
        string certificate_issuer;
        double certificate_not_valid_before;
        double certificate_not_valid_after;
        string certificate_key_alg;
        string certificate_sig_alg;
        string certificate_key_type;
        int certificate_key_length;
        Nullable!(int) certificate_exponent;
        Nullable!(string) certificate_curve;
        string[] san_dns;
        string[] san_uri;
        string[] san_email;
        Nullable!(Address[]) san_ip;
        bool basic_constraints_ca;
        Nullable!(int) basic_constraints_path_len;
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
            cur_record.id = line[1];
            cur_record.certificate_version = to!int(line[2]);
            cur_record.certificate_serial = line[3];
            cur_record.certificate_subject = line[4];
            cur_record.certificate_issuer = line[5];
            cur_record.certificate_not_valid_before = to!double(line[6]);
            cur_record.certificate_not_valid_after = to!double(line[7]);
            cur_record.certificate_key_alg = line[8];
            cur_record.certificate_sig_alg = line[9];
            cur_record.certificate_key_type = line[10];
            cur_record.certificate_key_length = to!int(line[11]);

            if (line[12] != header.unset_field)
                cur_record.certificate_exponent = to!int(line[12]);

            if (line[13] != header.unset_field)
                cur_record.certificate_curve = line[13];

            if (line[14] != header.unset_field) {
                cur_record.san_dns.length = line[14].split(header.set_seperator).length;
                foreach (i; 0 .. line[14].split(header.set_seperator).length) {
                    cur_record.san_dns[i] = line[14].split(header.set_seperator)[i];
                }
            }
            if (line[15] != header.unset_field) {
                cur_record.san_uri.length = line[15].split(header.set_seperator).length;
                foreach (i; 0 .. line[15].split(header.set_seperator).length) {
                    cur_record.san_uri[i] = line[15].split(header.set_seperator)[i];
                }
            }

            if (line[16] != header.unset_field) {
                cur_record.san_email.length = line[16].split(header.set_seperator).length;
                foreach (i; 0 .. line[16].split(header.set_seperator).length) {
                    cur_record.san_email[i] = line[16].split(header.set_seperator)[i];
                }
            }

            if (line[17] != header.unset_field) {
                cur_record.san_ip.length = line[17].split(header.set_seperator).length;
                foreach (i; 0 .. line[17].split(header.set_seperator).length) {
                    cur_record.san_ip[i] = parseAddress(line[17].split(header.set_seperator)[i]);
                }
            }

            if (line[18] != header.unset_field) {
                if (line[18] == "F") {
                    cur_record.basic_constraints_ca = false;
                } else {
                    cur_record.basic_constraints_ca = true;
                }
            }

            if (line[19] != header.unset_field)
                cur_record.basic_constraints_path_len = to!int(line[19]);

            ++rec_num;
            contents[rec_num] = cur_record;
        }

        return contents;
    }
}


version(unittest) {
    import unit_threaded;
    Parser.Header header;
    X509.Record[int] results;

    @Setup 
    void before() {
        File file = File("tests/logs/x509.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto x509_test = new X509;
        results = x509_test.parse_file(header, file);
    }

    @("x509_read_header")
    unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "x509";
    }

    @("x509_record_count")
    unittest
    {
        results.length.should == 3;
    }

    @("x509_read_test_1")
    unittest
    {
        results[1].ts.should == 1531687177.67832;
        results[1].id.should == "FVz825C4jlDdo6b14";
        results[1].certificate_version.should == 3;
        results[1].certificate_serial.should == "4B32DE72CAA28369";
        results[1].certificate_subject.should == "CN=*.companynameapis.com,O=CompanyName LLC,L=Home Town,ST=California,C=US";
        results[1].certificate_issuer.should == "CN=CompanyName Internet Authority G3,O=CompanyName Trust Services,C=US";
        results[1].certificate_not_valid_before.should == 1529422416;
        results[1].certificate_not_valid_after.should == 1535470260;
        results[1].certificate_key_alg.should == "id-ecPublicKey";
        results[1].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[1].certificate_key_type.should == "ecdsa";
        results[1].certificate_key_length.should == 256;
        assert(results[1].certificate_exponent.isNull);
        results[1].certificate_curve.should == "prime256v1";
        results[1].san_dns.should == ["*.companynameapis.com", "*.clients6.companyname.com", "*.cloudendpointsapis.com", "cloudendpointsapis.com" ,"companynameapis.com"] ;
        results[1].san_uri.should == [];
        results[1].san_email.should == [];
        assert(results[1].san_ip.isNull);
        results[1].basic_constraints_ca.should == false;
        assert(results[1].basic_constraints_path_len.isNull);
    }

    @("x509_read_test_2")
    unittest
    {
        results[2].ts.should == 1531687177.67832;
        results[2].id.should == "F8ZbvG3ftnyrB5Ezui";
        results[2].certificate_version.should == 3;
        results[2].certificate_serial.should == "01E3A9301CFC7206383F9A531D";
        results[2].certificate_subject.should == "CN=CompanyName Internet Authority G3,O=CompanyName Trust Services,C=US";
        results[2].certificate_issuer.should == "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R2";
        results[2].certificate_not_valid_before.should == 1497499242;
        results[2].certificate_not_valid_after.should == 1639544442;
        results[2].certificate_key_alg.should == "rsaEncryption";
        results[2].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[2].certificate_key_type.should == "rsa";
        results[2].certificate_key_length.should == 2048;
        results[2].certificate_exponent.should == 65537;
        assert(results[2].certificate_curve.isNull);
        results[2].san_dns.should == [];
        results[2].san_uri.should == [];
        results[2].san_email.should == [];
        assert(results[2].san_ip.isNull);
        results[2].basic_constraints_ca.should == true;
        results[2].basic_constraints_path_len.should == 0;
    }

    @("x509_read_test_3")
    unittest
    {
        results[3].ts.should == 1531687178.26231;
        results[3].id.should == "FmuFdY1BDVQ6VxTWNb";
        results[3].certificate_version.should == 3;
        results[3].certificate_serial.should == "0A0630427F5BBCED6957396593B6451F";
        results[3].certificate_subject.should == "CN=testcompany.com,O=TestCompany\\\\, Inc.,L=San Francisco,ST=California,C=US,serialNumber=12344657,jurisdictionST=Delaware,jurisdictionC=US,businessCategory=Private Organization";
        results[3].certificate_issuer.should == "CN=DigiCert SHA2 Extended Validation Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US";
        results[3].certificate_not_valid_before.should == 1525752000;
        results[3].certificate_not_valid_after.should == 1591200000;
        results[3].certificate_key_alg.should == "rsaEncryption";
        results[3].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[3].certificate_key_type.should == "rsa";
        results[3].certificate_key_length.should == 2048;
        results[3].certificate_exponent.should == 65537;
        assert(results[3].certificate_curve.isNull);
        results[3].san_dns.should == ["testcompany.com", "www.testcompany.com"];
        results[3].san_uri.should == [];
        results[3].san_email.should == [];
        assert(results[3].san_ip.isNull);
        results[3].basic_constraints_ca.should == false;
        assert(results[3].basic_constraints_path_len.isNull);
    }
}
