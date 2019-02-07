// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at x509://mozilla.org/MPL/2.0/.

module parsers.x509;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;
import std.experimental.logger;

import parser;


class X509 : Parser {
    /**
     * Struct to hold the information for a line in x509 log file.
     */
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

    /**
     * Parse a x509 log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = an x509 log file to be parsed
     *
     * Returns: Generator expression which returns an X509.Record struct.
     */
    public auto parse_file(Header header, File log_file) {
        int line_num = 0;
        auto range = log_file.byLine();
        return new Generator!(Record)({
            foreach (line; range) {
                string[] cur_line = strip(to!string(line)).split(header.seperator);
                line_num++;

                // Skip empty lines
                if (cur_line == [] || startsWith(cur_line[0], "#"))
                    continue;

                // Populate our record
                Record cur_record;

                try {
                    cur_record.ts = to!double(cur_line[0]);
                } catch (Exception e) {
                    error("Processing ts on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.id = cur_line[1];

                try {
                    cur_record.certificate_version = to!int(cur_line[2]);
                } catch (Exception e) {
                    error("Processing certificate_version on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.certificate_serial = cur_line[3];
                cur_record.certificate_subject = cur_line[4];
                cur_record.certificate_issuer = cur_line[5];

                try {
                    cur_record.certificate_not_valid_before = to!double(cur_line[6]);
                } catch (Exception e) {
                    error("Processing certificate_not_valid_before on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.certificate_not_valid_after = to!double(cur_line[7]);
                } catch (Exception e) {
                    error("Processing certificate_not_valid_after on line %d: %s", line_num, e.msg);
                    continue;
                }

                cur_record.certificate_key_alg = cur_line[8];
                cur_record.certificate_sig_alg = cur_line[9];
                cur_record.certificate_key_type = cur_line[10];

                try {
                    cur_record.certificate_key_length = to!int(cur_line[11]);
                } catch (Exception e) {
                    error("Processing certificate_key_length on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    if (cur_line[12] != header.unset_field)
                        cur_record.certificate_exponent = to!int(cur_line[12]);
                } catch (Exception e) {
                    error("Processing certificate_exponent on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[13] != header.unset_field)
                    cur_record.certificate_curve = cur_line[13];

                if (cur_line[14] != header.unset_field) {
                    cur_record.san_dns.length = cur_line[14].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[14].split(header.set_seperator).length) {
                        cur_record.san_dns[i] = cur_line[14].split(header.set_seperator)[i];
                    }
                }
                if (cur_line[15] != header.unset_field) {
                    cur_record.san_uri.length = cur_line[15].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[15].split(header.set_seperator).length) {
                        cur_record.san_uri[i] = cur_line[15].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[16] != header.unset_field) {
                    cur_record.san_email.length = cur_line[16].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[16].split(header.set_seperator).length) {
                        cur_record.san_email[i] = cur_line[16].split(header.set_seperator)[i];
                    }
                }

                if (cur_line[17] != header.unset_field) {
                    cur_record.san_ip.length = cur_line[17].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[17].split(header.set_seperator).length) {
                        cur_record.san_ip[i] = parseAddress(cur_line[17].split(header.set_seperator)[i]);
                    }
                }

                if (cur_line[18] != header.unset_field) {
                    if (cur_line[18] == "F") {
                        cur_record.basic_constraints_ca = false;
                    } else {
                        cur_record.basic_constraints_ca = true;
                    }
                }

                try {
                    if (cur_line[19] != header.unset_field)
                        cur_record.basic_constraints_path_len = to!int(cur_line[19]);
                } catch (Exception e) {
                    error("Processing basic_constraints_path_len on line %d: %s", line_num, e.msg);
                    continue;
                }

                yield(cur_record);
            }
        });
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

        auto gen = x509_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            X509.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
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
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].id == "FVz825C4jlDdo6b14")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687177.67832;
        results[entry].certificate_version.should == 3;
        results[entry].certificate_serial.should == "4B32DE72CAA28369";
        results[entry].certificate_subject.should == "CN=*.companynameapis.com,O=CompanyName LLC,L=Home Town,ST=California,C=US";
        results[entry].certificate_issuer.should == "CN=CompanyName Internet Authority G3,O=CompanyName Trust Services,C=US";
        results[entry].certificate_not_valid_before.should == 1529422416.000000;
        results[entry].certificate_not_valid_after.should == 1535470260.000000;
        results[entry].certificate_key_alg.should == "id-ecPublicKey";
        results[entry].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[entry].certificate_key_type.should == "ecdsa";
        results[entry].certificate_key_length.should == 256;
        assert(results[entry].certificate_exponent.isNull);
        results[entry].certificate_curve.should == "prime256v1";
        results[entry].san_dns.should == ["*.companynameapis.com", "*.clients6.companyname.com", "*.cloudendpointsapis.com", "cloudendpointsapis.com" ,"companynameapis.com"] ;
        results[entry].san_uri.should == [];
        results[entry].san_email.should == [];
        assert(results[entry].san_ip.isNull);
        results[entry].basic_constraints_ca.should == false;
        assert(results[entry].basic_constraints_path_len.isNull);
    }

    @("x509_read_test_2")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].id == "F8ZbvG3ftnyrB5Ezui")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687177.67832;
        results[entry].certificate_version.should == 3;
        results[entry].certificate_serial.should == "01E3A9301CFC7206383F9A531D";
        results[entry].certificate_subject.should == "CN=CompanyName Internet Authority G3,O=CompanyName Trust Services,C=US";
        results[entry].certificate_issuer.should == "CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R2";
        results[entry].certificate_not_valid_before.should == 1497499242.000000;
        results[entry].certificate_not_valid_after.should == 1639544442.000000;
        results[entry].certificate_key_alg.should == "rsaEncryption";
        results[entry].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[entry].certificate_key_type.should == "rsa";
        results[entry].certificate_key_length.should == 2048;
        results[entry].certificate_exponent.should == 65537;
        assert(results[entry].certificate_curve.isNull);
        results[entry].san_dns.should == [];
        results[entry].san_uri.should == [];
        results[entry].san_email.should == [];
        assert(results[entry].san_ip.isNull);
        results[entry].basic_constraints_ca.should == true;
        results[entry].basic_constraints_path_len.should == 0;
    }

    @("x509_read_test_3")
    unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].id == "FmuFdY1BDVQ6VxTWNb")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687178.26231;
        results[entry].certificate_version.should == 3;
        results[entry].certificate_serial.should == "0A0630427F5BBCED6957396593B6451F";
        results[entry].certificate_subject.should == "CN=testcompany.com,O=TestCompany\\\\, Inc.,L=San Francisco,ST=California,C=US,serialNumber=12344657,jurisdictionST=Delaware,jurisdictionC=US,businessCategory=Private Organization";
        results[entry].certificate_issuer.should == "CN=DigiCert SHA2 Extended Validation Server CA,OU=www.digicert.com,O=DigiCert Inc,C=US";
        results[entry].certificate_not_valid_before.should == 1525752000.000000;
        results[entry].certificate_not_valid_after.should == 1591200000.000000;
        results[entry].certificate_key_alg.should == "rsaEncryption";
        results[entry].certificate_sig_alg.should == "sha256WithRSAEncryption";
        results[entry].certificate_key_type.should == "rsa";
        results[entry].certificate_key_length.should == 2048;
        results[entry].certificate_exponent.should == 65537;
        assert(results[entry].certificate_curve.isNull);
        results[entry].san_dns.should == ["testcompany.com", "www.testcompany.com"];
        results[entry].san_uri.should == [];
        results[entry].san_email.should == [];
        assert(results[entry].san_ip.isNull);
        results[entry].basic_constraints_ca.should == false;
        assert(results[entry].basic_constraints_path_len.isNull);
    }
}
