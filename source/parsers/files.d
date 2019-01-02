// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.files;

import std.conv;
import std.socket;
import std.stdio;
import std.string;
import std.typecons;

import parser;


class Files : Parser {
    struct Record {
        double ts;
        string fuid;
        Address[] tx_hosts;
        Address[] rx_hosts;
        string[] conn_uids;
        string source;
        int depth;
        string[] analyzers;
        string mime_type;
        Nullable!(string) filename;
        double duration;
        Nullable!(bool) local_orig;
        bool is_orig;
        int seen_bytes;
        Nullable!(int) total_bytes;
        int missing_bytes;
        int overflow_bytes;
        bool timedout;
        Nullable!(string) parent_fuid;
        Nullable!(string) md5;
        Nullable!(string) sha1;
        Nullable!(string) sha256;
        Nullable!(string) extracted;
        Nullable!(bool) extracted_cutoff;
        Nullable!(int) extracted_size;
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
            cur_record.fuid = line[1];

            if (line[2] != header.unset_field) {
                cur_record.tx_hosts.length = line[2].split(header.set_seperator).length;
                foreach (i; 0 .. line[2].split(header.set_seperator).length) {
                    cur_record.tx_hosts[i] = parseAddress(line[2].split(header.set_seperator)[i]);
                }
            }

            if (line[3] != header.unset_field) {
                cur_record.rx_hosts.length = line[3].split(header.set_seperator).length;
                foreach (i; 0 .. line[3].split(header.set_seperator).length) {
                    cur_record.rx_hosts[i] = parseAddress(line[3].split(header.set_seperator)[i]);
                }
            }

            if (line[4] != header.unset_field)
                cur_record.conn_uids = line[4].split(header.set_seperator);

            cur_record.source = line[5];
            cur_record.depth = to!int(line[6]);

            if (line[7] != header.empty_field)
                cur_record.analyzers = line[7].split(header.set_seperator);

            cur_record.mime_type = line[8];

            if (line[9] != header.unset_field)
                cur_record.filename = line[9];

            cur_record.duration = to!double(line[10]);

            if (line[11] != header.unset_field) {
                if (line[11] == "F") {
                    cur_record.local_orig = false;
                } else {
                    cur_record.local_orig = true;
                }
            }

            if (line[12] != header.unset_field) {
                if (line[12] == "F") {
                    cur_record.is_orig = false;
                } else {
                    cur_record.is_orig = true;
                }
            }

            cur_record.seen_bytes = to!int(line[13]);

            if (line[14] != header.unset_field)
                cur_record.total_bytes = to!int(line[14]);

            cur_record.missing_bytes = to!int(line[15]);
            cur_record.overflow_bytes = to!int(line[16]);

            if (line[17] != header.unset_field) {
                if (line[17] == "F") {
                    cur_record.timedout = false;
                } else {
                    cur_record.timedout = true;
                }
            }

            if (line[18] != header.unset_field)
                cur_record.parent_fuid = line[18];

            if (line[19] != header.unset_field)
                cur_record.md5 = line[19];

            if (line[20] != header.unset_field)
                cur_record.sha1 = line[20];

            if (line[21] != header.unset_field)
                cur_record.sha256 = line[21];

            if (line[22] != header.unset_field)
                cur_record.extracted = line[22];

            if (line[23] != header.unset_field) {
                if (line[23] == "F") {
                    cur_record.extracted_cutoff = false;
                } else {
                    cur_record.extracted_cutoff = true;
                }
            }

            if (line[24] != header.unset_field)
                cur_record.extracted_size = to!int(line[24]);

            ++rec_num;
            contents[rec_num] = cur_record;
        }

        return contents;
    }
}


version(unittest) {
    import unit_threaded;
    Parser.Header header;
    Files.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/files.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto files_test = new Files;
        results = files_test.parse_file(header, file);
    }

    @("files_read_header")
    @safe unittest
    {
        header.seperator.should == "\t";
        header.set_seperator.should == ",";
        header.empty_field.should == "(empty)";
        header.unset_field.should == "-";
        header.path.should == "files";
    }

    @("files_record_count")
    @safe unittest
    {
        results.length.should == 4;
    }

    @("files_read_record_1")
    @safe unittest
    {
        results[1].ts.should == 1531687175.678291;
        results[1].fuid.should == "FqxvGx22DT6AwxHGPl";

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[1].tx_hosts.length) {
            tx_hosts_[i] = results[1].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.5"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[1].rx_hosts.length) {
            rx_hosts_[i] = results[1].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.2"];

        results[1].conn_uids.should == ["C49NlPigbiwRa1aJ3"];
        results[1].source.should == "SSL";
        results[1].depth.should == 0;
        results[1].analyzers.should == ["X509", "MD5", "SHA1"];
        results[1].mime_type.should == "application/pkix-cert";
        results[1].filename.should == "test_filename";
        results[1].duration.should == 0.000000;
        results[1].local_orig.should == true;
        results[1].is_orig.should == false;
        results[1].seen_bytes.should == 1964;
        assert(results[1].total_bytes.isNull);
        results[1].missing_bytes.should == 0;
        results[1].overflow_bytes.should == 0;
        results[1].timedout.should == false;
        assert(results[1].parent_fuid.isNull);
        results[1].md5.should == "5c7ef8e7311db007a796fcfb69335e68";
        results[1].sha1.should == "ccaa484866460e91532c9c7c232ab1744d299d33";
        assert(results[1].sha256.isNull);
        assert(results[1].extracted.isNull);
        assert(results[1].extracted_cutoff.isNull);
        assert(results[1].extracted_size.isNull);
    }

    @("files_read_record_2")
    @safe unittest
    {
        results[2].ts.should == 1531687185.306279;
        results[2].fuid.should == "FFRgqxygVeipwAvKl";

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[2].tx_hosts.length) {
            tx_hosts_[i] = results[2].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["fe80::250:f1ff:fe80:0"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[2].rx_hosts.length) {
            rx_hosts_[i] = results[2].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["fe80:541:4303:db20:9db7:490b:983b:62ca"];

        results[2].conn_uids.should == ["CuVIzg2991yFw6ZZl"];
        results[2].source.should == "HTTP";
        results[2].depth.should == 0;
        results[2].analyzers.shouldBeEmpty();
        results[2].mime_type.should == "application/ocsp-request";
        assert(results[2].filename.isNull);
        results[2].duration.should == 0.000000;
        results[2].local_orig.should == false;
        results[2].is_orig.should == true;
        results[2].seen_bytes.should == 75;
        results[2].total_bytes.should == 75;
        results[2].missing_bytes.should == 0;
        results[2].overflow_bytes.should == 0;
        results[2].timedout.should == false;
        assert(results[2].parent_fuid.isNull);
        assert(results[2].md5.isNull);
        assert(results[2].sha1.isNull);
        assert(results[2].sha256.isNull);
        assert(results[2].extracted.isNull);
        assert(results[2].extracted_cutoff.isNull);
        assert(results[2].extracted_size.isNull);
    }

    @("files_read_record_3")
    @safe unittest
    {
        results[3].ts.should == 1531687191.158275;
        results[3].fuid.should == "FHDk0m2U0SNRGPYN5g";

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[3].tx_hosts.length) {
            tx_hosts_[i] = results[3].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.2"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[3].rx_hosts.length) {
            rx_hosts_[i] = results[3].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.3"];

        results[3].conn_uids.should == ["Czi9O3kaUI8DpgVCd"];
        results[3].source.should == "HTTP";
        results[3].depth.should == 0;
        results[3].analyzers.shouldBeEmpty();
        results[3].mime_type.should == "application/ocsp-request";
        assert(results[3].filename.isNull);
        results[3].duration.should == 0.000000;
        assert(results[3].local_orig.isNull);
        results[3].is_orig.should == true;
        results[3].seen_bytes.should == 83;
        results[3].total_bytes.should == 83;
        results[3].missing_bytes.should == 0;
        results[3].overflow_bytes.should == 0;
        results[3].timedout.should == true;
        assert(results[3].parent_fuid.isNull);
        assert(results[3].md5.isNull);
        assert(results[3].sha1.isNull);
        assert(results[3].sha256.isNull);
        assert(results[3].extracted.isNull);
        results[3].extracted_cutoff.should == false;
        assert(results[3].extracted_size.isNull);
    }

    @("files_read_record_4")
    @safe unittest
    {
        results[4].ts.should == 1531687191.190277;
        results[4].fuid.should == "F6sICI3IY4vu5U4ys1";

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[4].tx_hosts.length) {
            tx_hosts_[i] = results[4].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.4"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[4].rx_hosts.length) {
            rx_hosts_[i] = results[4].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.2"];

        results[4].conn_uids.should == ["Czi9O3kaUI8DpgVCd"];
        results[4].source.should == "HTTP";
        results[4].depth.should == 0;
        results[4].analyzers.shouldBeEmpty();
        results[4].mime_type.should == "application/ocsp-response";
        assert(results[4].filename.isNull);
        results[4].duration.should == 0.000000;
        assert(results[4].local_orig.isNull);
        results[4].is_orig.should == false;
        results[4].seen_bytes.should == 471;
        results[4].total_bytes.should == 471;
        results[4].missing_bytes.should == 0;
        results[4].overflow_bytes.should == 0;
        results[4].timedout.should == false;
        assert(results[4].parent_fuid.isNull);
        assert(results[4].md5.isNull);
        assert(results[4].sha1.isNull);
        assert(results[4].sha256.isNull);
        assert(results[4].extracted.isNull);
        results[4].extracted_cutoff.should == true;
        results[4].extracted_size.should == 1800;
    }
}
