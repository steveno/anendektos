// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module parsers.files;

import std.concurrency: Generator, yield;
import std.conv;
import std.socket: Address, parseAddress;
import std.stdio: File;
import std.string: strip, startsWith, split;
import std.typecons: Nullable;

import parser;


class Files : Parser {
    /**
     * Struct to hold the information for a line in files log file.
     */
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

    /**
     * Parse a files log file ensuring that the values in the log file
     * conform to the types in our Record struct.
     *
     * Params: header = a Header object from the Parser class
     *         log_file = a files log file to be parsed
     *
     * Returns: Generator expression which returns a Files.Record struct.
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

                cur_record.fuid = cur_line[1];

                if (cur_line[2] != header.unset_field) {
                    cur_record.tx_hosts.length = cur_line[2].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[2].split(header.set_seperator).length) {
                        cur_record.tx_hosts[i] = parseAddress(cur_line[2].split(header.set_seperator)[i]);
                    }
                }

                if (cur_line[3] != header.unset_field) {
                    cur_record.rx_hosts.length = cur_line[3].split(header.set_seperator).length;
                    foreach (i; 0 .. cur_line[3].split(header.set_seperator).length) {
                        cur_record.rx_hosts[i] = parseAddress(cur_line[3].split(header.set_seperator)[i]);
                    }
                }

                if (cur_line[4] != header.unset_field)
                    cur_record.conn_uids = cur_line[4].split(header.set_seperator);

                cur_record.source = cur_line[5];

                try {
                    cur_record.depth = to!int(cur_line[6]);
                } catch (Exception e) {
                    super.log.error("Processing depth on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[7] != header.empty_field)
                    cur_record.analyzers = cur_line[7].split(header.set_seperator);

                cur_record.mime_type = cur_line[8];

                if (cur_line[9] != header.unset_field)
                    cur_record.filename = cur_line[9];

                try {
                    cur_record.duration = to!double(cur_line[10]);
                } catch (Exception e) {
                    super.log.error("Processing duration on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[11] != header.unset_field) {
                    if (cur_line[11] == "F") {
                        cur_record.local_orig = false;
                    } else {
                        cur_record.local_orig = true;
                    }
                }

                if (cur_line[12] != header.unset_field) {
                    if (cur_line[12] == "F") {
                        cur_record.is_orig = false;
                    } else {
                        cur_record.is_orig = true;
                    }
                }

                try {
                    cur_record.seen_bytes = to!int(cur_line[13]);
                } catch (Exception e) {
                    super.log.error("Processing  on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    if (cur_line[14] != header.unset_field)
                        cur_record.total_bytes = to!int(cur_line[14]);
                } catch (Exception e) {
                    super.log.error("Processing total_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.missing_bytes = to!int(cur_line[15]);
                } catch (Exception e) {
                    super.log.error("Processing missing_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                try {
                    cur_record.overflow_bytes = to!int(cur_line[16]);
                } catch (Exception e) {
                    super.log.error("Processing overflow_bytes on line %d: %s", line_num, e.msg);
                    continue;
                }

                if (cur_line[17] != header.unset_field) {
                    if (cur_line[17] == "F") {
                        cur_record.timedout = false;
                    } else {
                        cur_record.timedout = true;
                    }
                }

                if (cur_line[18] != header.unset_field)
                    cur_record.parent_fuid = cur_line[18];

                if (cur_line[19] != header.unset_field)
                    cur_record.md5 = cur_line[19];

                if (cur_line[20] != header.unset_field)
                    cur_record.sha1 = cur_line[20];

                if (cur_line[21] != header.unset_field)
                    cur_record.sha256 = cur_line[21];

                if (cur_line[22] != header.unset_field)
                    cur_record.extracted = cur_line[22];

                if (cur_line[23] != header.unset_field) {
                    if (cur_line[23] == "F") {
                        cur_record.extracted_cutoff = false;
                    } else {
                        cur_record.extracted_cutoff = true;
                    }
                }

                try {
                    if (cur_line[24] != header.unset_field)
                        cur_record.extracted_size = to!int(cur_line[24]);
                } catch (Exception e) {
                    super.log.error("Processing extracted_size on line %d: %s", line_num, e.msg);
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
    Files.Record[int] results;

    @Setup
    void before() {
        File file = File("tests/logs/files.log", "r");
        auto parser = new Parser();
        header = parser.parse_log_header(file);
        auto files_test = new Files;

        auto gen = files_test.parse_file(header, file);
        auto i = 0;
        while (!gen.empty()) {
            Files.Record record = gen.front();
            results[i] = record;
            gen.popFront();
            i++;
        }
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
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].fuid == "FqxvGx22DT6AwxHGPl")
                entry = i;
        }

        if (entry == -1)
            throw new Exception("Record not found");

        results[entry].ts.should == 1531687175.678291;

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[entry].tx_hosts.length) {
            tx_hosts_[i] = results[entry].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.5"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[entry].rx_hosts.length) {
            rx_hosts_[i] = results[entry].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.2"];

        results[entry].conn_uids.should == ["C49NlPigbiwRa1aJ3"];
        results[entry].source.should == "SSL";
        results[entry].depth.should == 0;
        results[entry].analyzers.should == ["X509", "MD5", "SHA1"];
        results[entry].mime_type.should == "application/pkix-cert";
        results[entry].filename.should == "test_filename";
        results[entry].duration.should == 0.000000;
        results[entry].local_orig.should == true;
        results[entry].is_orig.should == false;
        results[entry].seen_bytes.should == 1964;
        assert(results[entry].total_bytes.isNull);
        results[entry].missing_bytes.should == 0;
        results[entry].overflow_bytes.should == 0;
        results[entry].timedout.should == false;
        assert(results[entry].parent_fuid.isNull);
        results[entry].md5.should == "5c7ef8e7311db007a796fcfb69335e68";
        results[entry].sha1.should == "ccaa484866460e91532c9c7c232ab1744d299d33";
        assert(results[entry].sha256.isNull);
        assert(results[entry].extracted.isNull);
        assert(results[entry].extracted_cutoff.isNull);
        assert(results[entry].extracted_size.isNull);
    }

    @("files_read_record_2")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].fuid == "FFRgqxygVeipwAvKl")
                entry = i;
        }

        results[entry].ts.should == 1531687185.306279;

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[entry].tx_hosts.length) {
            tx_hosts_[i] = results[entry].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["fe80::250:f1ff:fe80:0"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[entry].rx_hosts.length) {
            rx_hosts_[i] = results[entry].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["fe80:541:4303:db20:9db7:490b:983b:62ca"];

        results[entry].conn_uids.should == ["CuVIzg2991yFw6ZZl"];
        results[entry].source.should == "HTTP";
        results[entry].depth.should == 0;
        results[entry].analyzers.shouldBeEmpty();
        results[entry].mime_type.should == "application/ocsp-request";
        assert(results[entry].filename.isNull);
        results[entry].duration.should == 0.000000;
        results[entry].local_orig.should == false;
        results[entry].is_orig.should == true;
        results[entry].seen_bytes.should == 75;
        results[entry].total_bytes.should == 75;
        results[entry].missing_bytes.should == 0;
        results[entry].overflow_bytes.should == 0;
        results[entry].timedout.should == false;
        assert(results[entry].parent_fuid.isNull);
        assert(results[entry].md5.isNull);
        assert(results[entry].sha1.isNull);
        assert(results[entry].sha256.isNull);
        assert(results[entry].extracted.isNull);
        assert(results[entry].extracted_cutoff.isNull);
        assert(results[entry].extracted_size.isNull);
    }

    @("files_read_record_3")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].fuid == "FHDk0m2U0SNRGPYN5g")
                entry = i;
        }

        results[entry].ts.should == 1531687191.158275;

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[entry].tx_hosts.length) {
            tx_hosts_[i] = results[entry].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.2"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[entry].rx_hosts.length) {
            rx_hosts_[i] = results[entry].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.3"];

        results[entry].conn_uids.should == ["Czi9O3kaUI8DpgVCd"];
        results[entry].source.should == "HTTP";
        results[entry].depth.should == 0;
        results[entry].analyzers.shouldBeEmpty();
        results[entry].mime_type.should == "application/ocsp-request";
        assert(results[entry].filename.isNull);
        results[entry].duration.should == 0.000000;
        assert(results[entry].local_orig.isNull);
        results[entry].is_orig.should == true;
        results[entry].seen_bytes.should == 83;
        results[entry].total_bytes.should == 83;
        results[entry].missing_bytes.should == 0;
        results[entry].overflow_bytes.should == 0;
        results[entry].timedout.should == true;
        assert(results[entry].parent_fuid.isNull);
        assert(results[entry].md5.isNull);
        assert(results[entry].sha1.isNull);
        assert(results[entry].sha256.isNull);
        assert(results[entry].extracted.isNull);
        results[entry].extracted_cutoff.should == false;
        assert(results[entry].extracted_size.isNull);
    }

    @("files_read_record_4")
    @safe unittest
    {
        int entry = -1;
        for (int i = 0; i < results.length; i++) {
            if (results[i].fuid == "F6sICI3IY4vu5U4ys1")
                entry = i;
        }

        results[entry].ts.should == 1531687191.190277;

        string[1] tx_hosts_;
        foreach(ulong i; 0 .. results[entry].tx_hosts.length) {
            tx_hosts_[i] = results[entry].tx_hosts[i].toAddrString();
        }
        tx_hosts_.should == ["10.0.0.4"];

        string[1] rx_hosts_;
        foreach(ulong i; 0 .. results[entry].rx_hosts.length) {
            rx_hosts_[i] = results[entry].rx_hosts[i].toAddrString();
        }
        rx_hosts_.should == ["10.0.0.2"];

        results[entry].conn_uids.should == ["Czi9O3kaUI8DpgVCd"];
        results[entry].source.should == "HTTP";
        results[entry].depth.should == 0;
        results[entry].analyzers.shouldBeEmpty();
        results[entry].mime_type.should == "application/ocsp-response";
        assert(results[entry].filename.isNull);
        results[entry].duration.should == 0.000000;
        assert(results[entry].local_orig.isNull);
        results[entry].is_orig.should == false;
        results[entry].seen_bytes.should == 471;
        results[entry].total_bytes.should == 471;
        results[entry].missing_bytes.should == 0;
        results[entry].overflow_bytes.should == 0;
        results[entry].timedout.should == false;
        assert(results[entry].parent_fuid.isNull);
        assert(results[entry].md5.isNull);
        assert(results[entry].sha1.isNull);
        assert(results[entry].sha256.isNull);
        assert(results[entry].extracted.isNull);
        results[entry].extracted_cutoff.should == true;
        results[entry].extracted_size.should == 1800;
    }
}
