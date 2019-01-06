// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module arguments;

import std.stdio;


class Arguments {
    string bro_path = "";
    string out_path = "";
    string config_path = "";

    public string parse_arguments(string[] args) {
        string ret_msg = "";
        bool skip_next = false;

        foreach (ulong i; 1 .. args.length) {
            if (skip_next) {
                skip_next = false;
                continue;
            }

            if (args[i] == "--help" || args[i] == "-h") {
                print_help();
                ret_msg = "0";
                break;
            }

            if (args[i] == "--version" || args[i] == "-v") {
                print_version();
                ret_msg = "0";
                break;
            }

            if (args[i] == "config_path") {
                if (i + 1 < args.length) {
                    this.config_path = args[i + 1];
                    skip_next = true;
                    continue;
                } else {
                    ret_msg = "config_path must be passed with a path";
                    break;
                }
            }

            if (args[i] == "bro_path") {
                if (i + 1 < args.length) {
                    bro_path = args[i + 1];
                    skip_next = true;
                    continue;
                } else {
                    ret_msg = "bro_path must be passed with a path";
                    break;
                }
            }

            if (args[i] == "out_path") {
                if (i + 1 < args.length) {
                    out_path = args[i + 1];
                    skip_next = true;
                    continue;
                } else {
                    ret_msg = "out_path must be passed with a path";
                    break;
                }
            }

            stderr.writefln("Unknown command line argument %s", args[i]);
            print_help();
            break;
        }

        if (config_path == "" && ret_msg != "0")
            throw new Exception("A configuration file must be passed in");

        return ret_msg;
    }

    private void print_version() {
        writeln("anendektos - version 1.0.0");
    }

    private void print_help() {
        string help_text = "
Usage: anendektos [--help] [--version] bro_path [bro_path] out_path
                  [out_path] config_path [config_path]

Positional arguments:
 bro_path       Path to bro logs to parse
 out_path       Path to output analysis to
 config_path    Path to configuration file

Named arguments
 --help, -h     Print this help message
 --version, -v  Print version information";

        writeln(help_text);
    }
}

version(unittest) {
    import unit_threaded;

    /*
    @("arguments_help_long")
    unittest
    {
        // TODO
    }

    @("arguments_help_short")
    unittest
    {
        // TODO
    }

    @("arguments_version_long")
    unittest
    {
        // TODO
    }

    @("arguments_version_short")
    unittest
    {
        // TODO
    }
    */

    @("arguments_config_path")
    unittest
    {
        auto args = new Arguments();
        args.parse_arguments(["./test", "config_path", "/home/user/user.ini"]);
        args.config_path.should == "/home/user/user.ini";
    }

    @("arguments_bro_path")
    unittest
    {
        auto args = new Arguments();
        args.parse_arguments(["./test", "bro_path", "/home/user/bro"]).shouldThrow!Exception;
    }

    @("arguments_out_path")
    unittest
    {
        auto args = new Arguments();
        args.parse_arguments(["./test", "out_path", "/home/user/out"]).shouldThrow!Exception;
    }

    @("arguments_bro_out_path")
    unittest
    {
        auto args = new Arguments();
        args.parse_arguments(["./test", "bro_path", "/home/user/bro", "out_path", "/home/user/out"]).shouldThrow!Exception;
    }

    @("arguments_bro_out_config_path")
    unittest
    {
        auto args = new Arguments();
        args.parse_arguments(["./test", "bro_path", "/home/user/bro", "out_path", "/home/user/out", "config_path", "/home/user/user.ini"]);
        args.out_path.should == "/home/user/out";
        args.bro_path.should == "/home/user/bro";
        args.config_path.should == "/home/user/user.ini";
    }
}
