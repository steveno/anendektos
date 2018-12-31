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

        foreach (ulong i; 1 .. args.length) {
            if (args[i] == "--help" || args[i] == "-h") {
                print_help();
                break;
            }

            if (args[i] == "--version" || args[i] == "-v") {
                print_version();
                break;
            }

            if (args[i] == "config_path") {
                if (i + 1 < args.length) {
                    this.config_path = args[i + 1];
                    continue;
                } else {
                    ret_msg = "config_path must be passed with a path";
                    break;
                }
            }

            if (args[i] == "bro_path") {
                if (i + 1 < args.length) {
                    bro_path = args[i + 1];
                    continue;
                } else {
                    ret_msg = "bro_path must be passed with a path";
                    break;
                }
            }

            if (args[i] == "out_path") {
                if (i + 1 < args.length) {
                    out_path = args[i + 1];
                    continue;
                } else {
                    ret_msg = "out_path must be passed with a path";
                    break;
                }
            }

            stderr.writefln("ERROR Unknown command line argument %s", args[i]);
            print_help();
            break;
        }

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
        auto m = mock!Arguments();
        m.parse_arguments(["./anendektos", "--help"]);
        m.expectCalled!"print_help"();
    }

    @("arguments_help_short")
    unittest
    {
        auto m = mock!Arguments;
        m.parse_arguments(["./anendektos", "-h"]);
        m.expectCalled!"print_help"();
    }

    @("arguments_version_long")
    unittest
    {
        auto m = mock!Arguments;
        m.parse_arguments(["./anendektos", "--version"]);
        m.expectCalled!"print_version"();
    }

    @("arguments_version_short")
    unittest
    {
        auto m = mock!Arguments;
        m.parse_arguments(["./anendektos", "-v"]);
        m.expectCalled!"print_version"();
    }
    */
}
