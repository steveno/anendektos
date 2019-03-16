// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module arguments;

import std.stdio;


class Arguments {
    string bro_path = "";
    string config_path = "";

    /**
     * Parse the command line arguments from the command line.
     */
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

            stderr.writefln("Unknown command line argument %s", args[i]);
            print_help();
            break;
        }

        if (config_path == "" && ret_msg != "0")
            throw new Exception("A configuration file must be passed in");

        return ret_msg;
    }

    /**
     * Print the application version to the command line.
     */
    private void print_version() {
        writeln("anendektos - version 1.0.0");
    }

    /**
     * Print the help text to the command line.
     */
    private void print_help() {
        string help_text = "
Usage: anendektos [--help] [--version] bro_path [bro_path] config_path [config_path]

Positional arguments:
 config_path    Path to configuration file

Named arguments
 --help, -h     Print this help message
 --version, -v  Print version information";

        writeln(help_text);
    }
}

version(unittest) {
    import unit_threaded;

    @("arguments_config_path")
    unittest {
        auto args = new Arguments();
        args.parse_arguments(["./test", "config_path", "/home/user/user.ini"]);
        args.config_path.should == "/home/user/user.ini";
    }

    @("arguments_config_path_no_path")
    unittest {
        auto args = new Arguments();
        args.parse_arguments(["./test", "config_path"]).shouldThrow!Exception;
    }
}
