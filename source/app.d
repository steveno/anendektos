// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

import std.stdio;
import std.experimental.logger;

import arguments;
import config;
import parser;


version(unittest) {
} else {
    int main(string[] args)
    {
        // We require at least one argument
        if (args.length < 2) {
            stderr.writeln("At least one command line argument is required");
            return 1;
        }

        // Parse arguments from the command line
        arguments.Arguments arg_parser = new arguments.Arguments();
        string msg = arg_parser.parse_arguments(args);
        if (msg == "0") {
            return 0;
        } else if (msg != "0" && msg != "") {
            stderr.writeln(msg);
            return 1;
        }

        // Parse our configuration and try and parse our bro logs
        const config.Config options = config.Config.get(arg_parser.config_path);
        auto log_parser = new parser.Parser();
        log_parser.parse_logs();

        return 0;
    }
}
