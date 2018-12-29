// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

import std.file;
import std.stdio;

import dlogg.log;
import dlogg.strict;

import arguments;
import parser;


version(unittest) {}
else {
    int main(string[] args)
    {
        arguments.Arguments arg_parser = new arguments.Arguments();
        string msg = arg_parser.parse_arguments(args);
        if (msg != "") {
            stderr.writeln(msg);
            return 1;
        }

        shared ILogger logger = new shared StrictLogger("anendektos.log");

        if (arg_parser.bro_path != "" && arg_parser.out_path != "")
            parse_logs(arg_parser.bro_path, arg_parser.out_path);

        return 0;
    }
}

void parse_logs(string bro_path, string out_path) {
    parser.Parser log_parser = new parser.Parser();
    log_parser.bro_path = bro_path;
    log_parser.out_path = out_path;
    log_parser.parse_logs();
}
