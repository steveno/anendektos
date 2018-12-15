/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import std.stdio;
import std.getopt;

import parser;


version(unittest) {}
else {
    void main(string[] args)
    {
        string log_path;
        string out_path;
        bool app_version;

        auto helpInformation = getopt (
                args,
                "log_path|l", "Path to bro logs", &log_path,
                "out_path|o", "Path to output analysis results", &out_path,
                "version|v", "Version information", &app_version,
                );

        if (helpInformation.helpWanted) {
            defaultGetoptPrinter("anendektos - bro log parser and summarizer",
                    helpInformation.options);
        }

        if (app_version) {
            writeln("anendektos - 1.0.0");
            return;
        }

        if (log_path && out_path) {
            parser.Parser log_parser = new parser.Parser();
            log_parser.log_path = log_path;
            log_parser.out_path = out_path;
            log_parser.parse_logs();
        } else {
            writeln("ERROR: You must pass both an input and output directory!");
        }
    }
}
