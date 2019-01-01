// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

import std.file;
import std.stdio;

import dlogg.log;
import dlogg.strict;

import arguments;
import config;
import parser;


version(unittest) {}
else {
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
        if (msg != "") {
            stderr.writeln(msg);
            return 1;
        }

        // If a config path was passed in use it
        if (arg_parser.config_path != "") {
            config.Config options = config.Config.get(arg_parser.config_path);

            shared ILogger logger = new shared StrictLogger(options.ini["application"].getKey("log_file"));
            switch (options.ini["application"].getKey("log_level"))
            {
                default:
                stderr.writefln("Unknown log_level configuration option \"%s\"", options.ini["application"].getKey("log_level"));
                return 1;

                case "Notice":
                logger.minOutputLevel = LoggingLevel.Notice;
                break;

                case "Warning":
                logger.minOutputLevel = LoggingLevel.Warning;
                break;

                case "Debug":
                logger.minOutputLevel = LoggingLevel.Debug;
                break;

                case "Fatal":
                logger.minOutputLevel = LoggingLevel.Fatal;
                break;

                case "Muted":
                logger.minOutputLevel = LoggingLevel.Muted;
                break;
            }

            parse_logs(options.ini["application"].getKey("bro_path"), options.ini["application"].getKey("out_path"));
        }
        // Since no config file was given see if any other command line arguments were given
        else {
            if (arg_parser.bro_path != "" && arg_parser.out_path != "")
                parse_logs(arg_parser.bro_path, arg_parser.out_path);
        }

        return 0;
    }
}

void parse_logs(string bro_path, string out_path) {
    parser.Parser log_parser = new parser.Parser(bro_path, out_path);
    log_parser.parse_logs();
}
