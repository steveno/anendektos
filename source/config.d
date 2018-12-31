// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

module config;

import std.file;
import std.stdio;

import dini;


class Config
{
    public Ini ini;
    
    private string config_path;
    private static bool instantiated_;
    private __gshared Config instance_;

    private this(string path) {
        this.config_path = path;
        parse();
    }

    static Config get(string path)
    {
        if (!instantiated_)
        {
            synchronized(Config.classinfo)
            {
                if (!instance_)
                {
                    instance_ = new Config(path);
                }

                instantiated_ = true;
            }
        }

        return instance_;
    }

    private int parse() {
        // Try and find the config file
        try {
            this.ini = Ini.Parse(this.config_path);
            return 0;
        } catch (FileException e) {
            stderr.writefln("Error reading configuration file: %s", e.msg);
            return 1;
        } 
    }
}
