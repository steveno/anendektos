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

    private static bool instantiated_;
    private __gshared Config instance_;

    private this(string path) {
        try {
            this.ini = Ini.Parse(path);
        } catch (FileException e) {
            throw new Exception("Error reading configuration file: %s", e.msg);
        }
    }

    /**
     * Returns the current instance of the logging object assuming that it has
     * either already been instantiated or the relevant configuration file is
     * in it's default location.
     */
    static Config get() {
        if (!instantiated_) {
            synchronized(Config.classinfo) {
                if (!instance_) {
                    // Default to the current directory
                    try {
                        instance_ = new Config("anendektos.ini");
                    } catch (FileException e) {
                        throw new Exception("Attempted to pull configuration without file path");
                    }
                }

                instantiated_ = true;
            }
        }

        return instance_;
    }

    /**
     * Returns the current instance of the logging object. If it has not been
     * instantiated, a new object is created based upon the path parameter.
     */
    static Config get(string path) {
        if (!instantiated_) {
            synchronized(Config.classinfo) {
                if (!instance_) {
                    instance_ = new Config(path);
                }

                instantiated_ = true;
            }
        }

        return instance_;
    }
}


version(unittest) {
    import unit_threaded;

    @("config_create")
    unittest {
        auto config = new Config("anendektos.ini");
        config.ini["application"].getKey("log_level").should == "warn";
    }

    @("config_create_fail")
    unittest {
        auto config = new Config("/not/a/path").shouldThrow!Exception;
    }

    @("config_create_get_default_path")
    unittest {
        auto config = Config.get();
        config.ini["application"].getKey("log_file").should == "../anendektos.log";
    }

    @("config_create_get_with_path")
    unittest {
        auto config = Config.get("anendektos.ini");
        config.ini["application"].getKey("log_file").should == "../anendektos.log";
    }
}
