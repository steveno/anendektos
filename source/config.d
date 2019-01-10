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
