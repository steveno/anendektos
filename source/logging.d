//          Copyright Steven Oliver 2018.
//          Copyright Mario Kröplin 2018.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

module logging;

import std.algorithm;
import std.array;
import std.conv;
import std.datetime;
import std.format;
import std.range;
import std.stdio;
import std.string;
import std.traits;

/**
 * Defines the importance of a log message.
 *
 * There are five different logging levels:
 *  * Trace = detailed tracing
 *  * Info  = useful information
 *  * Warn  = potential problem
 *  * Error = recoverable error
 *  * Fatal = fatal failure
 */
enum LogLevel {
    Trace = 1,
    Info = 2,
    Warn = 4,
    Error = 8,
    Fatal = 16,
}

/**
 * Returns a bit set containing the level and all levels above.
 */
@safe uint orAbove(LogLevel level) pure {
    return [EnumMembers!LogLevel].find(level).reduce!"a | b";
}

/**
 * Returns a bit set containing the level and all levels below.
 */
@safe uint orBelow(LogLevel level) pure {
    return [EnumMembers!LogLevel].retro.find(level).reduce!"a | b";
}

/**
 * Return whether or not a specific level is disabled.
 */
@safe bool disabled(LogLevel level) pure {
    uint levels = 0;

    with (LogLevel) {
        version (DisableTrace)
            levels |= Trace;
        version (DisableInfo)
            levels |= Info;
        version (DisableWarn)
            levels |= Warn;
        version (DisableError)
            levels |= Error;
        version (DisableFatal)
            levels |= Fatal;
    }
    return (level & levels) != 0;
}

struct Log {
    private Logger[] loggers;

    private uint levels;

    this(Logger[] loggers ...)
    in {
        assert(loggers.all!"a !is null");
    } body {
        this.loggers = loggers.dup;
        levels = reduce!((a, b) => a | b.levels)(0, this.loggers);
    }

    alias trace = append!(LogLevel.Trace);
    alias info = append!(LogLevel.Info);
    alias warn = append!(LogLevel.Warn);
    alias error = append!(LogLevel.Error);
    alias fatal = append!(LogLevel.Fatal);

    private struct Fence {}  // argument cannot be provided explicitly

    template append(LogLevel level) {
        void append(alias fmt, Fence _ = Fence(), string file = __FILE__, size_t line = __LINE__, A...)
            (lazy A args)
        if (isSomeString!(typeof(fmt))) {
            static if (!level.disabled)
                if (level & levels)
                    _append(level, file, line, format!fmt(args));
        }

        void append(Fence _ = Fence(), string file = __FILE__, size_t line = __LINE__, Char, A...)
            (in Char[] fmt, lazy A args) {
            static if (!level.disabled)
                if (level & levels)
                    _append(level, file, line, format(fmt, args));
        }

        void append(Fence _ = Fence(), string file = __FILE__, size_t line = __LINE__, A)
            (lazy A arg) {
            static if (!level.disabled)
                if (level & levels)
                    _append(level, file, line, arg.to!string);
        }
    }

    private void _append(LogLevel level, string file, size_t line, string message) {
        LogEvent event;

        event.time = Clock.currTime;
        event.level = level;
        event.file = file;
        event.line = line;
        event.message = message;

        foreach (logger; loggers)
            if (level & logger.levels)
                logger.append(event);
    }
}

__gshared Log log;

shared static this() {
    log = Log(stderrLogger);
}

/**
 * Represents a logging event.
 */
struct LogEvent {
    /// local _time of the event
    SysTime time;
    /// importance of the event
    LogLevel level;
    /// _file name of the event source
    string file;
    /// _line number of the event source
    size_t line;
    /// supplied _message
    string message;
}

auto fileLogger(alias Layout = layout)
    (string name, uint levels = LogLevel.Info.orAbove) {
    return new FileLogger!Layout(name, levels);
}

auto stderrLogger(alias Layout = layout)
    (uint levels = LogLevel.Warn.orAbove) {
    return new FileLogger!Layout(stderr, levels);
}

auto stdoutLogger(alias Layout = layout)
    (uint levels = LogLevel.Info.orAbove) {
    return new FileLogger!Layout(stdout, levels);
}

version (Posix)
    auto syslogLogger(alias Layout = syslogLayout)
        (string name = null, uint levels = LogLevel.Info.orAbove) {
        return new SyslogLogger!Layout(name, levels);
    }

abstract class Logger {
    private uint levels;

    this(uint levels) {
        this.levels = levels;
    }

    abstract void append(ref LogEvent event);
}

class FileLogger(alias Layout) : Logger {
    private File file;

    this(string name, uint levels = LogLevel.Info.orAbove) {
        super(levels);
        file = File(name, "ab");
    }

    this(File file, uint levels = LogLevel.Info.orAbove) {
        super(levels);
        this.file = file;
    }

    override void append(ref LogEvent event) {
        Layout(this.file.lockingTextWriter, event);
        this.file.flush;
    }
}

version (Posix) {
    private extern (C) void openlog(const char *ident, int option, int facility);

    private extern (C) void syslog(int priority, const char *format, ...);

    class SyslogLogger(alias Layout) : Logger {
        enum SyslogLevel {
            LOG_EMERG   = 0,  // system is unusable
            LOG_ALERT   = 1,  // action must be taken immediately
            LOG_CRIT    = 2,  // critical conditions
            LOG_ERR     = 3,  // error conditions
            LOG_WARNING = 4,  // warning conditions
            LOG_NOTICE  = 5,  // normal but significant condition
            LOG_INFO    = 6,  // informational
            LOG_DEBUG   = 7,  // debug-level messages
        }

        this(string identifier = null, uint levels = LogLevel.Info.orAbove) {
            enum LOG_USER = 1 << 3;

            super(levels);
            openlog(identifier.empty ? null : identifier.toStringz, 0, LOG_USER);
        }

        override void append(ref LogEvent event) {
            auto writer = appender!string;

            Layout(writer, event);
            writer.put('\0');
            syslog(priority(event.level), "%s", writer.data.ptr);
        }

        static SyslogLevel priority(LogLevel level) pure {
            final switch (level) with (LogLevel) with (SyslogLevel) {
                case Trace:
                    return LOG_DEBUG;
                case Info:
                    return LOG_INFO;
                case Warn:
                    return LOG_WARNING;
                case Error:
                    return LOG_ERR;
                case Fatal:
                    return LOG_CRIT;
            }
        }
    }

    void syslogLayout(Writer)(Writer writer, ref LogEvent event) {
        writer.put(event.message);
    }
}

/**
 * Time Thread Category Context layout
 */
void layout(Writer)(Writer writer, ref LogEvent event) {
    import core.thread : Thread;

    with (event) {
        writer.formattedWrite!"%s %-5s %s:%s"(time._toISOExtString, level, file, line);

        if (Thread thread = Thread.getThis) {
            string name = thread.name;

            if (!name.empty)
                writer.formattedWrite!" [%s]"(name);
        }

        writer.put(' ');
        writer.put(message);
        writer.put('\n');
    }
}

/**
 * SysTime.toISOExtString has no fixed length and no time-zone offset for local time
 */
private string _toISOExtString(SysTime time) {
    return format!"%s.%03d%s"(
        (cast (DateTime) time).toISOExtString,
        time.fracSecs.total!"msecs",
        time.utcOffset._toISOString);
}

/**
 * SimpleTimeZone.toISOString is private
 */
@safe private string _toISOString(Duration offset) pure {
    uint hours;
    uint minutes;

    abs(offset).split!("hours", "minutes")(hours, minutes);
    return format!"%s%02d:%02d"(offset.isNegative ? '-' : '+', hours, minutes);
}

version(unittest) {
    import unit_threaded;

    @("logging_orAbove")
    @safe pure unittest {
        with (LogLevel)
        {
            assert(Trace.orAbove == (Trace | Info | Warn | Error | Fatal));
            assert(Fatal.orAbove == Fatal);
        }
    }

    @("logging_orBelow")
    @safe pure unittest {
        with (LogLevel)
        {
            assert(Trace.orBelow == Trace);
            assert(Fatal.orBelow == (Trace | Info | Warn | Error | Fatal));
        }
    }

    @("logging_datetime")
    unittest {
        auto dateTime = DateTime(2003, 2, 1, 12);
        auto fracSecs = 123_456.usecs;
        auto timeZone =  new immutable SimpleTimeZone(1.hours);
        auto time = SysTime(dateTime, fracSecs, timeZone);

        assert(time._toISOExtString == "2003-02-01T12:00:00.123+01:00");
    }

    @("logging_writer")
    unittest {
        LogEvent event;

        event.time = SysTime.fromISOExtString("2003-02-01T11:55:00.123456Z");
        event.level = LogLevel.Error;
        event.file = "log.d";
        event.line = 42;
        event.message = "don't panic";

        auto writer = appender!string;

        layout(writer, event);
        assert(writer.data == "2003-02-01T11:55:00.123+00:00 Error log.d:42 don't panic\n");
    }

    @("logging_to_iso_string")
    unittest {
        assert(_toISOString(90.minutes) == "+01:30");
        assert(_toISOString(-90.minutes) == "-01:30");
    }
}
