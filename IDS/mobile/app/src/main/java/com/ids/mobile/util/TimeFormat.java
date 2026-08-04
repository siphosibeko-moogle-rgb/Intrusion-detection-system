package com.ids.mobile.util;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

/**
 * Timestamp helpers.
 *
 * The backend emits Instant.toString() (ISO-8601, UTC, e.g.
 * "2026-07-25T09:14:03.221Z"). On a glance screen an absolute UTC timestamp is
 * close to useless — "4m ago" answers the actual question, which is whether
 * this is happening NOW. We fall back to the raw string rather than throwing if
 * the format ever changes.
 *
 * java.time is available without desugaring because minSdk is 26.
 */
public final class TimeFormat {

    private static final DateTimeFormatter CLOCK =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private TimeFormat() { }

    /** "just now" / "4m ago" / "3h ago" / "2d ago". */
    public static String relative(String isoTimestamp) {
        if (isoTimestamp == null || isoTimestamp.isEmpty()) return "unknown";
        try {
            Instant then = Instant.parse(isoTimestamp);
            long seconds = Duration.between(then, Instant.now()).getSeconds();

            if (seconds < 0)    return "just now";   // minor clock skew between phone and server
            if (seconds < 60)   return seconds + "s ago";
            if (seconds < 3600) return (seconds / 60) + "m ago";
            if (seconds < 86400) return (seconds / 3600) + "h ago";
            return (seconds / 86400) + "d ago";
        } catch (Exception e) {
            return isoTimestamp;
        }
    }

    /** Local wall-clock time, for the "last updated" line. */
    public static String nowClock() {
        return CLOCK.format(Instant.now());
    }
}
