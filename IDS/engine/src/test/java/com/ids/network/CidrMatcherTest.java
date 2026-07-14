package com.ids.network;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CidrMatcherTest {

    // ── PARSING ─────────────────────────────────────────────────────────────

    @Test
    void parsesWellFormedCidr() {
        assertNotNull(CidrMatcher.parse("104.16.0.0/13"));
        assertNotNull(CidrMatcher.parse("0.0.0.0/0"));
        assertNotNull(CidrMatcher.parse("255.255.255.255/32"));
        assertNotNull(CidrMatcher.parse("  8.8.8.0/24  ")); // trims
    }

    @Test
    void rejectsMalformedInput() {
        assertNull(CidrMatcher.parse(null));
        assertNull(CidrMatcher.parse(""));
        assertNull(CidrMatcher.parse("104.16.0.0"));      // no prefix
        assertNull(CidrMatcher.parse("104.16.0.0/"));     // empty prefix
        assertNull(CidrMatcher.parse("104.16.0.0/33"));   // prefix > 32
        assertNull(CidrMatcher.parse("104.16.0.0/-1"));   // negative prefix
        assertNull(CidrMatcher.parse("104.16.0.0/ab"));   // non-numeric prefix
        assertNull(CidrMatcher.parse("104.16.0/24"));     // 3 octets
        assertNull(CidrMatcher.parse("1.2.3.4.5/24"));    // 5 octets
        assertNull(CidrMatcher.parse("104.16.0.256/24")); // octet > 255
        assertNull(CidrMatcher.parse("2606:4700::/32"));  // IPv6: not supported
        assertNull(CidrMatcher.parse("cloudflare/13"));   // not an address
    }

    // ── MATCHING ────────────────────────────────────────────────────────────

    @Test
    void matchesInsideBlockIncludingBoundaries() {
        CidrMatcher cloudflare = CidrMatcher.parse("104.16.0.0/13");
        assertTrue(cloudflare.matches("104.16.0.0"));      // network address
        assertTrue(cloudflare.matches("104.16.132.229"));
        assertTrue(cloudflare.matches("104.23.255.255")); // last address in /13
    }

    @Test
    void rejectsOutsideBlock() {
        CidrMatcher cloudflare = CidrMatcher.parse("104.16.0.0/13");
        assertFalse(cloudflare.matches("104.24.0.0"));  // first address past /13
        assertFalse(cloudflare.matches("104.15.255.255"));
        assertFalse(cloudflare.matches("8.8.8.8"));
        assertFalse(cloudflare.matches("not-an-ip"));
        assertFalse(cloudflare.matches(null));
    }

    @Test
    void hostBitsInTheBaseAreMaskedOff() {
        // "104.17.5.9/13" is sloppy input but unambiguous — the block is
        // whatever /13 contains 104.17.5.9, i.e. 104.16.0.0/13.
        CidrMatcher sloppy = CidrMatcher.parse("104.17.5.9/13");
        assertTrue(sloppy.matches("104.16.0.1"));
        assertFalse(sloppy.matches("104.24.0.1"));
    }

    @Test
    void slashZeroMatchesEverythingAndSlash32ExactlyOne() {
        CidrMatcher all = CidrMatcher.parse("0.0.0.0/0");
        assertTrue(all.matches("1.2.3.4"));
        assertTrue(all.matches("255.255.255.255"));

        CidrMatcher single = CidrMatcher.parse("8.8.8.8/32");
        assertTrue(single.matches("8.8.8.8"));
        assertFalse(single.matches("8.8.8.9"));
    }

    // ── IPv4 PARSER ─────────────────────────────────────────────────────────

    @Test
    void ipv4ToLongHandlesEdgesAndGarbage() {
        assertEquals(0L, CidrMatcher.ipv4ToLong("0.0.0.0"));
        assertEquals(0xFFFFFFFFL, CidrMatcher.ipv4ToLong("255.255.255.255"));
        assertEquals(-1, CidrMatcher.ipv4ToLong("256.0.0.1"));
        assertEquals(-1, CidrMatcher.ipv4ToLong("1.2.3"));
        assertEquals(-1, CidrMatcher.ipv4ToLong("1.2.3.4.5"));
        assertEquals(-1, CidrMatcher.ipv4ToLong("1..2.3"));
        assertEquals(-1, CidrMatcher.ipv4ToLong("::1"));
        assertEquals(-1, CidrMatcher.ipv4ToLong(""));
        assertEquals(-1, CidrMatcher.ipv4ToLong(null));
        assertEquals(-1, CidrMatcher.ipv4ToLong("1.2.3.4 "));  // no trim by design
        assertEquals(-1, CidrMatcher.ipv4ToLong("1234.1.1.1")); // >3 digits
    }
}
