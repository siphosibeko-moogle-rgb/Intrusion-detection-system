package com.ids.service;

import com.ids.service.ProviderFeedParser.FeedRange;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Pure-parse tests against captured feed shapes — no network. */
class ProviderFeedParserTest {

    // ── CLOUDFLARE (plain text) ─────────────────────────────────────────────

    @Test
    void cloudflareTextParsesLinesAndSkipsJunk() {
        String body = """
            173.245.48.0/20
            104.16.0.0/13

            # comment line
            not-a-cidr
            2606:4700::/32
            172.64.0.0/13
            """;
        List<FeedRange> out = ProviderFeedParser.parseCloudflareText(body);
        assertEquals(3, out.size());
        assertEquals("173.245.48.0/20", out.get(0).cidr());
        assertEquals("CDN", out.get(0).category());
    }

    // ── AWS (ip-ranges.json) ────────────────────────────────────────────────

    private static final String AWS_JSON = """
        {"syncToken":"1","createDate":"2026-07-01-00-00-00","prefixes":[
          {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"CLOUDFRONT"},
          {"ip_prefix":"13.32.0.0/15","region":"GLOBAL","service":"AMAZON"},
          {"ip_prefix":"3.208.0.0/12","region":"us-east-1","service":"EC2"},
          {"ip_prefix":"52.94.76.0/22","region":"us-west-2","service":"AMAZON"}
        ],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","service":"CLOUDFRONT"}]}
        """;

    @Test
    void awsKeepsOnlyRequestedServicesAndDeduplicates() throws Exception {
        List<FeedRange> out =
            ProviderFeedParser.parseAwsIpRanges(AWS_JSON, Set.of("CLOUDFRONT"));
        assertEquals(1, out.size());
        assertEquals("13.32.0.0/15", out.get(0).cidr());
        assertEquals("CLOUDFRONT", out.get(0).category());
    }

    @Test
    void awsAllKeepsEverythingIpv4Once() throws Exception {
        List<FeedRange> out =
            ProviderFeedParser.parseAwsIpRanges(AWS_JSON, Set.of("ALL"));
        // 13.32.0.0/15 appears under two services but must come out once.
        assertEquals(3, out.size());
    }

    // ── GOOGLE (goog.json) ──────────────────────────────────────────────────

    @Test
    void googleKeepsIpv4PrefixesOnly() throws Exception {
        String json = """
            {"prefixes":[
              {"ipv4Prefix":"8.8.8.0/24"},
              {"ipv6Prefix":"2001:4860::/32"},
              {"ipv4Prefix":"142.250.0.0/15"}
            ]}
            """;
        List<FeedRange> out = ProviderFeedParser.parseGoogleRanges(json);
        assertEquals(2, out.size());
        assertEquals("8.8.8.0/24", out.get(0).cidr());
    }

    // ── AZURE (ServiceTags_Public JSON) ─────────────────────────────────────

    @Test
    void azureFiltersByTagNameCaseInsensitive() throws Exception {
        String json = """
            {"values":[
              {"name":"AzureFrontDoor.Frontend","properties":
                 {"addressPrefixes":["13.107.213.0/24","2620:1ec:bdf::/48"]}},
              {"name":"Storage.WestUS","properties":
                 {"addressPrefixes":["13.93.168.0/24"]}}
            ]}
            """;
        List<FeedRange> out = ProviderFeedParser.parseAzureServiceTags(
            json, Set.of("AZUREFRONTDOOR.FRONTEND"));
        assertEquals(1, out.size());
        assertEquals("13.107.213.0/24", out.get(0).cidr());
        assertEquals("AzureFrontDoor.Frontend", out.get(0).category());
    }

    @Test
    void azureDownloadUrlIsExtractedFromPageHtml() {
        String html = "<a href=\"https://download.microsoft.com/download/7/1/d/"
            + "ServiceTags_Public_20260706.json\" class=\"btn\">click here</a>";
        assertEquals("https://download.microsoft.com/download/7/1/d/"
            + "ServiceTags_Public_20260706.json",
            ProviderFeedParser.extractAzureDownloadUrl(html));
        assertNull(ProviderFeedParser.extractAzureDownloadUrl("<html>nope</html>"));
        assertNull(ProviderFeedParser.extractAzureDownloadUrl(null));
    }
}
