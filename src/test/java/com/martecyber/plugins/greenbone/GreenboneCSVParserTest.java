package com.martecyber.plugins.greenbone;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link GreenboneCSVParser}: header-driven column lookup via the real Greenbone export
 *  header, CVSS-to-severity bucketing, the {@code host-{ip}} detection asset convention it shares
 *  with {@link GreenboneXMLParser} for cross-import dedup, and embedded-newline-safe CSV parsing
 *  (via {@link ScannerParserUtils#parseCsv}, already covered independently). */
class GreenboneCSVParserTest {

    private final GreenboneCSVParser parser = new GreenboneCSVParser();

    private static final String HEADER =
        "IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,"
        + "Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,"
        + "Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,"
        + "Product Detection Result,BIDs,CERTs,Other References\n";

    private ParseResult parse(String csv) throws Exception {
        return parser.parse(csv.getBytes(StandardCharsets.UTF_8));
    }

    private static String row(String ip, String hostname, String port, String proto, String cvss,
                               String nvtName, String summary, String insight, String solution,
                               String oid, String cves) {
        // Column order must exactly match HEADER — blank for every column this test doesn't care about.
        return String.join(",", ip, hostname, port, proto, cvss, "", "", "", nvtName,
            quoteIfNeeded(summary), "", oid, quoteIfNeeded(cves), "", "", "", "", "", quoteIfNeeded(solution),
            "", quoteIfNeeded(insight), "", "", "", "", "") + "\n";
    }

    private static String quoteIfNeeded(String s) {
        return s.contains(",") ? "\"" + s + "\"" : s;
    }

    @Test
    void validateRequiresNvtOidAndCvesColumnsOnTheHeaderLine() {
        assertTrue(parser.validate(HEADER.getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("IP,Hostname,Port\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void emptyContentProducesAnEmptyResult() throws Exception {
        assertTrue(parse("").getDetections().isEmpty());
    }

    @Test
    void emitsHostChainAndServiceAndKeysTheDetectionOnTheIpDerivedHostAsset() throws Exception {
        String csv = HEADER + row("10.0.0.1", "web01.example.com", "443", "tcp", "9.8",
            "Critical RCE", "Summary text", "Insight text", "Patch now", "1.3.6.1.4.1.25623.1.0.1", "CVE-2024-0001");
        ParseResult result = parse(csv);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.HOST) && a.getIdentifier().equals("host-10.0.0.1")));
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("10.0.0.1:443/tcp")));

        ParsedDetection d = result.getDetections().get(0);
        assertEquals("host-10.0.0.1", d.getAssetIdentifier());
        assertEquals("critical", d.getSeverity());
        assertEquals("Critical RCE", d.getTitle());
        assertEquals("greenbone-1.3.6.1.4.1.25623.1.0.1", d.getSourceTemplateId());
        assertTrue(d.getDescription().contains("Summary text"));
        assertTrue(d.getDescription().contains("Insight text"));
        assertTrue(d.getDescription().contains("Solution: Patch now"));
    }

    @Test
    void cvssIsBucketedIntoSeverityPerThePriorityScale() throws Exception {
        String csv = HEADER
            + row("10.0.0.1", "", "", "", "0.0", "Log finding", "s", "", "", "oid1", "")
            + row("10.0.0.2", "", "", "", "3.5", "Low finding", "s", "", "", "oid2", "");
        var detections = parse(csv).getDetections();
        assertEquals("info", detections.get(0).getSeverity());
        assertEquals("low",  detections.get(1).getSeverity());
    }

    @Test
    void rowWithoutAnIpIsSkipped() throws Exception {
        String csv = HEADER + row("", "", "443", "tcp", "9.0", "X", "s", "", "", "oid", "");
        assertTrue(parse(csv).getDetections().isEmpty());
    }

    @Test
    void rowWithoutAPortStillEmitsTheHostChainAndDetectionButNoService() throws Exception {
        String csv = HEADER + row("10.0.0.1", "", "", "", "9.0", "X", "s", "", "", "oid", "");
        ParseResult result = parse(csv);
        assertEquals(1, result.getDetections().size());
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.SERVICE)));
    }

    @Test
    void cveListIsSplitOnCommasInTheRawData() throws Exception {
        String csv = HEADER + row("10.0.0.1", "", "443", "tcp", "9.0", "X", "s", "", "", "oid",
            "CVE-2024-0001, CVE-2024-0002");
        String raw = parse(csv).getDetections().get(0).getRawData();
        assertTrue(raw.contains("CVE-2024-0001"));
        assertTrue(raw.contains("CVE-2024-0002"));
    }

    @Test
    void multipleRowsForTheSameHostShareOneHostAndServiceAsset() throws Exception {
        String csv = HEADER
            + row("10.0.0.1", "", "443", "tcp", "9.0", "Finding A", "s", "", "", "oid1", "")
            + row("10.0.0.1", "", "443", "tcp", "5.0", "Finding B", "s", "", "", "oid2", "");
        ParseResult result = parse(csv);
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.HOST)).count());
        assertEquals(1, result.getAssets().stream().filter(a -> a.getType().equals(AssetType.SERVICE)).count());
        assertEquals(2, result.getDetections().size());
    }
}
