package com.martecyber.plugins.greenbone;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.AssetMetadataKeys;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link GreenboneXMLParser}: the mixed-content &lt;host&gt; (leading text = IP, then
 *  &lt;asset&gt;/&lt;hostname&gt; children), the result-level vs. nvt-level {@code <name>}
 *  disambiguation, the explicit-&lt;solution&gt;-wins-over-tags convention, {@code "general"}
 *  ports never emitting a SERVICE asset, and the {@code host-{ip}} detection-asset convention
 *  shared with {@link GreenboneCSVParser} for cross-import dedup. */
class GreenboneXMLParserTest {

    private final GreenboneXMLParser parser = new GreenboneXMLParser();

    private ParseResult parse(String xml) throws Exception {
        return parser.parse(xml.getBytes(StandardCharsets.UTF_8));
    }

    // Replicates the real GVM quirk of a doubly-nested <report> wrapper (harmless for a StAX
    // walker that reacts to element names, not tree depth — see the class javadoc).
    private static final String XML = """
        <?xml version="1.0"?>
        <report>
        <report>
        <results>
          <result>
            <name>SSL Cipher Suite Issue</name>
            <host>
              10.0.0.1
              <asset asset_id="abc-123"/>
              <hostname>web01.example.com</hostname>
            </host>
            <port>443/tcp</port>
            <nvt oid="1.3.6.1.4.1.25623.1.0.103682">
              <name>Should be ignored (nvt-level name)</name>
              <family>SSL and TLS</family>
              <tags>summary=Weak cipher suite in use|insight=RSA key too short</tags>
              <solution>Upgrade the TLS configuration.</solution>
              <refs>
                <ref type="cve" id="CVE-2024-1111"/>
                <ref type="url" id="http://example.com/advisory"/>
              </refs>
            </nvt>
            <threat>High</threat>
            <severity>7.5</severity>
            <qod><value>80</value></qod>
          </result>
          <result>
            <name>Host-level TCP timestamps</name>
            <host>10.0.0.1</host>
            <port>general</port>
            <nvt oid="1.3.6.1.4.1.25623.1.0.100000">
              <family>General</family>
              <tags>summary=TCP timestamps are enabled|solution=Disable if not needed</tags>
            </nvt>
            <severity>2.0</severity>
          </result>
        </results>
        </report>
        </report>
        """;

    @Test
    void validateRequiresReportAndNvtOid() {
        assertTrue(parser.validate(XML.getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<report/>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parsesTheMixedContentHostCapturingLeadingIpTextAndNestedHostnameAndAssetId() throws Exception {
        ParseResult result = parse(XML);

        ParsedAsset host = result.getAssets().stream()
            .filter(a -> a.getType().equals(AssetType.HOST) && a.getIdentifier().equals("host-10.0.0.1")).findFirst().orElseThrow();
        assertEquals(List.of("web01.example.com"), host.getMetadata().get(AssetMetadataKeys.HOSTNAME_HINTS_KEY));
        assertEquals("greenbone", host.getMetadata().get(AssetMetadataKeys.EXTERNAL_ID_TOOL_KEY));
        assertEquals("abc-123", host.getMetadata().get(AssetMetadataKeys.EXTERNAL_ID_VALUE_KEY));
    }

    @Test
    void resultLevelNameWinsOverTheNestedNvtLevelName() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> x.getSourceTemplateId().contains("103682")).findFirst().orElseThrow();
        assertEquals("SSL Cipher Suite Issue", d.getTitle());
    }

    @Test
    void portWithASlashEmitsAServiceAssetLinkedToTheHost() throws Exception {
        ParseResult result = parse(XML);
        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().equals("10.0.0.1:443/tcp")));
    }

    @Test
    void generalPortNeverEmitsAServiceAssetButStillEmitsTheDetection() throws Exception {
        ParseResult result = parse(XML);
        assertTrue(result.getAssets().stream().noneMatch(a -> a.getType().equals(AssetType.SERVICE) && a.getIdentifier().contains("general")));
        assertTrue(result.getDetections().stream().anyMatch(d -> "Host-level TCP timestamps".equals(d.getTitle())));
    }

    @Test
    void explicitSolutionElementWinsOverTheTagsEmbeddedSolution() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> x.getSourceTemplateId().contains("103682")).findFirst().orElseThrow();
        assertTrue(d.getDescription().contains("Solution: Upgrade the TLS configuration."));
    }

    @Test
    void fallsBackToTheTagsEmbeddedSolutionWhenNoExplicitSolutionElement() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> "Host-level TCP timestamps".equals(x.getTitle())).findFirst().orElseThrow();
        assertTrue(d.getDescription().contains("Solution: Disable if not needed"));
    }

    @Test
    void severityIsBucketedFromTheResultLevelCvssNotAnvtScale() throws Exception {
        var detections = parse(XML).getDetections();
        assertEquals("high", detections.get(0).getSeverity()); // 7.5
        assertEquals("low", detections.get(1).getSeverity());  // 2.0 -> >0 and <4 buckets to "low"
    }

    @Test
    void onlyCveTypedRefsAreCollectedIntoRawData() throws Exception {
        ParsedDetection d = parse(XML).getDetections().stream()
            .filter(x -> x.getSourceTemplateId().contains("103682")).findFirst().orElseThrow();
        assertTrue(d.getRawData().contains("CVE-2024-1111"));
        assertFalse(d.getRawData().contains("http://example.com/advisory"));
    }

    @Test
    void detectionAssetIdentifierUsesTheSharedHostIpConventionForCrossImportDedup() throws Exception {
        ParsedDetection d = parse(XML).getDetections().get(0);
        assertEquals("host-10.0.0.1", d.getAssetIdentifier());
    }

    @Test
    void resultWithoutAHostIpIsSkipped() throws Exception {
        String xml = """
            <report><results>
              <result>
                <name>No host</name>
                <host></host>
                <nvt oid="1.2.3"><family>X</family></nvt>
                <severity>5.0</severity>
              </result>
            </results></report>
            """;
        ParseResult result = parse(xml);
        assertTrue(result.getAssets().isEmpty());
        assertTrue(result.getDetections().isEmpty());
    }

    @Test
    void templateIdFallsBackToASlugifiedTitleWhenNvtOidIsMissing() throws Exception {
        String xml = """
            <report><results>
              <result>
                <name>Weird Finding</name>
                <host>10.0.0.9</host>
                <nvt><family>X</family></nvt>
                <severity>5.0</severity>
              </result>
            </results></report>
            """;
        assertEquals("greenbone-weird-finding", parse(xml).getDetections().get(0).getSourceTemplateId());
    }
}
