package com.martecyber.plugins.greenbone;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Maps Greenbone/OpenVAS (GVM) "XML" report exports (format_id 5057e5cc-... "Anonymous XML")
 * into ParseResult. Verified against a real export: the document root wraps a second, nested
 * &lt;report&gt; element that actually contains &lt;results&gt; — a known GVM quirk, harmless
 * for a StAX walker since we react to element names rather than tree depth.
 *
 * Per &lt;result&gt;: &lt;host&gt; is mixed content (leading text = IP, then &lt;asset&gt;/
 * &lt;hostname&gt; children); &lt;port&gt; is "{spec}/{protocol}" where {spec} is a real port
 * number or the literal "general" for host-level checks (no SERVICE asset emitted for those);
 * the result-level &lt;severity&gt; (CVSS float, NOT the nested &lt;nvt&gt;&lt;severities&gt;
 * one) is what severity is bucketed from, per the OpenVAS/GVM CVSS scale matching the rest of
 * Ares's parsers; CVE ids live in &lt;nvt&gt;&lt;refs&gt;&lt;ref type="cve" id="CVE-..."/&gt;.
 */
public class GreenboneXMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "greenbone"; }
    @Override public String getFormatId() { return "xml"; }
    @Override public String getDisplayName() { return "Greenbone VM XML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".xml"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains("<report") && s.contains("<nvt oid=");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new ByteArrayInputStream(content));

        Set<String> seen = new HashSet<>();

        boolean inResult = false;
        boolean inNvt = false;
        boolean inHost = false;
        boolean hostDirectText = false;
        StringBuilder hostIpBuf = new StringBuilder();
        StringBuilder text = new StringBuilder();

        GreenboneResult cur = null;

        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                text.setLength(0);

                if ("result".equals(tag)) {
                    cur = new GreenboneResult();
                    inResult = true;
                } else if ("nvt".equals(tag) && inResult) {
                    inNvt = true;
                    cur.oid = r.getAttributeValue(null, "oid");
                } else if ("host".equals(tag) && inResult) {
                    inHost = true;
                    hostDirectText = true;
                    hostIpBuf.setLength(0);
                } else if (inHost && "asset".equals(tag)) {
                    // GVM's own stable host identifier — previously discarded entirely (only
                    // used as the "mixed-content text ends here" marker below). Capturing it
                    // lets AssetImportHelper resolve the same host across syncs even when its
                    // active IP changes, instead of only matching by IP/interface.
                    if (cur != null) cur.assetId = r.getAttributeValue(null, "asset_id");
                    hostDirectText = false;
                } else if (inHost && hostDirectText) {
                    // First nested child of <host> (asset/hostname) — mixed-content text ends here.
                    hostDirectText = false;
                } else if ("ref".equals(tag) && inNvt) {
                    String type = r.getAttributeValue(null, "type");
                    String id = r.getAttributeValue(null, "id");
                    if ("cve".equalsIgnoreCase(type) && id != null && !id.isBlank() && cur != null) {
                        cur.cves.add(id);
                    }
                }
            } else if (ev == XMLStreamConstants.CHARACTERS) {
                if (inHost && hostDirectText) hostIpBuf.append(r.getText());
                if (cur != null) text.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                String val = text.toString().trim();

                if ("host".equals(tag) && inResult) {
                    cur.ip = hostIpBuf.toString().trim();
                    inHost = false;
                } else if ("hostname".equals(tag) && cur != null) {
                    cur.hostname = val;
                } else if ("nvt".equals(tag) && inResult) {
                    inNvt = false;
                } else if ("name".equals(tag) && inResult && !inNvt && cur != null && cur.name == null) {
                    cur.name = val;
                } else if ("family".equals(tag) && inNvt && cur != null) {
                    cur.family = val;
                } else if ("tags".equals(tag) && inNvt && cur != null) {
                    cur.tags = parseTags(val);
                } else if ("solution".equals(tag) && inNvt && cur != null) {
                    cur.solution = val;
                } else if ("port".equals(tag) && inResult && !inNvt && cur != null) {
                    cur.port = val;
                } else if ("threat".equals(tag) && inResult && !inNvt && cur != null) {
                    cur.threat = val;
                } else if ("severity".equals(tag) && inResult && !inNvt && cur != null) {
                    cur.severity = val;
                } else if ("value".equals(tag) && inResult && !inNvt && cur != null && cur.qod == null) {
                    cur.qod = val;
                } else if ("result".equals(tag)) {
                    if (cur != null) emit(cur, result, seen);
                    cur = null;
                    inResult = false;
                    inNvt = false;
                }
                text.setLength(0);
            }
        }
        r.close();
        return result;
    }

    private void emit(GreenboneResult res, ParseResult result, Set<String> seen) {
        if (res.ip == null || res.ip.isBlank()) return;

        ScannerParserUtils.emitHostChain(res.ip, res.hostname, "greenbone", res.assetId, result, seen);

        Integer port = null;
        String protocol = null;
        if (res.port != null) {
            int slash = res.port.lastIndexOf('/');
            if (slash > 0) {
                String spec = res.port.substring(0, slash);
                protocol = res.port.substring(slash + 1);
                try { port = Integer.parseInt(spec.trim()); } catch (NumberFormatException ignored) {}
            }
        }
        if (port != null) {
            ScannerParserUtils.emitService(res.ip, port, protocol, null, result, seen);
        }

        double cvss = 0.0;
        try { if (res.severity != null) cvss = Double.parseDouble(res.severity); } catch (NumberFormatException ignored) {}
        String severity = ScannerParserUtils.cvssToSeverity(cvss, "info");

        String summary = res.tags.get("summary");
        String insight = res.tags.get("insight");
        String solution = (res.solution != null && !res.solution.isBlank()) ? res.solution : res.tags.get("solution");

        StringBuilder desc = new StringBuilder();
        if (summary != null && !summary.isBlank()) desc.append(summary.trim());
        if (insight != null && !insight.isBlank()) desc.append("\n\n").append(insight.trim());
        if (solution != null && !solution.isBlank()) desc.append("\n\nSolution: ").append(solution.trim());

        String title = (res.name != null && !res.name.isBlank()) ? res.name : "Greenbone finding";
        String templateId = "greenbone-" + (res.oid != null ? res.oid : title.toLowerCase().replaceAll("[^a-z0-9]+", "-"));

        // Every field this parser's own XML walk captured for the <result>, not the smaller
        // subset its own title/description/severity logic happens to read — name, hostname,
        // assetId, solution and the full <tags> map were previously dropped here even though
        // they were already sitting on GreenboneResult.
        String rawData;
        try {
            Map<String, Object> raw = new LinkedHashMap<>();
            raw.put("oid", res.oid);
            raw.put("name", res.name);
            raw.put("hostname", res.hostname);
            raw.put("assetId", res.assetId);
            raw.put("cve", res.cves);
            raw.put("cvssBase", res.severity);
            raw.put("threat", res.threat);
            raw.put("qod", res.qod);
            raw.put("family", res.family);
            raw.put("port", res.port);
            raw.put("solution", res.solution);
            raw.put("tags", res.tags);
            rawData = MAPPER.writeValueAsString(raw);
        } catch (Exception e) { rawData = "{}"; }

        // Detections must key off the same "host-{ip}" token emitHostChain uses for the HOST
        // ParsedAsset — resolving by hostname here would attach findings to whatever asset a
        // stale/different hostname string happened to resolve to instead of the real host.
        String assetIdentifier = "host-" + res.ip;
        result.addDetection(new ParsedDetection(title, severity, desc.toString().trim(),
            assetIdentifier, templateId, rawData));
    }

    /** Pipe-delimited "key=value|key=value..." tag encoding used by GVM NVTs. */
    private Map<String, String> parseTags(String raw) {
        Map<String, String> map = new LinkedHashMap<>();
        if (raw == null || raw.isBlank()) return map;
        for (String segment : raw.split("\\|")) {
            int eq = segment.indexOf('=');
            if (eq <= 0) continue;
            map.put(segment.substring(0, eq).trim(), segment.substring(eq + 1).trim());
        }
        return map;
    }

    /** Transient per-&lt;result&gt; accumulator. */
    private static class GreenboneResult {
        String ip;
        String hostname;
        String assetId;
        String name;
        String port;
        String threat;
        String severity;
        String qod;
        String oid;
        String family;
        String solution;
        Map<String, String> tags = Map.of();
        List<String> cves = new ArrayList<>();
    }
}
