package com.martecyber.plugins.greenbone;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Maps Greenbone/OpenVAS CSV report exports into ParseResult. Verified against a real export;
 * exact header confirmed:
 *   IP,Hostname,Port,Port Protocol,CVSS,Severity,QoD,Solution Type,NVT Name,Summary,
 *   Specific Result,NVT OID,CVEs,Task ID,Task Name,Timestamp,Result ID,Impact,Solution,
 *   Affected Software/OS,Vulnerability Insight,Vulnerability Detection Method,
 *   Product Detection Result,BIDs,CERTs,Other References
 *
 * One row per result — flatter than the XML export (no pipe-delimited tags to unpack).
 * Several columns (Summary, Solution, Vulnerability Insight, ...) contain literal embedded
 * newlines inside quoted values, so this uses ScannerParserUtils.parseCsv (a whole-content
 * tokenizer) rather than a line-by-line reader like the existing PurpleKnight/Testssl CSV
 * parsers — those formats don't have this problem, so they're left untouched.
 *
 * Same asset-identifier and severity conventions as GreenboneXMLParser so that importing the
 * XML and CSV exports of the same underlying scan naturally dedups against each other.
 */
public class GreenboneCSVParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "greenbone"; }
    @Override public String getFormatId() { return "csv"; }
    @Override public String getDisplayName() { return "Greenbone VM CSV"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".csv"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        int nl = s.indexOf('\n');
        String header = (nl >= 0 ? s.substring(0, nl) : s).toLowerCase();
        return header.contains("nvt oid") && header.contains("cves");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        List<String[]> records = ScannerParserUtils.parseCsv(content);
        if (records.isEmpty()) return result;

        Map<String, Integer> idx = indexHeaders(records.get(0));
        Set<String> seen = new HashSet<>();

        for (int i = 1; i < records.size(); i++) {
            String[] cols = records.get(i);

            String ip = get(cols, idx, "ip");
            if (ip == null || ip.isBlank()) continue;
            String hostname = get(cols, idx, "hostname");

            ScannerParserUtils.emitHostChain(ip, hostname, result, seen);

            String portStr = get(cols, idx, "port");
            String proto = get(cols, idx, "port protocol");
            if (portStr != null) {
                try {
                    int port = Integer.parseInt(portStr.trim());
                    ScannerParserUtils.emitService(ip, port, proto, null, result, seen);
                } catch (NumberFormatException ignored) {}
            }

            double cvss = 0.0;
            String cvssStr = get(cols, idx, "cvss");
            try { if (cvssStr != null) cvss = Double.parseDouble(cvssStr.trim()); } catch (NumberFormatException ignored) {}
            String severity = ScannerParserUtils.cvssToSeverity(cvss, "info");

            String name = get(cols, idx, "nvt name");
            String summary = get(cols, idx, "summary");
            String insight = get(cols, idx, "vulnerability insight");
            String solution = get(cols, idx, "solution");

            StringBuilder desc = new StringBuilder();
            if (summary != null && !summary.isBlank()) desc.append(summary.trim());
            if (insight != null && !insight.isBlank()) desc.append("\n\n").append(insight.trim());
            if (solution != null && !solution.isBlank()) desc.append("\n\nSolution: ").append(solution.trim());

            String oid = get(cols, idx, "nvt oid");
            String title = (name != null && !name.isBlank()) ? name : "Greenbone finding";
            String templateId = "greenbone-" + (oid != null ? oid : title.toLowerCase().replaceAll("[^a-z0-9]+", "-"));

            // Every column this row had, not the handful this parser's own title/description/
            // severity logic reads — Task ID/Name, Timestamp, Result ID, Impact, Affected
            // Software/OS, Vulnerability Detection Method, Product Detection Result and Other
            // References were previously dropped entirely. Matches PurpleKnightCSVParser's
            // same "dump every column" convention rather than hand-picking a subset.
            String rawData;
            try {
                Map<String, Object> raw = new LinkedHashMap<>();
                for (Map.Entry<String, Integer> h : idx.entrySet()) {
                    if (h.getValue() < cols.length) raw.put(h.getKey(), cols[h.getValue()]);
                }
                rawData = MAPPER.writeValueAsString(raw);
            } catch (Exception e) { rawData = "{}"; }

            // Detections must key off the same "host-{ip}" token emitHostChain uses for the HOST
            // ParsedAsset — resolving by hostname here would attach findings to whatever asset a
            // stale/different hostname string happened to resolve to instead of the real host.
            String assetIdentifier = "host-" + ip;
            result.addDetection(new ParsedDetection(title, severity, desc.toString().trim(),
                assetIdentifier, templateId, rawData));
        }
        return result;
    }

    private Map<String, Integer> indexHeaders(String[] headers) {
        Map<String, Integer> idx = new LinkedHashMap<>();
        for (int i = 0; i < headers.length; i++) idx.put(headers[i].trim().toLowerCase(), i);
        return idx;
    }

    private String get(String[] cols, Map<String, Integer> idx, String key) {
        Integer i = idx.get(key);
        if (i == null || i >= cols.length) return null;
        String v = cols[i].trim();
        return v.isEmpty() ? null : v;
    }
}
