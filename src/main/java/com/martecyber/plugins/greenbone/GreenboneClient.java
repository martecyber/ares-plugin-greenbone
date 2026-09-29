package com.martecyber.plugins.greenbone;

import com.martecyber.ares.integrations.tools.IntegrationClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Client for the Greenbone Management Protocol (GMP) — the XML protocol {@code gvmd} exposes,
 * NOT a REST API. There is no length-prefixed framing: a command is written as raw UTF-8 XML
 * bytes directly to the socket, and the response is read by parsing XML events until the
 * response's root element closes (confirmed against GMP protocol documentation and community
 * client implementations — no vendor SDK exists for Java, so this is hand-rolled the same way
 * the file-import parsers hand-roll StAX parsing).
 *
 * Not validated against a live GVM instance in this environment — the command shapes below
 * (authenticate / get_version / get_tasks / get_reports / start_task) reflect the documented,
 * long-stable GMP command set, but should be verified end-to-end against a real instance before
 * relying on this in production.
 *
 * format_id "a994b278-1f62-11e1-96ac-406186ea4fc5" (the built-in, non-anonymized "XML" report
 * format — NOT "Anonymous XML", 5057e5cc-..., which replaces real host IPs with random ones and
 * was mistakenly used here originally) is shipped with every GVM install (not something users
 * configure) — using it with get_reports yields the exact same
 * &lt;report&gt;&lt;results&gt;&lt;result&gt;... shape as the standalone file export
 * GreenboneXMLParser already parses, so live syncs reuse that parser unchanged.
 */
public class GreenboneClient implements IntegrationClient {

    private static final Logger log = LoggerFactory.getLogger(GreenboneClient.class);
    private static final String REPORT_FORMAT_ID = "a994b278-1f62-11e1-96ac-406186ea4fc5";
    private static final int DEFAULT_PORT = 9390;
    private static final int SOCKET_TIMEOUT_MS = 60_000;

    private final ObjectMapper objectMapper;

    public GreenboneClient(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override public String supports() { return "greenbone"; }

    @Override
    public java.util.List<java.util.Map<String, String>> listPickerItems(String settingsJson, Map<String, String> credentials) throws Exception {
        return listTasks(settingsJson, credentials).stream()
            .map(t -> Map.of("id", t.id(), "name", t.name(), "status", t.status()))
            .toList();
    }

    @Override
    public void testConnection(String settingsJson, Map<String, String> credentials) throws Exception {
        withSession(settingsJson, credentials, socket -> {
            GmpResponse r = sendCommand(socket, "<get_version/>");
            if (!r.ok()) throw new RuntimeException("Greenbone get_version failed: " + r.statusText());
            return null;
        });
    }

    public record GmpTask(String id, String name, String status) {}

    /** Lists all tasks visible to these credentials, for the grant-creation task picker. */
    public List<GmpTask> listTasks(String settingsJson, Map<String, String> credentials) throws Exception {
        return withSession(settingsJson, credentials, socket -> {
            GmpResponse r = sendCommand(socket, "<get_tasks/>");
            if (!r.ok()) throw new RuntimeException("Greenbone get_tasks failed: " + r.statusText());
            return parseTasks(r.rawBody());
        });
    }

    /** Starts (re-)running a task that was already configured in GVM. Fire-and-forget — does
     *  not wait for the scan to finish (a GVM scan can take hours). */
    public void startTask(String settingsJson, Map<String, String> credentials, String taskId) throws Exception {
        withSession(settingsJson, credentials, socket -> {
            GmpResponse r = sendCommand(socket, "<start_task task_id=\"" + escapeXmlAttr(taskId) + "\"/>");
            if (!r.ok()) throw new RuntimeException("Greenbone start_task failed: " + r.statusText());
            return null;
        });
    }

    /**
     * Fetches the most recent report for a task, in the built-in "XML" format —
     * the returned bytes can be passed directly to GreenboneXMLParser.parse().
     */
    public byte[] fetchLatestReport(String settingsJson, Map<String, String> credentials, String taskId) throws Exception {
        return withSession(settingsJson, credentials, socket -> {
            GmpResponse taskResp = sendCommand(socket,
                "<get_tasks task_id=\"" + escapeXmlAttr(taskId) + "\" details=\"1\"/>");
            if (!taskResp.ok())
                throw new RuntimeException("Greenbone get_tasks(details) failed: " + taskResp.statusText());
            String reportId = findLastReportId(taskResp.rawBody());
            if (reportId == null)
                throw new RuntimeException("Greenbone task " + taskId + " has no completed report yet");

            // ignore_pagination bypasses gvmd's default "first"/"rows" filter, which otherwise
            // silently truncates the result set to whatever the server's default page size is.
            GmpResponse reportResp = sendCommand(socket,
                "<get_reports report_id=\"" + escapeXmlAttr(reportId) + "\" format_id=\""
                    + REPORT_FORMAT_ID + "\" details=\"1\" ignore_pagination=\"1\"/>");
            if (!reportResp.ok())
                throw new RuntimeException("Greenbone get_reports failed: " + reportResp.statusText());
            return reportResp.rawBody();
        });
    }

    // ── Session / transport ─────────────────────────────────────────────────

    @FunctionalInterface
    private interface SessionFunction<T> { T apply(Socket socket) throws Exception; }

    private <T> T withSession(String settingsJson, Map<String, String> credentials, SessionFunction<T> fn) throws Exception {
        GmpSettings s = parseSettings(settingsJson);
        try (Socket socket = openSocket(s)) {
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            if (socket instanceof SSLSocket sslSocket) sslSocket.startHandshake();
            authenticate(socket, credentials);
            return fn.apply(socket);
        }
    }

    /** Some gvmd deployments (especially quick Docker setups) are found running GMP in plain
     *  text with no TLS at all — {@code settings.tls=false} opts out of the TLS handshake
     *  entirely rather than just relaxing certificate validation. */
    private Socket openSocket(GmpSettings s) throws Exception {
        if (!s.tls()) return new Socket(s.host(), s.port());
        SSLSocketFactory factory = buildSocketFactory(s.insecureTls());
        return factory.createSocket(s.host(), s.port());
    }

    private void authenticate(Socket socket, Map<String, String> credentials) throws Exception {
        String user = credentials.getOrDefault("username", "");
        String pass = credentials.getOrDefault("password", "");
        String xml = "<authenticate><credentials><username>" + escapeXmlText(user)
            + "</username><password>" + escapeXmlText(pass) + "</password></credentials></authenticate>";
        GmpResponse r = sendCommand(socket, xml);
        if (!r.ok()) throw new RuntimeException("Greenbone authentication failed: " + r.statusText());
    }

    private record GmpResponse(int status, String statusText, byte[] rawBody) {
        boolean ok() { return status >= 200 && status < 300; }
    }

    /**
     * Writes a GMP command and reads back the response. Since GMP has no length prefix, the
     * response is read by walking XML events until the root element's closing tag — the
     * connection itself stays open for further commands. A tee wraps the socket's InputStream
     * so the raw bytes StAX consumes are captured verbatim for callers that need to hand them
     * to another XML parser (e.g. the report bytes going to GreenboneXMLParser).
     */
    private GmpResponse sendCommand(Socket socket, String requestXml) throws Exception {
        socket.getOutputStream().write(requestXml.getBytes(StandardCharsets.UTF_8));
        socket.getOutputStream().flush();
        return readResponse(socket.getInputStream());
    }

    /**
     * Reads one GMP response by walking XML events until the root element's closing tag —
     * split out from {@link #sendCommand} so the framing/status-capture logic can be exercised
     * directly against a plain stream in tests, independent of a live socket.
     */
    private GmpResponse readResponse(InputStream in) throws Exception {
        ByteArrayOutputStream capture = new ByteArrayOutputStream();
        InputStream tee = new FilterInputStream(in) {
            @Override public int read() throws IOException {
                int b = super.read();
                if (b != -1) capture.write(b);
                return b;
            }
            @Override public int read(byte[] b, int off, int len) throws IOException {
                int n = super.read(b, off, len);
                if (n > 0) capture.write(b, off, n);
                return n;
            }
        };

        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(tee);

        int depth = 0;
        boolean started = false;
        int status = 0;
        String statusText = null;
        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                if (!started) {
                    started = true;
                    status = parseIntAttr(r.getAttributeValue(null, "status"));
                    statusText = r.getAttributeValue(null, "status_text");
                }
                depth++;
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                depth--;
                if (started && depth == 0) break;
            }
        }
        r.close();
        return new GmpResponse(status, statusText != null ? statusText : "no status_text", capture.toByteArray());
    }

    // ── Response parsing ────────────────────────────────────────────────────

    private List<GmpTask> parseTasks(byte[] body) throws Exception {
        List<GmpTask> tasks = new ArrayList<>();
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new java.io.ByteArrayInputStream(body));

        boolean inTask = false;
        boolean inOwner = false;
        String id = null, name = null, status = null;
        StringBuilder text = new StringBuilder();
        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                text.setLength(0);
                if ("task".equals(tag)) {
                    inTask = true;
                    inOwner = false;
                    id = r.getAttributeValue(null, "id");
                    name = null;
                    status = null;
                } else if ("owner".equals(tag) && inTask) {
                    // <task><owner><name>USERNAME</name></owner><name>TASK NAME</name>...</task> —
                    // both are unqualified <name> elements; skip the owner's while inside it so
                    // the task's OWN <name> (which comes after </owner>) is what gets captured.
                    inOwner = true;
                }
            } else if (ev == XMLStreamConstants.CHARACTERS) {
                text.append(r.getText());
            } else if (ev == XMLStreamConstants.END_ELEMENT) {
                String tag = r.getLocalName();
                if ("owner".equals(tag) && inTask) inOwner = false;
                else if (inTask && !inOwner && "name".equals(tag) && name == null) name = text.toString().trim();
                else if (inTask && !inOwner && "status".equals(tag) && status == null) status = text.toString().trim();
                else if ("task".equals(tag) && inTask) {
                    tasks.add(new GmpTask(id, name != null ? name : "(unnamed)", status != null ? status : "Unknown"));
                    inTask = false;
                }
                text.setLength(0);
            }
        }
        r.close();
        return tasks;
    }

    /** Walks a get_tasks(details=1) response for &lt;last_report&gt;&lt;report id="..."&gt;. */
    private String findLastReportId(byte[] body) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        XMLStreamReader r = factory.createXMLStreamReader(new java.io.ByteArrayInputStream(body));

        boolean inLastReport = false;
        String reportId = null;
        while (r.hasNext()) {
            int ev = r.next();
            if (ev == XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                if ("last_report".equals(tag)) inLastReport = true;
                else if ("report".equals(tag) && inLastReport) {
                    reportId = r.getAttributeValue(null, "id");
                    break;
                }
            } else if (ev == XMLStreamConstants.END_ELEMENT && "last_report".equals(r.getLocalName())) {
                inLastReport = false;
            }
        }
        r.close();
        return reportId;
    }

    // ── Settings / TLS ───────────────────────────────────────────────────────

    private record GmpSettings(String host, int port, boolean tls, boolean insecureTls) {}

    private GmpSettings parseSettings(String settingsJson) {
        if (settingsJson == null || settingsJson.isBlank())
            throw new IllegalStateException("Greenbone integration has no connection settings configured");
        try {
            JsonNode n = objectMapper.readTree(settingsJson);
            String host = n.path("host").asText(null);
            if (host == null || host.isBlank())
                throw new IllegalStateException("Greenbone integration settings missing 'host'");
            int port = n.path("port").asInt(DEFAULT_PORT);
            // Default true — existing integrations configured before this option was added
            // assumed TLS, so absence of the field must not silently switch them to plain text.
            boolean tls = n.path("tls").asBoolean(true);
            boolean insecure = tls && n.path("insecureTls").asBoolean(false);
            return new GmpSettings(host, port, tls, insecure);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Invalid Greenbone integration settings: " + e.getMessage(), e);
        }
    }

    /** insecureTls=true trusts any server certificate — for self-signed certs common on
     *  internal GVM deployments. Exposed as a checkbox in the integration's settings. */
    private SSLSocketFactory buildSocketFactory(boolean insecureTls) throws Exception {
        if (!insecureTls) return (SSLSocketFactory) SSLSocketFactory.getDefault();
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        return ctx.getSocketFactory();
    }

    private int parseIntAttr(String v) {
        if (v == null) return 0;
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return 0; }
    }

    private String escapeXmlText(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private String escapeXmlAttr(String s) {
        if (s == null) return "";
        return escapeXmlText(s).replace("\"", "&quot;");
    }
}
