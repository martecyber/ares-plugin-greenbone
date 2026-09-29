package com.martecyber.plugins.greenbone;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.martecyber.ares.imports.IngestFacade;
import com.martecyber.ares.imports.IngestResult;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import com.martecyber.ares.integrations.GrantView;
import com.martecyber.ares.integrations.IntegrationFacade;
import com.martecyber.ares.integrations.IntegrationView;
import com.martecyber.ares.jobs.JobFacade;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Does the actual work of a Greenbone/OpenVAS sync.
 *
 * A grant = one GVM task. A project can hold several grants (several tasks); both LAUNCH_SCAN and
 * SYNC_VULNS operate on every task granted to the project in one job, rather than exposing a
 * per-task selector at trigger time — the task scoping lives entirely in the grant.
 *
 * LAUNCH_SCAN:  start_task on each granted task's existing GVM task (fire-and-forget — a scan can
 *               take hours, this does not wait for completion).
 * SYNC_VULNS:   fetches the latest report for each granted task (get_reports, built-in "XML"
 *               format) and parses it with the same {@link GreenboneXMLParser} used for file
 *               import — the live GMP report and the file-exported report share the exact same
 *               XML shape.
 *
 * <p>A plain object, not a Spring bean — {@link GreenboneIntegrationActionHandler} (the plugin's
 * one actual Spring-managed class) constructs one directly, plain-{@code new}-ing the
 * {@link GreenboneXMLParser} (same plugin, no dependencies of its own) it passes in. Runs
 * {@link #launchScan}/{@link #syncVulns}
 * via a plain {@code CompletableFuture.runAsync(...)} instead of the original {@code @Async} +
 * self-injection trick, which needs a Spring AOP proxy this plugin's hand-constructed objects
 * don't have.
 */
public class GreenboneSyncJobHandler {

    private static final Logger log = LoggerFactory.getLogger(GreenboneSyncJobHandler.class);
    private static final String SOURCE_TYPE = "greenbone";

    private final JobFacade jobFacade;
    private final IntegrationFacade integrationFacade;
    private final GreenboneClient greenboneClient;
    private final GreenboneXMLParser greenboneParser;
    private final IngestFacade ingestFacade;
    private final ObjectMapper objectMapper;

    public GreenboneSyncJobHandler(JobFacade jobFacade,
                                    IntegrationFacade integrationFacade,
                                    GreenboneClient greenboneClient,
                                    GreenboneXMLParser greenboneParser,
                                    IngestFacade ingestFacade,
                                    ObjectMapper objectMapper) {
        this.jobFacade = jobFacade;
        this.integrationFacade = integrationFacade;
        this.greenboneClient = greenboneClient;
        this.greenboneParser = greenboneParser;
        this.ingestFacade = ingestFacade;
        this.objectMapper = objectMapper;
    }

    // ── Launch scan ─────────────────────────────────────────────────────────────

    public void launchScan(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);
            List<GrantView> grants = integrationFacade.resolveGrants(integrationId, projectId, orgId);

            int started = 0;
            List<String> errors = new ArrayList<>();
            for (int idx = 0; idx < grants.size(); idx++) {
                GrantView grant = grants.get(idx);
                String taskId = grant.taskId();
                if (taskId == null || taskId.isBlank()) {
                    errors.add("Grant " + grant.id() + " has no task selected");
                    continue;
                }
                try {
                    greenboneClient.startTask(integration.settings(), creds, taskId);
                    started++;
                    log.info("Greenbone launch scan job={} task={} started", jobId, taskId);
                } catch (Exception e) {
                    errors.add("Task " + taskId + " (" + grant.taskName() + "): " + e.getMessage());
                    log.warn("Greenbone launch scan job={} task={} failed: {}", jobId, taskId, e.getMessage());
                }
                setStatus(jobId, null, 10 + (80 * (idx + 1) / grants.size()));
            }

            updateLastSync(integrationId);

            Map<String, Object> resultData = new LinkedHashMap<>();
            resultData.put("tasksStarted", started);
            resultData.put("tasksTotal", grants.size());
            if (!errors.isEmpty()) resultData.put("errors", errors);

            if (started == 0 && !grants.isEmpty()) {
                safeFailJob(jobId, "Failed to start any granted task: " + String.join("; ", errors));
            } else {
                completeJob(jobId, resultData);
            }
            log.info("Greenbone launch scan done job={} started={}/{}", jobId, started, grants.size());

        } catch (Exception ex) {
            log.error("Greenbone launch scan failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Sync vulns ────────────────────────────────────────────────────────────

    public void syncVulns(Long jobId, Long integrationId, Long projectId, Long orgId) {
        setStatus(jobId, "running", 0);
        try {
            IntegrationView integration = integrationFacade.get(integrationId);
            Map<String, String> creds = integrationFacade.loadCredentials(integrationId);
            List<GrantView> grants = integrationFacade.resolveGrants(integrationId, projectId, orgId);

            int assetsCreated = 0, detectionsCreated = 0, detectionsUpdated = 0, warnings = 0;
            int tasksSynced = 0;
            List<String> errors = new ArrayList<>();

            for (int idx = 0; idx < grants.size(); idx++) {
                GrantView grant = grants.get(idx);
                String taskId = grant.taskId();
                if (taskId == null || taskId.isBlank()) {
                    errors.add("Grant " + grant.id() + " has no task selected");
                    continue;
                }
                try {
                    byte[] reportBytes = greenboneClient.fetchLatestReport(integration.settings(), creds, taskId);
                    ParseResult parsed = greenboneParser.parse(reportBytes);
                    injectNvtUrls(parsed, integration.settings());
                    IngestResult result = ingestFacade.ingest(projectId, orgId, SOURCE_TYPE, parsed);

                    assetsCreated     += result.assetsCreated();
                    detectionsCreated += result.detectionsCreated();
                    detectionsUpdated += result.detectionsUpdated();
                    warnings          += result.warnings().size();
                    tasksSynced++;
                    log.info("Greenbone sync job={} task={} assets={} detections created/updated={}/{}",
                        jobId, taskId, result.assetsCreated(), result.detectionsCreated(), result.detectionsUpdated());
                } catch (Exception e) {
                    errors.add("Task " + taskId + " (" + grant.taskName() + "): " + e.getMessage());
                    log.warn("Greenbone sync job={} task={} failed: {}", jobId, taskId, e.getMessage());
                }
                setStatus(jobId, null, 10 + (80 * (idx + 1) / grants.size()));
            }

            updateLastSync(integrationId);

            Map<String, Object> resultData = new LinkedHashMap<>();
            resultData.put("tasksSynced",       tasksSynced);
            resultData.put("tasksTotal",        grants.size());
            resultData.put("assetsCreated",     assetsCreated);
            resultData.put("detectionsCreated", detectionsCreated);
            resultData.put("detectionsUpdated", detectionsUpdated);
            resultData.put("warnings",          warnings);
            if (!errors.isEmpty()) resultData.put("errors", errors);

            if (tasksSynced == 0 && !grants.isEmpty()) {
                safeFailJob(jobId, "Failed to sync any granted task: " + String.join("; ", errors));
            } else {
                completeJob(jobId, resultData);
            }
            log.info("Greenbone sync done job={} synced={}/{} assets={} detections={}",
                jobId, tasksSynced, grants.size(), assetsCreated, detectionsCreated);

        } catch (Exception ex) {
            log.error("Greenbone vuln sync failed job={}", jobId, ex);
            safeFailJob(jobId, ex.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * If the integration has a configured GVM web UI base URL, stamps each parsed detection's
     * rawData with a direct "<webUrl>/nvt/<oid>" link — the file-import Phase 1 flow has no known
     * instance URL, so those detections simply lack this field and the frontend badge renders
     * without a link (same graceful fallback as Nuclei's optional template-url).
     */
    private void injectNvtUrls(ParseResult parsed, String settingsJson) {
        String webUrl = extractWebUrl(settingsJson);
        if (webUrl == null) return;
        for (ParsedDetection d : parsed.getDetections()) {
            try {
                JsonNode raw = objectMapper.readTree(d.getRawData());
                if (!(raw instanceof ObjectNode obj)) continue;
                String oid = raw.path("oid").asText(null);
                if (oid == null || oid.isBlank()) continue;
                obj.put("nvtUrl", webUrl + "/nvt/" + oid);
                d.setRawData(objectMapper.writeValueAsString(obj));
            } catch (Exception ignored) {}
        }
    }

    private String extractWebUrl(String settingsJson) {
        try {
            JsonNode n = objectMapper.readTree(settingsJson);
            String url = n.path("webUrl").asText(null);
            if (url == null || url.isBlank()) return null;
            return url.trim().replaceAll("/+$", "");
        } catch (Exception e) { return null; }
    }

    private void setStatus(Long jobId, String status, Integer progress) {
        try { jobFacade.update(jobId, status, progress, null, null); }
        catch (Exception e) { log.warn("job update failed: {}", e.getMessage()); }
    }

    private void completeJob(Long jobId, Map<String, Object> resultData) {
        try {
            String json = objectMapper.writeValueAsString(resultData);
            jobFacade.update(jobId, "completed", 100, json, null);
        } catch (Exception e) { log.warn("Could not complete job {}: {}", jobId, e.getMessage()); }
    }

    private void safeFailJob(Long jobId, String error) {
        try { jobFacade.update(jobId, "failed", null, null, error); }
        catch (Exception ignored) {}
    }

    private void updateLastSync(Long integrationId) {
        try {
            integrationFacade.recordSyncResult(integrationId, "success");
        } catch (Exception e) {
            log.warn("Could not update lastSyncAt for integration {}: {}", integrationId, e.getMessage());
        }
    }
}
