package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.ids.desktop.service.BackendClient;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * IP Investigation Panel — a self-contained JavaFX component.
 *
 * Drop this into any HBox or SplitPane. Call investigate(ip) to load
 * a profile. The panel manages its own background threads safely.
 *
 * Design principle: Every network call happens in a Task (background thread).
 * All UI updates go through Platform.runLater(). This ensures the JavaFX
 * Application Thread is never blocked, even on slow backends.
 */
public class IpInvestigationPanel extends VBox {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());
    private static final DateTimeFormatter TIME_FMT =
        DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    private BackendClient backend;

    //Header
    private final Label  lblIp         = bold("", 16);
    private final Label  lblRiskBadge  = new Label("—");
    private final Label  lblScore      = new Label("Score: —");

    //Overview grid
    private final Label lblFirstSeen   = info("—");
    private final Label lblLastSeen    = info("—");
    private final Label lblTargets     = info("—");
    private final Label lblTotalAlerts = info("—");
    private final Label lblTopThreat   = info("—");
    private final Label lblMostTarget  = info("—");
    private final Label lblProtocols   = info("—");
    private final Label lblMac         = info("—");

    //Threat history
    private final ListView<String>         threatHistoryList   = new ListView<>();
    private java.util.List<JsonNode>       threatHistoryNodes  = new java.util.ArrayList<>();

    //Threat detail
    private final Label  lblDetailType     = info("—");
    private final Label  lblDetailSeverity = info("—");
    private final Label  lblDetailDest     = info("—");
    private final Label  lblDetailProto    = info("—");
    private final Label  lblDetailPackets  = info("—");
    private final Label  lblDetailTs       = info("—");
    private final Label  lblDetailWindow   = info("—");
    private final TextArea txtDetailReason = new TextArea("Select a threat to see why it triggered.");
    private final VBox   packetEvidenceBox = new VBox(6);

    // Timeline
    private final VBox timelineBox = new VBox(8);

    // ── Status
    private final Label lblStatus = new Label("Click a source IP to investigate.");

    private String currentIp = null;

    public IpInvestigationPanel(BackendClient backend, Runnable onClose) {
        this.backend = backend;
        buildUI(onClose);
    }

    //  PUBLIC API

    /**
     * Load and display the investigation profile for the given IP.
     * Safe to call from the FX thread — the HTTP call runs in a Task.
     */
    public void investigate(String ip) {
        if (ip == null || ip.isBlank()) return;
        currentIp = ip;
        setStatus("Loading profile for " + ip + "...");
        clearAll();

        Task<JsonNode> profileTask = new Task<>() {
            @Override protected JsonNode call() throws Exception {
                return backend.getIpProfile(ip);
            }
        };
        profileTask.setOnSucceeded(e -> {
            populateProfile(profileTask.getValue());
            loadTimeline(ip);
        });
        profileTask.setOnFailed(e ->
            Platform.runLater(() -> setStatus("Failed to load profile: "
                + profileTask.getException().getMessage())));

        Thread t = new Thread(profileTask, "ids-ip-profile");
        t.setDaemon(true);
        t.start();
    }

    //PRIVATE BUILD

    private void buildUI(Runnable onClose) {
        setSpacing(0);
        setStyle("-fx-background-color: #0d1117;");
        setPrefWidth(420);
        setMinWidth(380);

        getChildren().addAll(
            buildHeader(onClose),
            buildOverviewSection(),
            buildThreatHistorySection(),
            buildThreatDetailSection(),
            buildTimelineSection(),
            lblStatus
        );

        lblStatus.setStyle("-fx-text-fill: #6b7280; -fx-font-size: 11px;");
        lblStatus.setPadding(new Insets(6, 12, 6, 12));
    }

    private HBox buildHeader(Runnable onClose) {
        HBox header = new HBox(8);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(12, 12, 8, 12));
        header.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d;"
                      + "-fx-border-width: 0 0 1 0;");

        // Risk badge styling
        lblRiskBadge.setStyle("-fx-padding: 2 8 2 8; -fx-background-radius: 4;"
                            + "-fx-font-size: 11px; -fx-font-weight: bold;"
                            + "-fx-background-color: #21262d; -fx-text-fill: #8b949e;");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button btnClose = new Button("✕");
        btnClose.setStyle("-fx-background-color: transparent; -fx-text-fill: #6b7280;"
                        + "-fx-cursor: hand; -fx-font-size: 14px;");
        btnClose.setOnAction(e -> onClose.run());
        btnClose.setTooltip(new Tooltip("Close investigation panel"));

        VBox titleBox = new VBox(2, lblIp, new HBox(6, lblRiskBadge, lblScore));
        lblScore.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11px;");

        header.getChildren().addAll(new Circle(5, Color.web("#f59e0b")), titleBox, spacer, btnClose);
        return header;
    }

    private VBox buildOverviewSection() {
        return section("Overview",
            twoColGrid(
                
                "MAC Address",   lblMac,
                "First Seen",    lblFirstSeen,
                "Last Seen",     lblLastSeen,
                "Total Alerts",  lblTotalAlerts,
                "Targets",       lblTargets,
                "Protocols",     lblProtocols,
                "Top Threat",    lblTopThreat,
                "Most Targeted", lblMostTarget
            ));
    }

    private VBox buildThreatHistorySection() {
        threatHistoryList.setPrefHeight(140);
        threatHistoryList.setStyle("-fx-background-color: #0d1117; -fx-border-color: #30363d;");
        threatHistoryList.getSelectionModel().selectedIndexProperty().addListener(
            (obs, ov, nv) -> {
                int idx = nv.intValue();
                if (idx >= 0 && idx < threatHistoryNodes.size())
                    populateThreatDetail(threatHistoryNodes.get(idx));
            });
        return section("Threat History", threatHistoryList);
    }

    private VBox buildThreatDetailSection() {
        txtDetailReason.setWrapText(true);
        txtDetailReason.setPrefHeight(80);
        txtDetailReason.setEditable(false);
        txtDetailReason.setStyle("-fx-control-inner-background: #161b22; -fx-text-fill: #c9d1d9;"
                               + "-fx-border-color: #30363d; -fx-font-size: 11px;");

        // Packet evidence — collapsible
        TitledPane packetPane = new TitledPane("Packet Evidence", buildPacketEvidenceScroll());
        packetPane.setExpanded(false);
        packetPane.setStyle("-fx-text-fill: #8b949e; -fx-background-color: #0d1117;");

        VBox content = new VBox(6,
            twoColGrid(
                "Threat Type",  lblDetailType,
                "Severity",     lblDetailSeverity,
                "Destination",  lblDetailDest,
                "Protocol",     lblDetailProto,
                "Packets",      lblDetailPackets,
                "Window",       lblDetailWindow,
                "Timestamp",    lblDetailTs
            ),
            new Label("Detection Reason:") {{ setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11px;"); }},
            txtDetailReason,
            packetPane
        );
        content.setSpacing(6);

        return section("Threat Details", content);
    }

    private ScrollPane buildPacketEvidenceScroll() {
        packetEvidenceBox.setStyle("-fx-background-color: #0d1117;");
        packetEvidenceBox.setPadding(new Insets(4));
        ScrollPane sp = new ScrollPane(packetEvidenceBox);
        sp.setFitToWidth(true);
        sp.setPrefHeight(200);
        sp.setStyle("-fx-background: #0d1117; -fx-background-color: #0d1117;");
        return sp;
    }

    private VBox buildTimelineSection() {
        timelineBox.setStyle("-fx-background-color: #0d1117;");
        timelineBox.setPadding(new Insets(8, 4, 8, 4));
        ScrollPane sp = new ScrollPane(timelineBox);
        sp.setFitToWidth(true);
        sp.setPrefHeight(220);
        sp.setStyle("-fx-background: #0d1117; -fx-background-color: #0d1117;");
        return section("Attack Timeline", sp);
    }

    //POPULATION

    private void populateProfile(JsonNode p) {
        Platform.runLater(() -> {
            if (p == null) { setStatus("No data found."); return; }

            String ip  = p.path("ip").asText("Unknown");
            String mac = p.path("mac").asText("Unknown");
            String risk = p.path("riskLevel").asText("LOW");
            int score   = p.path("threatScore").asInt(0);

            lblIp.setText(ip);
            lblMac.setText(mac);
            lblTotalAlerts.setText(String.valueOf(p.path("totalAlerts").asLong()));
            lblTargets.setText(p.path("targetCount").asLong() + " hosts");
            lblTopThreat.setText(p.path("topThreatType").asText("—"));
            lblMostTarget.setText(p.path("mostTargetedHost").asText("—"));
            lblScore.setText("Score: " + score + " / 100");

            // Format timestamps
            safeSetInstant(p.path("firstSeen").asText(), lblFirstSeen);
            safeSetInstant(p.path("lastSeen").asText(), lblLastSeen);

            // Protocols
            StringBuilder protos = new StringBuilder();
            p.path("protocols").forEach(n -> {
                if (protos.length() > 0) protos.append(", ");
                protos.append(n.asText());
            });
            lblProtocols.setText(protos.length() > 0 ? protos.toString() : "—");

            // Risk badge color
            applyRiskStyle(lblRiskBadge, risk);
            lblRiskBadge.setText(risk);

            // Populate threat history list
            threatHistoryNodes.clear();
            threatHistoryList.getItems().clear();

            JsonNode threats = p.path("recentThreats");
            int i = 1;
            for (JsonNode t : threats) {
                threatHistoryNodes.add(t);
                String time = "";
                try {
                    time = TIME_FMT.format(Instant.parse(t.path("timestamp").asText()));
                } catch (Exception ignored) {}
                String sev  = t.path("severity").asText("?");
                String type = t.path("threatType").asText("UNKNOWN");
                threatHistoryList.getItems().add(
                    String.format("%2d. [%s] %-9s %s", i++, time, sev, type));
            }

            setStatus("Loaded profile for " + ip + " — " + threats.size() + " events");
        });
    }

    private void populateThreatDetail(JsonNode t) {
        lblDetailType.setText(t.path("threatType").asText("—"));
        lblDetailDest.setText(t.path("destIp").asText("—"));
        lblDetailProto.setText(t.path("protocol").asText("—"));
        lblDetailPackets.setText(String.valueOf(t.path("packetCount").asInt(0)));
        lblDetailWindow.setText(t.path("windowMs").asLong(0) + " ms");
        safeSetInstant(t.path("timestamp").asText(), lblDetailTs);

        String severity = t.path("severity").asText("—");
        lblDetailSeverity.setText(severity);
        applyRiskStyle(lblDetailSeverity, severity);

        String details = t.path("details").asText("");
        txtDetailReason.setText(details.isBlank()
            ? "No additional details recorded." : details);

        // Build Wireshark-style packet evidence from available fields
        buildPacketEvidence(t);
    }

    /**
     * Wireshark-style packet evidence.
     *
     * We don't have full packet captures stored per alert (that would require
     * the PacketLog table). What we DO have is enough to build a meaningful
     * evidence panel. Each layer is an expandable TitledPane.
     *
     * When you hook in PacketLog data in a future phase, just add more layers here.
     */
    private void buildPacketEvidence(JsonNode alert) {
        packetEvidenceBox.getChildren().clear();

        // Ethernet Layer
        TitledPane ethPane = evidenceLayer("Ethernet Layer",
        	    "Source MAC",      alert.path("sourceMac").asText("—"),
        	    "Destination MAC", alert.path("destMac").asText("—"),
        	    "Protocol",        alert.path("protocol").asText("—")
        	);

        // IP Layer
        TitledPane ipPane = evidenceLayer("IP Layer",
            "Source IP",       alert.path("sourceIp").asText("—"),
            "Destination IP",  alert.path("destIp").asText("—"),
            "Protocol",        alert.path("protocol").asText("—"),
            "Packet Count",    String.valueOf(alert.path("packetCount").asInt(0))
        );

        // Application layer — parsed from requestType and details
        String requestType = alert.path("requestType").asText("");
        String details     = alert.path("details").asText("");
        String threatType  = alert.path("threatType").asText("");

        TitledPane appPane = buildAppLayerPane(threatType, requestType, details);

        // Detection context
        TitledPane detectionPane = evidenceLayer("IDS Detection Context",
            "Detector",        threatType,
            "Window (ms)",     String.valueOf(alert.path("windowMs").asLong(0)),
            "Severity",        alert.path("severity").asText("—"),
            "Detection Reason", details.length() > 80 ? details.substring(0, 80) + "…" : details
        );

        ethPane.setExpanded(true);
        ipPane.setExpanded(true);
        appPane.setExpanded(true);
        detectionPane.setExpanded(false);

        packetEvidenceBox.getChildren().addAll(ethPane, ipPane, appPane, detectionPane);
    }

    private TitledPane buildAppLayerPane(String threatType, String requestType, String details) {
        String layerName;
        String[][] fields;

        if (threatType.contains("HTTP") || requestType.startsWith("GET")
                || requestType.startsWith("POST")) {
            layerName = "HTTP Layer";
            fields = new String[][] {
                {"Method",    requestType.split(" ")[0]},
                {"URI",       requestType.contains(" ") ? requestType.split(" ")[1] : "—"},
                {"Details",   details.length() > 100 ? details.substring(0, 100) + "…" : details}
            };
        } else if (threatType.contains("DNS")) {
            layerName = "DNS Layer";
            fields = new String[][] {
                {"Query",   extractFromDetails(details, "domain", "query")},
                {"Details", details.length() > 100 ? details.substring(0, 100) + "…" : details}
            };
        } else if (threatType.contains("SSH") || threatType.contains("BRUTE")) {
            layerName = "TCP / Application Layer";
            fields = new String[][] {
                {"Target Service", "SSH (port 22)"},
                {"Attempt Count",  extractFromDetails(details, "attempt", "count", "failed")},
                {"Details",        details.length() > 100 ? details.substring(0, 100) + "…" : details}
            };
        } else {
            layerName = "Application Layer";
            fields = new String[][] {
                {"Request Type", requestType.isBlank() ? "—" : requestType},
                {"Details",      details.length() > 100 ? details.substring(0, 100) + "…" : details}
            };
        }

        String[][] f = fields;
        return evidenceLayer(layerName, flattenFields(f));
    }

    //TIMELINE
    private void loadTimeline(String ip) {
        Task<JsonNode> task = new Task<>() {
            @Override protected JsonNode call() throws Exception {
                return backend.getTimeline(ip);
            }
        };
        task.setOnSucceeded(e -> buildTimeline(task.getValue()));
        task.setOnFailed(e -> Platform.runLater(
            () -> timelineBox.getChildren().setAll(new Label("Timeline unavailable."))));

        Thread t = new Thread(task, "ids-timeline");
        t.setDaemon(true);
        t.start();
    }

    private void buildTimeline(JsonNode alertArray) {
        List<AttackTimelineBuilder.TimelineEvent> events =
            AttackTimelineBuilder.build(alertArray);

        Platform.runLater(() -> {
            timelineBox.getChildren().clear();
            if (events.isEmpty()) {
                timelineBox.getChildren().add(
                    styledLabel("No timeline data available.", "#6b7280", 11));
                return;
            }

            for (AttackTimelineBuilder.TimelineEvent ev : events) {
                timelineBox.getChildren().add(buildTimelineCard(ev));
            }
        });
    }

    private VBox buildTimelineCard(AttackTimelineBuilder.TimelineEvent ev) {
        // Time + phase label
        HBox header = new HBox(8);
        header.setAlignment(Pos.CENTER_LEFT);

        Label lblTime  = styledLabel(ev.time(), "#6b7280", 11);
        Label lblPhase = new Label(ev.phase().label);
        applyRiskStyle(lblPhase, ev.severity());
        lblPhase.setStyle(lblPhase.getStyle() + "-fx-font-size: 11px; -fx-padding: 1 6 1 6;"
                        + "-fx-background-radius: 3;");

        Label lblCount = styledLabel("× " + ev.alertCount(), "#6b7280", 10);
        header.getChildren().addAll(lblTime, lblPhase, lblCount);

        Label lblTitle = bold(ev.title(), 12);
        Label lblDesc  = new Label(ev.description());
        lblDesc.setWrapText(true);
        lblDesc.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11px;");

        VBox card = new VBox(3, header, lblTitle, lblDesc);
        card.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d;"
                    + "-fx-border-radius: 6; -fx-background-radius: 6; -fx-padding: 8;");
        return card;
    }

    //HELPERS
    private VBox section(String title, javafx.scene.Node content) {
        Label lbl = new Label(title);
        lbl.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11px; -fx-font-weight: bold;");
        lbl.setPadding(new Insets(10, 12, 4, 12));

        VBox box = new VBox(0, lbl, padded(content));
        box.setStyle("-fx-border-color: transparent transparent #21262d transparent;"
                   + "-fx-border-width: 0 0 1 0;");
        return box;
    }

    private VBox padded(javafx.scene.Node node) {
        VBox v = new VBox(node);
        v.setPadding(new Insets(0, 12, 8, 12));
        return v;
    }

    // Two-column grid: "Key", valueLabel, "Key", valueLabel, ...
    private GridPane twoColGrid(Object... pairs) {
        GridPane grid = new GridPane();
        grid.setHgap(12); grid.setVgap(4);
        ColumnConstraints c1 = new ColumnConstraints(110);
        ColumnConstraints c2 = new ColumnConstraints();
        c2.setHgrow(Priority.ALWAYS);
        grid.getColumnConstraints().addAll(c1, c2);

        for (int i = 0; i < pairs.length; i += 2) {
            Label key = new Label(String.valueOf(pairs[i]) + ":");
            key.setStyle("-fx-text-fill: #6b7280; -fx-font-size: 11px;");
            javafx.scene.Node val = (pairs[i+1] instanceof javafx.scene.Node n)
                ? n : new Label(String.valueOf(pairs[i+1]));
            grid.addRow(i / 2, key, val);
        }
        return grid;
    }

    private TitledPane evidenceLayer(String title, String... kvPairs) {
        GridPane grid = new GridPane();
        grid.setHgap(12); grid.setVgap(3);
        grid.setPadding(new Insets(4));
        ColumnConstraints c1 = new ColumnConstraints(120);
        ColumnConstraints c2 = new ColumnConstraints();
        c2.setHgrow(Priority.ALWAYS);
        grid.getColumnConstraints().addAll(c1, c2);

        for (int i = 0; i < kvPairs.length; i += 2) {
            Label k = new Label(kvPairs[i] + ":");
            k.setStyle("-fx-text-fill: #6b7280; -fx-font-size: 11px;");
            Label v = new Label(kvPairs[i + 1]);
            v.setStyle("-fx-text-fill: #00d4ff; -fx-font-size: 11px;");
            v.setWrapText(true);
            grid.addRow(i / 2, k, v);
        }

        TitledPane pane = new TitledPane(title, grid);
        pane.setStyle("-fx-font-size: 11px; -fx-text-fill: #8b949e;"
                    + "-fx-background-color: #161b22;");
        return pane;
    }

    private static Label bold(String text, int size) {
        Label l = new Label(text);
        l.setFont(Font.font("System", FontWeight.BOLD, size));
        l.setStyle("-fx-text-fill: #c9d1d9;");
        return l;
    }

    private static Label info(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: #00d4ff; -fx-font-size: 12px;");
        return l;
    }

    private static Label styledLabel(String text, String color, int size) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: " + color + "; -fx-font-size: " + size + "px;");
        return l;
    }

    private void applyRiskStyle(Label lbl, String level) {
        String style = switch (level == null ? "" : level.toUpperCase()) {
            case "CRITICAL" -> "-fx-text-fill: #ef4444; -fx-background-color: #3f1f1f;";
            case "HIGH"     -> "-fx-text-fill: #f97316; -fx-background-color: #3f2a1a;";
            case "MEDIUM"   -> "-fx-text-fill: #f59e0b; -fx-background-color: #3f3520;";
            case "LOW"      -> "-fx-text-fill: #22c55e; -fx-background-color: #1a3f2a;";
            default         -> "-fx-text-fill: #8b949e; -fx-background-color: #21262d;";
        };
        lbl.setStyle(lbl.getStyle().replaceAll("-fx-text-fill:[^;]+;", "")
                        .replaceAll("-fx-background-color:[^;]+;", "")
                    + style);
    }

    private void safeSetInstant(String raw, Label lbl) {
        try {
            lbl.setText(FMT.format(Instant.parse(raw)));
        } catch (Exception e) {
            lbl.setText(raw.isBlank() ? "—" : raw);
        }
    }
    public void setBackend(BackendClient backend) {
        this.backend = backend;
    }

    private void setStatus(String msg) {
        Platform.runLater(() -> lblStatus.setText(msg));
    }

    private void clearAll() {
        Platform.runLater(() -> {
            lblIp.setText("Loading...");
            lblRiskBadge.setText("—");
            lblScore.setText("Score: —");
            lblFirstSeen.setText("—"); lblLastSeen.setText("—");
            lblTargets.setText("—"); lblTotalAlerts.setText("—");
            lblTopThreat.setText("—"); lblMostTarget.setText("—");
            lblProtocols.setText("—"); lblMac.setText("—");
            threatHistoryList.getItems().clear();
            threatHistoryNodes.clear();
            lblDetailType.setText("—"); lblDetailSeverity.setText("—");
            lblDetailDest.setText("—"); lblDetailProto.setText("—");
            lblDetailPackets.setText("—"); lblDetailTs.setText("—");
            lblDetailWindow.setText("—");
            txtDetailReason.setText("Select a threat to see why it triggered.");
            packetEvidenceBox.getChildren().clear();
            timelineBox.getChildren().clear();
        });
    }

    private String extractFromDetails(String details, String... keywords) {
        if (details == null || details.isBlank()) return "—";
        // Simple: return first line or the whole thing shortened
        String[] lines = details.split("[,\\.\\n]");
        for (String kw : keywords)
            for (String line : lines)
                if (line.toLowerCase().contains(kw.toLowerCase()))
                    return line.trim();
        return details.length() > 60 ? details.substring(0, 60) + "…" : details;
    }

    private String[] flattenFields(String[][] fields) {
        String[] flat = new String[fields.length * 2];
        for (int i = 0; i < fields.length; i++) {
            flat[i * 2]     = fields[i][0];
            flat[i * 2 + 1] = fields[i].length > 1 ? fields[i][1] : "—";
        }
        return flat;
    }
}