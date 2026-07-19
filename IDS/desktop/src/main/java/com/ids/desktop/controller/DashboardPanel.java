package com.ids.desktop.controller;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.desktop.service.BackendClient;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Label;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;

/**
 * DashboardPanel — the SOC-style overview screen (Dashboard tab).
 *
 * ARCHITECTURE NOTE
 * ------------------
 * Same pattern as every other panel in this app (CaseDetailPanel,
 * AlertGroupsPanel, IpInvestigationPanel): a plain VBox that MainController
 * drops into a tab. No FXML for the internals — built in code, matching
 * how those panels work.
 *
 * Data comes from GET /api/dashboard/summary and GET /api/dashboard/health
 * (DashboardController on the backend). We parse JsonNode directly instead
 * of adding new model classes — same shortcut CaseDetailPanel already uses
 * for its Overview/Notes tabs. Two small local row classes (DashAlertRow,
 * DashCaseRow) exist only to feed TableView columns; they are not part of
 * the app's shared model package on purpose — they're throwaway view rows,
 * reusing AlertItem/CaseItem would force a mismatch (those classes carry
 * fields this JSON doesn't have).
 *
 * THREADING
 * ---------
 * One ScheduledExecutorService (daemon thread "ids-dashboard") polls the
 * backend every 5 seconds. HTTP calls happen on that thread; every UI
 * mutation is wrapped in Platform.runLater(). This mirrors DataLoader's
 * pattern used by MainController — the FX thread is never blocked.
 *
 * LIFECYCLE
 * ---------
 * MainController calls start() once logged in, and stop() from its own
 * shutdown() method (same place it already stops the live feed socket).
 * Polling only needs to run while this tab could plausibly be visible;
 * for simplicity (per the "keep it simple" brief) it runs continuously
 * rather than pausing when another tab is selected. At 1 request/5s this
 * is not meaningful load — revisit only if that changes.
 */
public class DashboardPanel extends VBox {

	private static final String BG_ROOT   = Theme.BG_ROOT;
	private static final String BG_CARD   = Theme.BG_CARD;
	private static final String BORDER    = Theme.BORDER;
	private static final String TEXT_MAIN = Theme.TEXT_MAIN;
	private static final String TEXT_SUB  = Theme.TEXT_SUB;

	private static final String COLOR_CRITICAL = Theme.SEVERITY_CRITICAL;
	private static final String COLOR_HIGH     = Theme.SEVERITY_HIGH;
	private static final String COLOR_MEDIUM   = Theme.SEVERITY_MEDIUM;
	private static final String COLOR_LOW      = Theme.SEVERITY_LOW;   // now blue, not green — see Theme.java doc

    private static final DateTimeFormatter TIME_FMT =
            DateTimeFormatter.ofPattern("HH:mm").withZone(ZoneId.systemDefault());

    private final ObjectMapper mapper = new ObjectMapper();
    private BackendClient backend;

    private ScheduledExecutorService scheduler;

    // ── Stat cards ──────────────────────────────────────────────────────
    private Label lblActiveAlerts, lblCriticalThreats, lblOpenCases, lblMonitoredHosts;
    private Label lblOpenCasesSub;

    // ── Charts ──────────────────────────────────────────────────────────
    private LineChart<String, Number> activityChart;
    private XYChart.Series<String, Number> seriesTotal;
    private XYChart.Series<String, Number> seriesCritical;
    private PieChart severityChart;

    // ── Tables ──────────────────────────────────────────────────────────
    // Top Alerts and Threat Actors are each split Active/Whitelisted: two
    // backing lists per section, one tab per list. The Tab references exist
    // only so refresh can rewrite the "(n)" counts in the titles.
    private final ObservableList<TopAlertRow> activeAlerts = FXCollections.observableArrayList();
    private final ObservableList<TopAlertRow> whitelistedAlerts = FXCollections.observableArrayList();
    private Tab tabAlertsActive, tabAlertsWhitelisted;

    private final ObservableList<ThreatActorRow> activeActors = FXCollections.observableArrayList();
    private final ObservableList<ThreatActorRow> whitelistedActors = FXCollections.observableArrayList();
    private Tab tabActorsActive, tabActorsWhitelisted;

    private TableView<DashCaseRow> recentCasesTable;
    private final ObservableList<DashCaseRow> recentCases = FXCollections.observableArrayList();
    private final java.util.function.Consumer<String> onIpClick;
   

    private Label lblLastUpdated;

    public DashboardPanel(BackendClient backend, java.util.function.Consumer<String> onIpClick) {
        this.backend = backend;
        this.onIpClick = onIpClick;
        setStyle("-fx-background-color: " + BG_ROOT + ";");
        setSpacing(16);
        setPadding(new Insets(16));
        buildUI();
    }

    public void setBackend(BackendClient backend) {
        this.backend = backend;
    }

    // ── LIFECYCLE ───────────────────────────────────────────────────────

    /** Starts the 5-second polling loop. Safe to call more than once (restarts). */
    public void start() {
        stop(); // guard against double-start leaking a thread
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ids-dashboard");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::refresh, 0, 5, TimeUnit.SECONDS);
    }

    /** Stops polling. Call this from MainController.shutdown(). */
    public void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    // ── UI CONSTRUCTION ─────────────────────────────────────────────────

    private void buildUI() {
        ScrollPane scroll = new ScrollPane();
        scroll.setFitToWidth(true);
        scroll.setStyle("-fx-background: " + BG_ROOT + "; -fx-background-color: " + BG_ROOT + ";");

        VBox content = new VBox(16);
        content.setPadding(new Insets(4));

        content.getChildren().addAll(
                buildStatCardsRow(),
                buildChartsRow(),
                buildTopAlertsSection(),
                buildAlertsAndHealthRow(),
                buildRecentCasesSection()
        );

        lblLastUpdated = new Label("Waiting for first refresh…");
        lblLastUpdated.setStyle("-fx-text-fill: " + TEXT_SUB + "; -fx-font-size: 10;");

        scroll.setContent(content);
        VBox.setVgrow(scroll, Priority.ALWAYS);

        getChildren().addAll(scroll, lblLastUpdated);
    }

    // ── Row 1: stat cards ───────────────────────────────────────────────

    private HBox buildStatCardsRow() {
        HBox row = new HBox(16);

        VBox cardAlerts = statCard("Active Alerts", "0", "#1f6feb");
        lblActiveAlerts = (Label) ((VBox) cardAlerts.getChildren().get(1)).getChildren().get(0);

        VBox cardCritical = statCard("Critical Threats", "0", COLOR_CRITICAL);
        lblCriticalThreats = (Label) ((VBox) cardCritical.getChildren().get(1)).getChildren().get(0);

        VBox cardCases = statCard("Open Cases", "0", "#8957e5");
        VBox cardCasesTextBox = (VBox) cardCases.getChildren().get(1);
        lblOpenCases = (Label) cardCasesTextBox.getChildren().get(0);
        lblOpenCasesSub = new Label("0 investigating");
        lblOpenCasesSub.setStyle("-fx-text-fill: " + TEXT_SUB + "; -fx-font-size: 11;");
        cardCasesTextBox.getChildren().add(lblOpenCasesSub);

        VBox cardHosts = statCard("Monitored Hosts", "0", "#22c55e");
        lblMonitoredHosts = (Label) ((VBox) cardHosts.getChildren().get(1)).getChildren().get(0);

        for (VBox c : List.of(cardAlerts, cardCritical, cardCases, cardHosts)) {
            HBox.setHgrow(c, Priority.ALWAYS);
        }

        row.getChildren().addAll(cardAlerts, cardCritical, cardCases, cardHosts);
        return row;
    }

    /** Builds a card: [colored accent bar+icon | VBox(bigNumber, title)]. */
    private VBox statCard(String title, String initialValue, String accentColor) {
        VBox card = new VBox();
        card.setStyle("-fx-background-color: " + BG_CARD + "; -fx-border-color: " + BORDER +
                "; -fx-border-width: 1; -fx-background-radius: 8; -fx-border-radius: 8;");
        card.setPadding(new Insets(14));
        card.setSpacing(4);
        card.setMinWidth(180);

        Region accent = new Region();
        accent.setPrefHeight(3);
        accent.setStyle("-fx-background-color: " + accentColor + "; -fx-background-radius: 2;");

        Label big = new Label(initialValue);
        big.setStyle("-fx-text-fill: " + TEXT_MAIN + "; -fx-font-size: 26; -fx-font-weight: bold;");

        Label sub = new Label(title);
        sub.setStyle("-fx-text-fill: " + TEXT_SUB + "; -fx-font-size: 12;");

        VBox textBox = new VBox(2, big, sub);
        card.getChildren().addAll(accent, textBox);
        card.setEffect(Theme.cardShadow());
        return card;
    }

    // ── Row 2: activity line chart + severity donut ────────────────────

    private HBox buildChartsRow() {
        HBox row = new HBox(16);

        // Activity line chart
        VBox activityBox = panelContainer("Alert Activity (Last Hour)");
        CategoryAxis xAxis = new CategoryAxis();
        NumberAxis yAxis = new NumberAxis();
        xAxis.setTickLabelFill(Color.web(TEXT_SUB));
        yAxis.setTickLabelFill(Color.web(TEXT_SUB));
        activityChart = new LineChart<>(xAxis, yAxis);
        activityChart.setAnimated(false);
        activityChart.setLegendVisible(true);
        activityChart.setStyle("-fx-background-color: " + BG_CARD + ";");
        activityChart.setCreateSymbols(false);
        activityChart.setPrefHeight(260);

        seriesTotal = new XYChart.Series<>();
        seriesTotal.setName("Alerts");
        seriesCritical = new XYChart.Series<>();
        seriesCritical.setName("Critical");
        activityChart.getData().addAll(seriesTotal, seriesCritical);
        activityBox.getChildren().add(activityChart);
        HBox.setHgrow(activityBox, Priority.ALWAYS);

        // Severity donut
        VBox severityBox = panelContainer("Alert Severity Distribution");
        severityChart = new PieChart();
        severityChart.setLegendVisible(true);
        severityChart.setLabelsVisible(true);
        severityChart.setStyle("-fx-background-color: " + BG_CARD + ";");
        severityChart.setPrefHeight(280);
        severityChart.setPrefWidth(340);
        severityBox.getChildren().add(severityChart);

        row.getChildren().addAll(activityBox, severityBox);
        return row;
    }

    // ── Row 3: Top Alerts (Active / Whitelisted) ────────────────────────

    private VBox buildTopAlertsSection() {
        VBox box = panelContainer("Top Alerts");
        TableView<TopAlertRow> activeTable =
                buildTopAlertsTable(activeAlerts, "No alerts yet.");
        TableView<TopAlertRow> whitelistedTable =
                buildTopAlertsTable(whitelistedAlerts, "No whitelisted hosts with recent activity.");
        activeTable.setPrefHeight(240);
        whitelistedTable.setPrefHeight(240);
        tabAlertsActive      = new Tab("Active (0)", activeTable);
        tabAlertsWhitelisted = new Tab("Whitelisted (0)", whitelistedTable);
        box.getChildren().add(splitTabPane(tabAlertsActive, tabAlertsWhitelisted));
        return box;
    }

    private TableView<TopAlertRow> buildTopAlertsTable(
            ObservableList<TopAlertRow> items, String placeholder) {
        TableView<TopAlertRow> tv = new TableView<>();
        tv.setStyle("-fx-background-color: " + BG_CARD + ";");
        tv.setItems(items);
        tv.setPlaceholder(new Label(placeholder));

        TableColumn<TopAlertRow, String> colTime = new TableColumn<>("Time");
        colTime.setCellValueFactory(new PropertyValueFactory<>("timestamp"));

        TableColumn<TopAlertRow, String> colSeverity = new TableColumn<>("Severity");
        colSeverity.setCellValueFactory(new PropertyValueFactory<>("severity"));
        colSeverity.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String sev, boolean empty) {
                super.updateItem(sev, empty);
                if (empty || sev == null) { setText(null); setStyle(""); return; }
                setText(sev);
                setStyle("-fx-text-fill: " + severityColor(sev) + "; -fx-font-weight: bold;");
            }
        });

        TableColumn<TopAlertRow, String> colThreat = new TableColumn<>("Threat Type");
        colThreat.setCellValueFactory(new PropertyValueFactory<>("threatType"));

        TableColumn<TopAlertRow, String> colSource = new TableColumn<>("Source IP");
        colSource.setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        colSource.setCellFactory(col -> ipLinkCell());

        TableColumn<TopAlertRow, String> colDest = new TableColumn<>("Dest IP");
        colDest.setCellValueFactory(new PropertyValueFactory<>("destIp"));

        TableColumn<TopAlertRow, String> colProtocol = new TableColumn<>("Protocol");
        colProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));

        // Threat Type is the free-text column (hover shows the full value).
        TableLayout.constrain(tv);
        TableLayout.bounded(colTime,      55,  70,  95);
        TableLayout.bounded(colSeverity,  70,  90, 110);
        TableLayout.flex   (colThreat,   120, 160);
        TableLayout.bounded(colSource,   100, 120, 150);
        TableLayout.bounded(colDest,     100, 120, 150);
        TableLayout.bounded(colProtocol,  60,  80, 100);
        TableLayout.tooltipCells(colThreat);

        tv.getColumns().addAll(List.of(colTime, colSeverity, colThreat, colSource, colDest, colProtocol));
        return tv;
    }

    private String severityColor(String sev) {
        return switch (sev.toUpperCase()) {
            case "CRITICAL" -> COLOR_CRITICAL;
            case "HIGH"     -> COLOR_HIGH;
            case "MEDIUM"   -> COLOR_MEDIUM;
            case "LOW"      -> COLOR_LOW;
            default         -> TEXT_MAIN;
        };
    }

    private VBox buildRecentCasesSection() {
        VBox box = panelContainer("Recent Investigations");
        recentCasesTable = buildRecentCasesTable();
        recentCasesTable.setPrefHeight(200);
        box.getChildren().add(recentCasesTable);
        return box;
    }

    private TableView<DashCaseRow> buildRecentCasesTable() {
        TableView<DashCaseRow> tv = new TableView<>();
        tv.setStyle("-fx-background-color: " + BG_CARD + ";");
        tv.setItems(recentCases);
        tv.setPlaceholder(new Label("No cases yet."));

        TableColumn<DashCaseRow, String> colNum = new TableColumn<>("Case #");
        colNum.setCellValueFactory(new PropertyValueFactory<>("caseNumber"));

        TableColumn<DashCaseRow, String> colTitle = new TableColumn<>("Title");
        colTitle.setCellValueFactory(new PropertyValueFactory<>("title"));

        TableColumn<DashCaseRow, String> colPriority = new TableColumn<>("Priority");
        colPriority.setCellValueFactory(new PropertyValueFactory<>("priority"));

        TableColumn<DashCaseRow, String> colStatus = new TableColumn<>("Status");
        colStatus.setCellValueFactory(new PropertyValueFactory<>("status"));

        TableColumn<DashCaseRow, String> colOpened = new TableColumn<>("Opened");
        colOpened.setCellValueFactory(new PropertyValueFactory<>("openedAt"));

        TableColumn<DashCaseRow, String> colAssigned = new TableColumn<>("Assigned To");
        colAssigned.setCellValueFactory(new PropertyValueFactory<>("assignedTo"));

        // Title is the free-text column (hover shows the full value).
        TableLayout.constrain(tv);
        TableLayout.bounded(colNum,       90, 110, 140);
        TableLayout.flex   (colTitle,    140, 220);
        TableLayout.bounded(colPriority,  70,  90, 110);
        TableLayout.bounded(colStatus,    90, 110, 140);
        TableLayout.bounded(colOpened,   110, 140, 180);
        TableLayout.bounded(colAssigned,  90, 110, 150);
        TableLayout.tooltipCells(colTitle);

        tv.getColumns().addAll(List.of(colNum, colTitle, colPriority, colStatus, colOpened, colAssigned));
        return tv;
    }

    private VBox panelContainer(String title) {
        VBox box = new VBox(10);
        box.setStyle("-fx-background-color: " + BG_CARD + "; -fx-border-color: " + BORDER +
                "; -fx-border-width: 1; -fx-background-radius: 8; -fx-border-radius: 8;");
        box.setPadding(new Insets(12));

        Label lbl = new Label(title);
        lbl.setStyle("-fx-text-fill: " + TEXT_MAIN + "; -fx-font-size: 13; -fx-font-weight: bold;");
        box.getChildren().add(lbl);
        box.setEffect(Theme.cardShadow());
        return box;
    }

    // ── DATA REFRESH (background thread) ────────────────────────────────

    private void refresh() {
        if (backend == null || !backend.isLoggedIn()) return;

        try {
            JsonNode summary = mapper.readTree(backend.getRaw("/api/dashboard/summary"));
            JsonNode actorsJson = mapper.readTree(backend.getRaw("/api/dashboard/threat-actors?limit=15"));
            Platform.runLater(() -> {
            	applySummary(summary);
                applyThreatActors(actorsJson);
                lblLastUpdated.setText("Last updated " +
                        DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault())
                                .format(Instant.now()));
            });
        } catch (Exception e) {
            Platform.runLater(() ->
                    lblLastUpdated.setText("Refresh failed: " + e.getMessage()));
        }
    }

    private void applySummary(JsonNode s) {
        lblActiveAlerts.setText(String.valueOf(s.path("activeAlerts").asLong(0)));
        lblCriticalThreats.setText(String.valueOf(s.path("criticalThreats").asLong(0)));
        lblOpenCases.setText(String.valueOf(s.path("openCases").asLong(0)));
        lblOpenCasesSub.setText(s.path("investigatingCases").asLong(0) + " investigating");
        lblMonitoredHosts.setText(String.valueOf(s.path("monitoredHosts").asLong(0)));

        // Severity donut
        JsonNode dist = s.path("severityDistribution");
        ObservableList<PieChart.Data> pieData = FXCollections.observableArrayList(
                new PieChart.Data("Critical", dist.path("CRITICAL").asLong(0)),
                new PieChart.Data("High", dist.path("HIGH").asLong(0)),
                new PieChart.Data("Medium", dist.path("MEDIUM").asLong(0)),
                new PieChart.Data("Low", dist.path("LOW").asLong(0))
        );
        severityChart.setData(pieData);
        // Colour the slices after they're laid out (JavaFX requires the node to exist first)
        Platform.runLater(() -> {
            colorSlice(pieData, 0, COLOR_CRITICAL);
            colorSlice(pieData, 1, COLOR_HIGH);
            colorSlice(pieData, 2, COLOR_MEDIUM);
            colorSlice(pieData, 3, COLOR_LOW);
        });

        // Activity line chart
        seriesTotal.getData().clear();
        seriesCritical.getData().clear();
        for (JsonNode point : s.path("activity")) {
            String label = formatBucketTime(point.path("time").asText(""));
            seriesTotal.getData().add(new XYChart.Data<>(label, point.path("total").asLong(0)));
            seriesCritical.getData().add(new XYChart.Data<>(label, point.path("critical").asLong(0)));
        }

        // Top Alerts — partition into the Active/Whitelisted tabs
        List<TopAlertRow> active = new ArrayList<>();
        List<TopAlertRow> whitelisted = new ArrayList<>();
        for (JsonNode n : s.path("recentAlerts")) {
            TopAlertRow row = new TopAlertRow(
                    formatBucketTime(n.path("timestamp").asText("")),
                    n.path("severity").asText(""),
                    n.path("threatType").asText(""),
                    n.path("sourceIp").asText(""),
                    n.path("destIp").asText(""),
                    n.path("protocol").asText(""),
                    n.path("whitelisted").asBoolean(false)
            );
            (row.isWhitelisted() ? whitelisted : active).add(row);
        }
        activeAlerts.setAll(active);
        whitelistedAlerts.setAll(whitelisted);
        tabAlertsActive.setText("Active (" + active.size() + ")");
        tabAlertsWhitelisted.setText("Whitelisted (" + whitelisted.size() + ")");

        // Recent cases table
        List<DashCaseRow> caseRows = new ArrayList<>();
        for (JsonNode n : s.path("recentCases")) {
            caseRows.add(new DashCaseRow(
                    n.path("caseNumber").asText(""),
                    n.path("title").asText(""),
                    n.path("priority").asText(""),
                    n.path("status").asText(""),
                    formatBucketTime(n.path("openedAt").asText("")),
                    n.path("assignedTo").asText("")
            ));
        }
        recentCases.setAll(caseRows);
    }

    private void colorSlice(ObservableList<PieChart.Data> data, int index, String color) {
        if (index < data.size() && data.get(index).getNode() != null) {
            data.get(index).getNode().setStyle("-fx-pie-color: " + color + ";");
        }
    }

    private String formatBucketTime(String isoTimestamp) {
        if (isoTimestamp == null || isoTimestamp.isBlank()) return "";
        try {
            return TIME_FMT.format(Instant.parse(isoTimestamp));
        } catch (Exception e) {
            return isoTimestamp;
        }
    }
    public static class ThreatActorRow {
        private final int rank;
        private final String ip, topThreatType, lastSeen;
        private final int threatScore, totalAlerts;
        private final boolean whitelisted;

        public ThreatActorRow(int rank, String ip, int threatScore, int totalAlerts,
                               String topThreatType, String lastSeen, boolean whitelisted) {
            this.rank = rank;
            this.ip = ip;
            this.threatScore = threatScore;
            this.totalAlerts = totalAlerts;
            this.topThreatType = topThreatType;
            this.lastSeen = lastSeen;
            this.whitelisted = whitelisted;
        }

        public int getRank() { return rank; }
        public String getIp() { return ip; }
        public int getThreatScore() { return threatScore; }
        public int getTotalAlerts() { return totalAlerts; }
        public String getTopThreatType() { return topThreatType; }
        public String getLastSeen() { return lastSeen; }
        public boolean isWhitelisted() { return whitelisted; }
    }

    public static class TopAlertRow {
        private final String timestamp, severity, threatType, sourceIp, destIp, protocol;
        private final boolean whitelisted;

        public TopAlertRow(String timestamp, String severity, String threatType,
                            String sourceIp, String destIp, String protocol,
                            boolean whitelisted) {
            this.timestamp = timestamp;
            this.severity = severity;
            this.threatType = threatType;
            this.sourceIp = sourceIp;
            this.destIp = destIp;
            this.protocol = protocol;
            this.whitelisted = whitelisted;
        }

        public String getTimestamp() { return timestamp; }
        public String getSeverity() { return severity; }
        public String getThreatType() { return threatType; }
        public String getSourceIp() { return sourceIp; }
        public String getDestIp() { return destIp; }
        public String getProtocol() { return protocol; }
        public boolean isWhitelisted() { return whitelisted; }
    }

    public static class DashCaseRow {
        private final String caseNumber, title, priority, status, openedAt, assignedTo;

        public DashCaseRow(String caseNumber, String title, String priority,
                            String status, String openedAt, String assignedTo) {
            this.caseNumber = caseNumber;
            this.title = title;
            this.priority = priority;
            this.status = status;
            this.openedAt = openedAt;
            this.assignedTo = assignedTo;
        }

        public String getCaseNumber() { return caseNumber; }
        public String getTitle() { return title; }
        public String getPriority() { return priority; }
        public String getStatus() { return status; }
        public String getOpenedAt() { return openedAt; }
        public String getAssignedTo() { return assignedTo; }
    }
    private void applyThreatActors(JsonNode actorsNode) {
        List<ThreatActorRow> active = new ArrayList<>();
        List<ThreatActorRow> whitelisted = new ArrayList<>();
        for (JsonNode n : actorsNode) {
            ThreatActorRow row = new ThreatActorRow(
                n.path("rank").asInt(0),
                n.path("ip").asText(""),
                n.path("threatScore").asInt(0),
                (int) n.path("totalAlerts").asLong(0),
                n.path("topThreatType").asText(""),
                formatBucketTime(n.path("lastSeen").asText("")),
                n.path("whitelisted").asBoolean(false)
            );
            (row.isWhitelisted() ? whitelisted : active).add(row);
        }
        activeActors.setAll(active);
        whitelistedActors.setAll(whitelisted);
        tabActorsActive.setText("Active (" + active.size() + ")");
        tabActorsWhitelisted.setText("Whitelisted (" + whitelisted.size() + ")");
    }
    private VBox buildAlertsAndHealthRow() {
        VBox actorsBox = panelContainer("Threat Actors");
        TableView<ThreatActorRow> activeTable =
                buildThreatActorsTable(activeActors, "No threat actors yet.");
        TableView<ThreatActorRow> whitelistedTable =
                buildThreatActorsTable(whitelistedActors, "No whitelisted threat actors.");
        activeTable.setPrefHeight(320); // taller now that it owns the full row
        whitelistedTable.setPrefHeight(320);
        tabActorsActive      = new Tab("Active (0)", activeTable);
        tabActorsWhitelisted = new Tab("Whitelisted (0)", whitelistedTable);
        actorsBox.getChildren().add(splitTabPane(tabActorsActive, tabActorsWhitelisted));
        return actorsBox;
    }

    /** Active/Whitelisted TabPane shared by Top Alerts and Threat Actors. */
    private TabPane splitTabPane(Tab active, Tab whitelisted) {
        active.setClosable(false);
        whitelisted.setClosable(false);
        TabPane pane = new TabPane(active, whitelisted);
        pane.setStyle("-fx-background-color: " + BG_CARD + ";");
        pane.getSelectionModel().select(active);
        return pane;
    }

    /** Hyperlink-style cell for clickable Source IP columns (drill-down). */
    private <R> TableCell<R, String> ipLinkCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String ip, boolean empty) {
                super.updateItem(ip, empty);
                if (empty || ip == null) { setText(null); setStyle(""); setOnMouseClicked(null); return; }
                setText(ip);
                setStyle("-fx-text-fill: " + Theme.ACCENT + "; -fx-font-weight:bold; -fx-cursor:hand; -fx-underline:true;");
                setOnMouseClicked(e -> { if (onIpClick != null) onIpClick.accept(ip); });
            }
        };
    }

    private TableView<ThreatActorRow> buildThreatActorsTable(
            ObservableList<ThreatActorRow> items, String placeholder) {
        TableView<ThreatActorRow> tv = new TableView<>();
        tv.setStyle("-fx-background-color: " + BG_CARD + ";");
        tv.setItems(items);
        tv.setPlaceholder(new Label(placeholder));

        TableColumn<ThreatActorRow, Number> colRank = new TableColumn<>("#");
        colRank.setCellValueFactory(c -> new javafx.beans.property.SimpleIntegerProperty(c.getValue().getRank()));

        TableColumn<ThreatActorRow, String> colIp = new TableColumn<>("IP");
        colIp.setCellValueFactory(new PropertyValueFactory<>("ip"));
        colIp.setCellFactory(col -> ipLinkCell());

        TableColumn<ThreatActorRow, ThreatActorRow> colScore = new TableColumn<>("Threat Score");
        colScore.setCellValueFactory(c -> new javafx.beans.property.SimpleObjectProperty<>(c.getValue()));
        colScore.setCellFactory(c -> threatScoreCell());

        TableColumn<ThreatActorRow, Number> colAlerts = new TableColumn<>("Alerts");
        colAlerts.setCellValueFactory(c -> new javafx.beans.property.SimpleIntegerProperty(c.getValue().getTotalAlerts()));

        TableColumn<ThreatActorRow, String> colTopThreat = new TableColumn<>("Top Threat");
        colTopThreat.setCellValueFactory(new PropertyValueFactory<>("topThreatType"));

        TableColumn<ThreatActorRow, String> colLastSeen = new TableColumn<>("Last Seen");
        colLastSeen.setCellValueFactory(new PropertyValueFactory<>("lastSeen"));

        // Top Threat is the free-text column; colIp keeps its hyperlink cell
        // factory and colScore its bar renderer — width hints only for those.
        TableLayout.constrain(tv);
        TableLayout.bounded(colRank,       30,  34,  44);
        TableLayout.bounded(colIp,        100, 120, 150);
        TableLayout.bounded(colScore,     120, 150, 180);
        TableLayout.bounded(colAlerts,     55,  70,  95);
        TableLayout.flex   (colTopThreat, 120, 160);
        TableLayout.bounded(colLastSeen,  100, 120, 160);
        TableLayout.tooltipCells(colTopThreat);

        tv.getColumns().addAll(List.of(colRank, colIp, colScore, colAlerts, colTopThreat, colLastSeen));
        return tv;
    }

    private TableCell<ThreatActorRow, ThreatActorRow> threatScoreCell() {
        return new TableCell<>() {
            @Override
            protected void updateItem(ThreatActorRow row, boolean empty) {
                super.updateItem(row, empty);
                if (empty || row == null) { setGraphic(null); return; }

                int score = row.getThreatScore();
                String color = score >= 75 ? COLOR_CRITICAL
                              : score >= 50 ? COLOR_HIGH
                              : score >= 25 ? COLOR_MEDIUM
                              : COLOR_LOW;

                Region track = new Region();
                track.setPrefSize(80, 8);
                track.setStyle("-fx-background-color: " + BORDER + "; -fx-background-radius: 4;");

                Region fill = new Region();
                fill.setPrefSize(80 * (score / 100.0), 8);
                fill.setStyle("-fx-background-color: " + color + "; -fx-background-radius: 4;");

                javafx.scene.layout.StackPane bar = new javafx.scene.layout.StackPane(track, fill);
                bar.setAlignment(Pos.CENTER_LEFT);

                Label val = new Label(String.valueOf(score));
                val.setStyle("-fx-text-fill: " + TEXT_MAIN + "; -fx-font-size: 11; -fx-font-weight: bold;");

                HBox box = new HBox(8, bar, val);
                box.setAlignment(Pos.CENTER_LEFT);
                setGraphic(box);
            }
        };
    }
}