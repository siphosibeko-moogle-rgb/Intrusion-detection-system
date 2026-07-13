package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;

import com.ids.desktop.model.*;
import com.ids.desktop.service.BackendClient;
import com.ids.desktop.service.LiveFeedClient;
import com.ids.desktop.service.HealthPoller;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;

import java.net.URL;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.*;
import javafx.scene.layout.StackPane;

public class MainController implements Initializable {

    private static final String BACKEND_URL      = "http://localhost:8080";
    private static final DateTimeFormatter FMT   =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    // ── FXML BINDINGS ─────────────────────────────────────────────────────────
    
    @FXML private Label  lblUser;
    @FXML private StackPane healthHost;
    

    // Alerts tab
    @FXML private TextField        tfFilterIp, tfFilterMac, tfFilterType;
    @FXML private ComboBox<String> cbFilterSeverity, cbFilterProtocol;
    @FXML private TableView<AlertItem>            alertTable;
    @FXML private TableColumn<AlertItem, String>  colTimestamp, colSeverity, colThreatType;
    @FXML private TableColumn<AlertItem, String>  colSourceIp, colSourceMac, colDestIp;
    @FXML private TableColumn<AlertItem, String>  colProtocol, colRequestType, colDetails;
    @FXML private TableColumn<AlertItem, Integer> colPackets;
    @FXML private TableColumn<AlertItem, Integer> colOccurrences;

    @FXML private javafx.scene.layout.StackPane dashboardHost;

  
    // My whitelist
    @FXML private TableView<MyWhitelistItem>            myWhitelistTable;
    @FXML private TableColumn<MyWhitelistItem, String>  colMyWlIp, colMyWlMac, colMyWlLabel, colMyWlAddedAt;
    @FXML private TextField tfNewMyWlIp, tfNewMyWlMac, tfNewMyWlLabel, tfFilterWlIp;

    // Flagged IPs
    @FXML private TableView<FlaggedIpItem>            flaggedIpTable;
    @FXML private TableColumn<FlaggedIpItem, Boolean> colFlagSel;
    @FXML private TableColumn<FlaggedIpItem, String>  colFlagIp, colFlagMac, colFlagThreat, colFlagProto, colFlagSeen;
    @FXML private TableColumn<FlaggedIpItem, Integer> colFlagHits;
    @FXML private CheckBox cbSelectAllFlagged;
    @FXML private Label    lblFlaggedCount;

    // Cases
    @FXML private TableView<CaseItem>            casesTable;
    @FXML private TableColumn<CaseItem, String>  colCaseNum, colCaseTitle, colCaseStatus;
    @FXML private TableColumn<CaseItem, String>  colCaseSeverity, colCaseSuspectIp, colCaseSuspectMac;
    @FXML private TableColumn<CaseItem, String>  colCaseThreatType, colCaseAssignedTo, colCaseOpenedAt;
    @FXML private TextField        tfCaseFilterStatus, tfCaseFilterIp;
    @FXML private TextField        tfNewCaseTitle, tfNewCaseSuspectIp, tfNewCaseSuspectMac;
    @FXML private ComboBox<String> cbNewCaseSeverity;
    @FXML private Label            lblCaseStatus;
    @FXML private TabPane          tabPane;

    // Settings / login
    @FXML private TextField     tfBackendUrl;
    @FXML private TextField     tfUsername;
    @FXML private PasswordField pfPassword;
    @FXML private Label         lblLoginStatus;
    @FXML private void onOpenAlertGroups() { openAlertGroups(); }

    // ── STATE ─────────────────────────────────────────────────────────────────
    // MainController is a coordinator: it owns login/lifecycle, the live feed,
    // and side-panel navigation. Everything table-specific lives in dedicated
    // managers (AlertTableManager, WhitelistPanelManager, CaseBoardManager,
    // DashboardPanel) that receive the FXML-injected controls via bind/setup.
    private BackendClient        backend;
    private LiveFeedClient       wsFeed;
    private DataLoader           dataLoader;
    private AlertTableManager    alertManager;
    private WhitelistPanelManager whitelistManager;
    private CaseBoardManager     caseBoard;
    private IpInvestigationPanel investigationPanel;
    private CaseDetailPanel   caseDetailPanel;
    private AlertGroupsPanel  alertGroupsPanel;
    private StackPane         sidePanelStack;
    private DashboardPanel dashboardPanel;
    private HeaderHealthWidget healthWidget;
    private HealthPoller healthPoller;

    private final ObservableList<AlertItem>        allAlerts      = FXCollections.observableArrayList();

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ids-poll-thread");
                t.setDaemon(true);
                return t;
            });

    // ── INIT ──────────────────────────────────────────────────────────────────

    @Override
    public void initialize(URL url, ResourceBundle rb) {

        backend = new BackendClient(BACKEND_URL);
        dataLoader = new DataLoader(backend);
        
        dashboardPanel = new DashboardPanel(backend, this::openInvestigation);
        dashboardHost.getChildren().add(dashboardPanel);

        alertManager = new AlertTableManager(
                alertTable,
                tfFilterIp,
                tfFilterMac,
                tfFilterType,
                cbFilterSeverity,
                cbFilterProtocol,
                allAlerts);

        alertManager.setup(
                colTimestamp,
                colSeverity,
                colThreatType,
                colSourceIp,
                colSourceMac,
                colDestIp,
                colProtocol,
                colRequestType,
                colPackets,
                colDetails,
                colOccurrences);

        whitelistManager = new WhitelistPanelManager(
                () -> dataLoader, () -> backend, this::isReady,
                msg -> lblLoginStatus.setText(msg));
        whitelistManager.bindMyWhitelist(myWhitelistTable,
                colMyWlIp, colMyWlMac, colMyWlLabel, colMyWlAddedAt,
                tfNewMyWlIp, tfNewMyWlMac, tfNewMyWlLabel, tfFilterWlIp);
        whitelistManager.bindFlaggedIps(flaggedIpTable,
                colFlagSel, colFlagIp, colFlagMac, colFlagThreat,
                colFlagProto, colFlagHits, colFlagSeen,
                cbSelectAllFlagged, lblFlaggedCount);

        caseBoard = new CaseBoardManager(
                () -> dataLoader, () -> backend, this::isReady,
                this::openCaseDetail);
        caseBoard.bind(casesTable,
                colCaseNum, colCaseTitle, colCaseStatus, colCaseSeverity,
                colCaseSuspectIp, colCaseSuspectMac, colCaseThreatType,
                colCaseAssignedTo, colCaseOpenedAt,
                tfCaseFilterStatus, tfCaseFilterIp,
                tfNewCaseTitle, tfNewCaseSuspectIp, tfNewCaseSuspectMac,
                cbNewCaseSeverity, lblCaseStatus);

        cbFilterSeverity.setItems(FXCollections.observableArrayList(
                "", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"));

        cbFilterProtocol.setItems(FXCollections.observableArrayList(
                "", "TCP", "UDP", "ICMP", "ARP"));

        cbNewCaseSeverity.setItems(FXCollections.observableArrayList(
                "CRITICAL", "HIGH", "MEDIUM", "LOW"));
        cbNewCaseSeverity.setValue("HIGH");

        healthWidget = new HeaderHealthWidget();
        healthHost.getChildren().add(healthWidget);

        // NEW: Replaces setupInvestigationPanel() and setupCaseDetailPanel()
        setupSidePanels();
    }

    // ── LOGIN ─────────────────────────────────────────────────────────────────

    @FXML
    private void onLogin() {
        String user = tfUsername.getText().trim();
        String pass = pfPassword.getText();

        if (user.isEmpty() || pass.isEmpty()) {
            lblLoginStatus.setText("Username and password required");
            return;
        }
        lblLoginStatus.setText("Connecting...");
        backend    = new BackendClient(backendUrl());
        dataLoader = new DataLoader(backend);

        dataLoader.login(user, pass,
                () -> {
                    lblLoginStatus.setText("Logged in as " + user);
                    lblUser.setText(user);
                    
                    investigationPanel.setBackend(backend);
                    caseDetailPanel.setBackend(backend);
                    dashboardPanel.setBackend(backend);
                    dashboardPanel.start();
                    healthPoller = new HealthPoller(backend);
                    healthPoller.addListener(healthWidget::update);
                    healthPoller.start();
                    loadAllData();
                    startLiveFeed();
                    startPolling();
                },
                msg -> {
                    lblLoginStatus.setText("Connection failed: " + msg);
                    
                });
    }

    // ── DATA LOADING ──────────────────────────────────────────────────────────

    private void loadAllData() {
        dataLoader.loadAlertSummaries(
                this::onAlertsLoaded,
                this::updateStats,
                msg -> handleSessionError("Alert load failed", msg));
        whitelistManager.reload();
        caseBoard.reload();
    }

    private void onAlertsLoaded(List<AlertItem> items) {
        // Cap to 2000 rows so the JavaFX list never becomes a memory hog.
        // The backend already returns them newest-first, so we drop the tail.
        List<AlertItem> capped = items.size() > 2000 ? items.subList(0, 2000) : items;
        allAlerts.setAll(capped);       // ← setAll() wipes first, then adds — no stale rows
        alertManager.rebuildIndex();    // rebuild the (sourceIp,threatType) dedup index
        
    }

    // ── LIVE FEED (WEBSOCKET) ─────────────────────────────────────────────────

    private void startLiveFeed() {
        try {
            String wsUrl = backendUrl()
                    .replace("http://",  "ws://")
                    .replace("https://", "wss://")
                    + "/ws/websocket";

            // FIX: Correct 5-param constructor.
            //   param 1 - wsUrl          : the WebSocket endpoint
            //   param 2 - onAlert        : this::onAlertReceived handles BOTH new alerts
            //                              AND deletion events routed from /topic/alerts/deleted
            //   param 3 - onConnect      : null — no action needed on connect
            //   param 4 - onDisconnect   : null — no action needed on disconnect
            //   param 5 - onCleared      : null — we use the local handleClearAlerts() instead
            wsFeed = new LiveFeedClient(
                    wsUrl,
                    this::onAlertReceived,
                    null,
                    null,
                    null
            );
            wsFeed.connect();
        } catch (Exception e) {
            System.err.println("[Desktop] WebSocket connect failed: " + e.getMessage());
        }
    }

    private void onAlertReceived(JsonNode node) {
        // ── DELETION EVENT ROUTING ─────────────────────────────────────────────
        // Backend broadcasts {"id": 42} on /topic/alerts/deleted when a row is
        // deleted via DELETE /api/alerts/summaries/{id}.
        // LiveFeedClient subscribes to /topic/alerts/deleted and routes the message
        // here via the same onAlert callback (it falls through the onCleared check).
        //
        // We detect it: deletion payload has "id" but NO "threatType".
        // A full AlertSummary always has "threatType" — a deletion payload never does.
        if (node.has("id") && !node.has("threatType")) {
            long id = node.path("id").asLong(0);
            if (id > 0) {
                // Already on WS I/O thread — must dispatch to JavaFX thread for UI
                Platform.runLater(() -> {
                    alertManager.removeById(id);
                    
                    updateStats(null); // recalculate counters from the now-shorter list
                });
                return;
            }
        }

        // ── NEW / UPDATED ALERT SUMMARY ────────────────────────────────────────
        String ts        = fmtInstantSafe(node.path("lastSeen").asText(""));
        String firstSeen = fmtInstantSafe(node.path("firstSeen").asText(""));
        String severity  = node.path("severity").asText();
        String type      = node.path("threatType").asText();
        String srcIp     = node.path("sourceIp").asText();

        Platform.runLater(() -> {
            // Build AlertItem from the AlertSummary WebSocket payload
            AlertItem item = new AlertItem(
                    ts, severity, type, srcIp,
                    node.path("sourceMac").asText(),
                    node.path("destIp").asText(),
                    node.path("protocol").asText(),
                    node.path("requestType").asText(),
                    node.path("packetCount").asInt(0),
                    node.path("details").asText());

            item.setOccurrences(node.path("occurrenceCount").asInt(1));
            item.setFirstSeen(firstSeen);
            item.setId(node.path("id").asLong(0)); // FIX: map id so removeById() works

            alertManager.upsertAlert(item); // deduplicates by (sourceIp, threatType)

           
        });
    }

    // ── POLLING ───────────────────────────────────────────────────────────────

    private void startPolling() {
        scheduler.scheduleAtFixedRate(() -> {
            if (isReady()) dataLoader.loadAlertSummaries(
                    this::onAlertsLoaded,
                    this::updateStats,
                    msg -> handleSessionError("Poll failed", msg));
        }, 30, 30, TimeUnit.SECONDS);
    }

    // ── STATS ─────────────────────────────────────────────────────────────────

    private void updateStats(JsonNode stats) {
        // Severity counts are now shown only on the Dashboard tab's stat cards
        // (DashboardPanel, driven by /api/dashboard/summary). The header no
        // longer displays raw counts — this method is kept as a no-op landing
        // point for the 3 existing call sites rather than touching all three.
    }

    // ── FXML ACTIONS ──────────────────────────────────────────────────────────

    @FXML private void onClearFilters() { alertManager.clearFilters(); }
    @FXML private void onRefresh()      { if (isReady()) loadAllData(); }

    /**
     * Dismisses the selected alert from both the dashboard AND the database.
     *
     * Flow:
     *  1. Desktop calls DELETE /api/alerts/summaries/{id}
     *  2. Backend deletes the alert_summary row from PostgreSQL
     *  3. Backend broadcasts {"id": X} on /topic/alerts/deleted via WebSocket
     *  4. All connected desktop clients receive the event → onAlertReceived()
     *     detects the deletion payload → alertManager.removeById(id) removes the row
     *
     * The raw `alerts` table (forensic history) is NOT touched.
     * If the engine re-detects the same threat, a new row will appear — that is
     * correct IDS behaviour. Use the whitelist to suppress known-safe sources.
     *
     * Wire this in your FXML:  onAction="#onDismissAlert"
     */
    @FXML
    private void onDismissAlert() {
        AlertItem selected = alertTable.getSelectionModel().getSelectedItem();
        if (selected == null) return;
        if (!isReady()) { lblLoginStatus.setText("Not connected"); return; }
        if (selected.getId() <= 0) {
            lblLoginStatus.setText("Cannot dismiss: no database ID — press Refresh first.");
            return;
        }
        dataLoader.submit("ids-dismiss-alert",
                () -> backend.deleteAlertSummary(selected.getId()),
                () -> lblLoginStatus.setText("Alert dismissed from database."),
                err -> lblLoginStatus.setText("Dismiss failed: " + err));}
    /**
     * Clears the dashboard TABLE VIEW only. The database is NOT touched.
     *
     * The engine will re-populate within its cooldown (3s/threat) if
     * threats are still active — that is correct IDS behaviour.
     *
     * Use this for demo resets or screen decluttering only.
     * Wire in your FXML:  onAction="#handleClearAlerts"
     */
    @FXML
    private void handleClearAlerts() {
        allAlerts.clear();            // clears Alerts tab   — DB untouched
                    // clears Attackers tab — DB untouched
        alertManager.rebuildIndex();  // reset dedup index so next upsertAlert() works cleanly
        lblLoginStatus.setText("View cleared. Data preserved in database.");
    }

    // ── WHITELIST ACTIONS — thin delegations to WhitelistPanelManager ─────────

    @FXML private void onAddMyWhitelist()       { whitelistManager.addMyEntry(); }
    @FXML private void onDeleteMyWhitelist()    { whitelistManager.deleteSelectedMyEntry(); }
    @FXML private void onSelectAllFlagged()     { whitelistManager.toggleSelectAllFlagged(); }
    @FXML private void onAcceptFlagged()        { whitelistManager.acceptSelectedFlagged(); }
    @FXML private void onRemoveFlagged()        { whitelistManager.clearFlaggedSelection(); }

    // ── CASE ACTIONS — thin delegations to CaseBoardManager ──────────────────

    @FXML private void onCreateCase() { caseBoard.createCase(); }
    @FXML private void onCloseCase()  { caseBoard.closeSelectedCase(); }

    // ── HELPERS ───────────────────────────────────────────────────────────────

    private boolean isReady() { return backend != null && backend.isLoggedIn(); }

    /**
     * Backend URL from the Settings tab, falling back to the default.
     * FIX: tfBackendUrl was FXML-bound but never read — typing a custom
     * backend address in Settings had no effect; login always went to
     * localhost:8080.
     */
    private String backendUrl() {
        String url = tfBackendUrl != null ? tfBackendUrl.getText() : null;
        if (url == null || url.isBlank()) return BACKEND_URL;
        url = url.trim();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    

    private String fmtInstantSafe(String raw) {
        if (raw == null || raw.isBlank()) return FMT.format(Instant.now());
        try   { return FMT.format(Instant.parse(raw)); }
        catch (Exception e) { return raw; }
    }

    private void handleSessionError(String prefix, String msg) {
        lblLoginStatus.setText(prefix + ": " + msg);
        if (msg != null && msg.contains("Session expired"))
            backend.invalidateSession();
    }

    private javafx.scene.layout.Pane findRootPane() {
        javafx.scene.Node node = alertTable;
        while (node.getParent() != null) {
            if (node.getParent() instanceof HBox || node.getParent() instanceof BorderPane)
                return (javafx.scene.layout.Pane) node.getParent();
            node = node.getParent();
        }
        return (javafx.scene.layout.Pane) node;
    }

    private void wireIpColumnClick() {
        colSourceIp.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String ip, boolean empty) {
                super.updateItem(ip, empty);
                if (empty || ip == null) { setText(null); setStyle(""); setOnMouseClicked(null); return; }
                setText(ip);
                setStyle("-fx-text-fill:#00d4ff; -fx-font-weight:bold; -fx-cursor:hand; -fx-underline:true;");
                setOnMouseClicked(e -> openInvestigation(ip));
            }
        });
        
    }

    

   

    // ── SHUTDOWN ──────────────────────────────────────────────────────────────

    public void shutdown() {
        scheduler.shutdownNow();
        if (dashboardPanel != null) dashboardPanel.stop();
        try { scheduler.awaitTermination(2, TimeUnit.SECONDS); }
        catch (InterruptedException ignored) {}
        if (wsFeed != null) try { wsFeed.close(); } catch (Exception ignored) {}
        if (healthPoller != null) healthPoller.stop();
    }
    // ── INVESTIGATION PANEL ───────────────────────────────────────────────────

 // ── SIDE PANELS (Investigation + Case Detail) ──────────────────────────
 // Both panels used to each call bp.setRight(...) independently. A BorderPane
 // only holds ONE node per position, so the second setRight() call silently
 // evicted the first panel from the scene graph — it kept working internally
 // (visible/managed toggles, HTTP calls, label updates all succeeded) but had
 // no parent, so it never rendered. Fix: one StackPane holds both panels and
 // claims bp.right exactly once. Visibility toggling still gives you the same
 // "only one shows at a time" behaviour, but neither node is ever detached.
    private void setupSidePanels() {
        investigationPanel = new IpInvestigationPanel(backend, this::closeInvestigationPanel);
        investigationPanel.setVisible(false);
        investigationPanel.setManaged(false);

        caseDetailPanel = new CaseDetailPanel(backend, this::closeCaseDetailPanel);
        caseDetailPanel.setVisible(false);
        caseDetailPanel.setManaged(false);

        alertGroupsPanel = new AlertGroupsPanel(backend, this::closeAlertGroupsPanel, this::openCaseDetail);
        alertGroupsPanel.setVisible(false);
        alertGroupsPanel.setManaged(false);

        sidePanelStack = new StackPane(investigationPanel, caseDetailPanel, alertGroupsPanel);

        Platform.runLater(() -> {
            javafx.scene.layout.Pane root = findRootPane();
            if (root instanceof HBox hbox) {
                hbox.getChildren().add(sidePanelStack);
                HBox.setHgrow(sidePanelStack, Priority.NEVER);
            } else if (root instanceof BorderPane bp) {
                bp.setRight(sidePanelStack);
            }
        });

        wireIpColumnClick();
    }

    /** Shows exactly one side panel and hides the other two. */
    private void showOnlySidePanel(javafx.scene.Node toShow) {
        for (javafx.scene.Node n : sidePanelStack.getChildren()) {
            boolean show = (n == toShow);
            n.setVisible(show);
            n.setManaged(show);
        }
    }

    private void openInvestigation(String ip) {
        if (!isReady() || ip == null || ip.isBlank()) return;
        showOnlySidePanel(investigationPanel);
        investigationPanel.investigate(ip);
    }

    private void openCaseDetail(long caseId, String caseNumber) {
        if (!isReady()) return;
        caseDetailPanel.setBackend(backend);
        showOnlySidePanel(caseDetailPanel);
        caseDetailPanel.openCase(caseId, caseNumber);
    }

    private void openAlertGroups() {
        if (!isReady()) return;
        alertGroupsPanel.setBackend(backend);
        showOnlySidePanel(alertGroupsPanel);
        alertGroupsPanel.open();
    }

    private void closeInvestigationPanel() {
        investigationPanel.setVisible(false);
        investigationPanel.setManaged(false);
    }

    private void closeCaseDetailPanel() {
        caseDetailPanel.setVisible(false);
        caseDetailPanel.setManaged(false);
    }

    private void closeAlertGroupsPanel() {
        alertGroupsPanel.setVisible(false);
        alertGroupsPanel.setManaged(false);
    }
}