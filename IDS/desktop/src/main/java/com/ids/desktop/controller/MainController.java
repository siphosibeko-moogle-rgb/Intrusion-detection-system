package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.ids.desktop.model.*;
import com.ids.desktop.service.BackendClient;
import com.ids.desktop.service.LiveFeedClient;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

import java.net.URL;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.ResourceBundle;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import javafx.scene.layout.StackPane;

public class MainController implements Initializable {

    private static final String BACKEND_URL      = "http://localhost:8080";
    private static final int    MAX_LIVE_ENTRIES = 500;
    private static final DateTimeFormatter FMT   =
            DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    // ── FXML BINDINGS ─────────────────────────────────────────────────────────
    @FXML private Label  lblStatus;
    @FXML private Circle dotLive;
    @FXML private Label  lblUser;
    @FXML private Label  lblTotal, lblCritical, lblHigh, lblMedium;

    // Alerts tab
    @FXML private TextField        tfFilterIp, tfFilterMac, tfFilterType;
    @FXML private ComboBox<String> cbFilterSeverity, cbFilterProtocol;
    @FXML private TableView<AlertItem>            alertTable;
    @FXML private TableColumn<AlertItem, String>  colTimestamp, colSeverity, colThreatType;
    @FXML private TableColumn<AlertItem, String>  colSourceIp, colSourceMac, colDestIp;
    @FXML private TableColumn<AlertItem, String>  colProtocol, colRequestType, colDetails;
    @FXML private TableColumn<AlertItem, Integer> colPackets;
    @FXML private TableColumn<AlertItem, Integer> colOccurrences;

    // Live feed
    @FXML private ListView<String> liveFeedList;

    // Attackers tab
    @FXML private TableView<AlertItem>            attackerTable;
    @FXML private TableColumn<AlertItem, String>  colAtkIp, colAtkMac;
    @FXML private TableColumn<AlertItem, Integer> colAtkCount;
    @FXML private TextField                       tfFilterAtkIp;

    // My whitelist
    @FXML private TableView<MyWhitelistItem>            myWhitelistTable;
    @FXML private TableColumn<MyWhitelistItem, String>  colMyWlIp, colMyWlMac, colMyWlLabel, colMyWlAddedAt;
    @FXML private TextField tfNewMyWlIp, tfNewMyWlMac, tfNewMyWlLabel, tfFilterWlIp;

    // Org whitelist – accepted
    @FXML private TableView<OrgWhitelistItem>            orgAcceptedTable;
    @FXML private TableColumn<OrgWhitelistItem, String>  colOrgAccIp, colOrgAccName, colOrgAccAsn, colOrgAccCountry, colOrgAccSeen;
    @FXML private TableColumn<OrgWhitelistItem, Integer> colOrgAccHits;

    // Org whitelist – pending
    @FXML private TableView<OrgWhitelistItem>            orgPendingTable;
    @FXML private TableColumn<OrgWhitelistItem, Boolean> colOrgPendSel;
    @FXML private TableColumn<OrgWhitelistItem, String>  colOrgPendIp, colOrgPendMac, colOrgPendName, colOrgPendAsn, colOrgPendCountry, colOrgPendSeen;
    @FXML private TableColumn<OrgWhitelistItem, Integer> colOrgPendHits;
    @FXML private CheckBox cbSelectAllPendingOrg;
    @FXML private Label    lblPendingOrgCount;

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

    // ── STATE ─────────────────────────────────────────────────────────────────
    private BackendClient        backend;
    private LiveFeedClient       wsFeed;
    private DataLoader           dataLoader;
    private AlertTableManager    alertManager;
    private IpInvestigationPanel investigationPanel;
    private CaseDetailPanel caseDetailPanel;
    private SplitPane            mainSplitPane;

    private final ObservableList<AlertItem>        allAlerts      = FXCollections.observableArrayList();
    private final ObservableList<AlertItem>        attackers      = FXCollections.observableArrayList();
    private final ObservableList<String>           liveEntries    = FXCollections.observableArrayList();
    private final ObservableList<CaseItem>         caseEntries    = FXCollections.observableArrayList();
    private final ObservableList<MyWhitelistItem>  myWlEntries    = FXCollections.observableArrayList();
    private final ObservableList<OrgWhitelistItem> orgAcceptedRaw = FXCollections.observableArrayList();
    private final ObservableList<OrgWhitelistItem> orgPendingRaw  = FXCollections.observableArrayList();
    private final ObservableList<FlaggedIpItem>    flaggedIps     = FXCollections.observableArrayList();

    private FilteredList<MyWhitelistItem>  filteredMyWl;
    private FilteredList<OrgWhitelistItem> orgAccepted, orgPending;
    private FilteredList<CaseItem>         filteredCases;

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "ids-poll-thread");
                t.setDaemon(true);
                return t;
            });

    // ── INIT ──────────────────────────────────────────────────────────────────

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        backend    = new BackendClient(BACKEND_URL);
        dataLoader = new DataLoader(backend);

        alertManager = new AlertTableManager(
                alertTable, attackerTable,
                tfFilterIp, tfFilterMac, tfFilterType,
                cbFilterSeverity, cbFilterProtocol,
                tfFilterAtkIp, allAlerts, attackers);

        alertManager.setup(
                colTimestamp, colSeverity, colThreatType,
                colSourceIp, colSourceMac, colDestIp,
                colProtocol, colRequestType, colPackets, colDetails, colOccurrences,
                colAtkIp, colAtkMac, colAtkCount);

        setupWhitelistTables();
        setupCasesTable();

        liveFeedList.setItems(liveEntries);

        cbFilterSeverity.setItems(FXCollections.observableArrayList("", "CRITICAL", "HIGH", "MEDIUM", "LOW"));
        cbFilterProtocol.setItems(FXCollections.observableArrayList("", "TCP", "UDP", "ICMP", "ARP"));
        cbNewCaseSeverity.setItems(FXCollections.observableArrayList("CRITICAL", "HIGH", "MEDIUM", "LOW"));
        cbNewCaseSeverity.setValue("HIGH");

        tfFilterWlIp.textProperty().addListener((o, ov, nv)       -> applyWlFilter());
        tfCaseFilterStatus.textProperty().addListener((o, ov, nv) -> applyCaseFilter());
        tfCaseFilterIp.textProperty().addListener((o, ov, nv)     -> applyCaseFilter());

        setStatus("Not connected", false);
        setupSidePanels();
        wireCaseTableDoubleClick();
    }

    // ── TABLE SETUP ───────────────────────────────────────────────────────────

    private void setupWhitelistTables() {
        colMyWlIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colMyWlMac    .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colMyWlLabel  .setCellValueFactory(new PropertyValueFactory<>("label"));
        colMyWlAddedAt.setCellValueFactory(new PropertyValueFactory<>("addedAt"));
        colMyWlIp.setCellFactory(col -> cyanCell());
        filteredMyWl = new FilteredList<>(myWlEntries, p -> true);
        myWhitelistTable.setItems(filteredMyWl);
        myWhitelistTable.setPlaceholder(new Label("No trusted devices."));

        colFlagSel   .setCellValueFactory(new PropertyValueFactory<>("selected"));
        colFlagSel   .setCellFactory(col -> checkBoxCell(FlaggedIpItem.class));
        colFlagIp    .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colFlagMac   .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colFlagThreat.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colFlagProto .setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colFlagHits  .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colFlagSeen  .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colFlagThreat.setCellFactory(col -> amberCell());
        colFlagHits  .setCellFactory(col -> hitCountCell());
        flaggedIpTable.setItems(flaggedIps);
        flaggedIpTable.setPlaceholder(new Label("No flagged IPs."));

        colOrgAccIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colOrgAccName   .setCellValueFactory(new PropertyValueFactory<>("orgName"));
        colOrgAccAsn    .setCellValueFactory(new PropertyValueFactory<>("asn"));
        colOrgAccCountry.setCellValueFactory(new PropertyValueFactory<>("country"));
        colOrgAccHits   .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colOrgAccSeen   .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colOrgAccIp.setCellFactory(col -> cyanCell());
        orgAccepted = new FilteredList<>(orgAcceptedRaw, p -> true);
        orgAcceptedTable.setItems(orgAccepted);

        colOrgPendSel    .setCellValueFactory(new PropertyValueFactory<>("selected"));
        colOrgPendSel    .setCellFactory(col -> checkBoxCell(OrgWhitelistItem.class));
        colOrgPendIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colOrgPendMac    .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colOrgPendName   .setCellValueFactory(new PropertyValueFactory<>("orgName"));
        colOrgPendAsn    .setCellValueFactory(new PropertyValueFactory<>("asn"));
        colOrgPendCountry.setCellValueFactory(new PropertyValueFactory<>("country"));
        colOrgPendHits   .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colOrgPendSeen   .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colOrgPendHits.setCellFactory(col -> hitCountCell());
        orgPending = new FilteredList<>(orgPendingRaw, p -> true);
        orgPendingTable.setItems(orgPending);
        orgPendingTable.setPlaceholder(new Label("No pending organizations."));
    }

    private void setupCasesTable() {
        colCaseNum       .setCellValueFactory(new PropertyValueFactory<>("caseNumber"));
        colCaseTitle     .setCellValueFactory(new PropertyValueFactory<>("title"));
        colCaseStatus    .setCellValueFactory(new PropertyValueFactory<>("status"));
        colCaseSeverity  .setCellValueFactory(new PropertyValueFactory<>("severity"));
        colCaseSuspectIp .setCellValueFactory(new PropertyValueFactory<>("suspectIp"));
        colCaseSuspectMac.setCellValueFactory(new PropertyValueFactory<>("suspectMac"));
        colCaseThreatType.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colCaseAssignedTo.setCellValueFactory(new PropertyValueFactory<>("assignedTo"));
        colCaseOpenedAt  .setCellValueFactory(new PropertyValueFactory<>("openedAt"));

        colCaseStatus.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                if (empty || val == null) { setText(null); setStyle(""); return; }
                setText(val);
                setStyle(switch (val) {
                    case "OPEN"          -> "-fx-text-fill:#ef4444; -fx-font-weight:bold;";
                    case "INVESTIGATING" -> "-fx-text-fill:#f59e0b;";
                    case "CLOSED"        -> "-fx-text-fill:#22c55e;";
                    default              -> "";
                });
            }
        });

        filteredCases = new FilteredList<>(caseEntries, p -> true);
        casesTable.setItems(filteredCases);
        casesTable.setPlaceholder(new Label("No forensic cases opened yet."));
        wireCaseTableDoubleClick();
        ContextMenu menu = new ContextMenu();

        MenuItem open = new MenuItem("Open Investigation");

        open.setOnAction(e -> {

            CaseItem selected = casesTable.getSelectionModel().getSelectedItem();

            if (selected != null) {
                openCaseDetail(selected.getId(), selected.getCaseNumber());
            }
        });

        MenuItem close = new MenuItem("Close Case");

        close.setOnAction(e -> onCloseCase());

        menu.getItems().addAll(open, close);

        casesTable.setContextMenu(menu);
    }

    // ── FILTERS ───────────────────────────────────────────────────────────────

    private void applyWlFilter() {
        String f = tfFilterWlIp.getText().toLowerCase().trim();
        filteredMyWl.setPredicate(w ->
                f.isEmpty()
                || w.getIp().toLowerCase().contains(f)
                || (w.getMac()   != null && w.getMac().toLowerCase().contains(f))
                || (w.getLabel() != null && w.getLabel().toLowerCase().contains(f)));
        orgAccepted.setPredicate(o ->
                f.isEmpty()
                || o.getIp().toLowerCase().contains(f)
                || (o.getOrgName() != null && o.getOrgName().toLowerCase().contains(f)));
        orgPending.setPredicate(o ->
                f.isEmpty()
                || o.getIp().toLowerCase().contains(f)
                || (o.getOrgName() != null && o.getOrgName().toLowerCase().contains(f)));
    }

    private void applyCaseFilter() {
        String status = tfCaseFilterStatus.getText().toLowerCase().trim();
        String ip     = tfCaseFilterIp.getText().toLowerCase().trim();
        filteredCases.setPredicate(c -> {
            if (!status.isEmpty() && !c.getStatus().toLowerCase().contains(status)) return false;
            if (!ip.isEmpty()     && !c.getSuspectIp().toLowerCase().contains(ip))  return false;
            return true;
        });
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
        backend    = new BackendClient(BACKEND_URL);
        dataLoader = new DataLoader(backend);

        dataLoader.login(user, pass,
                () -> {
                    lblLoginStatus.setText("Logged in as " + user);
                    lblUser.setText(user);
                    setStatus("Connected", true);
                    investigationPanel.setBackend(backend);
                    caseDetailPanel.setBackend(backend);
                    loadAllData();
                    startLiveFeed();
                    startPolling();
                },
                msg -> {
                    lblLoginStatus.setText("Connection failed: " + msg);
                    setStatus("Not connected", false);
                });
    }

    // ── DATA LOADING ──────────────────────────────────────────────────────────

    private void loadAllData() {
        dataLoader.loadAlertSummaries(
                this::onAlertsLoaded,
                this::updateStats,
                msg -> handleSessionError("Alert load failed", msg));
        dataLoader.loadWhitelist(
                this::onWhitelistLoaded,
                msg -> System.err.println("[Desktop] Whitelist load error: " + msg));
        dataLoader.loadCases(
                caseEntries::setAll,
                msg -> System.err.println("[Desktop] Cases load error: " + msg));
    }

    private void onAlertsLoaded(List<AlertItem> items) {
        // Cap to 2000 rows so the JavaFX list never becomes a memory hog.
        // The backend already returns them newest-first, so we drop the tail.
        List<AlertItem> capped = items.size() > 2000 ? items.subList(0, 2000) : items;
        allAlerts.setAll(capped);       // ← setAll() wipes first, then adds — no stale rows
        alertManager.rebuildIndex();    // rebuild the (sourceIp,threatType) dedup index
        alertManager.rebuildAttackers();
    }

    // ── LIVE FEED (WEBSOCKET) ─────────────────────────────────────────────────

    private void startLiveFeed() {
        try {
            String wsUrl = BACKEND_URL
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
                    alertManager.rebuildAttackers();
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
            // Append to the live-feed strip
            liveEntries.add(0, String.format("[%s] %s %s from %s",
                    ts,
                    severity.isEmpty() ? "?" : severity,
                    type.isEmpty()     ? "?" : type,
                    srcIp.isEmpty()    ? "?" : srcIp));
            if (liveEntries.size() > MAX_LIVE_ENTRIES)
                liveEntries.remove(liveEntries.size() - 1);

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

            // Throttle attacker-table rebuild to at most once per 5 seconds
            long now = System.currentTimeMillis();
            if (now - alertManager.getLastAttackerRebuild() > 5_000)
                alertManager.rebuildAttackers();
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
        // Prefer live DB counts from the backend response.
        // Fall back to counting from the in-memory list when stats is null
        // (e.g. after a local removeById call).
        if (stats != null && stats.has("total")) {
            lblTotal   .setText(String.valueOf(stats.path("total")   .asInt()));
            lblCritical.setText(String.valueOf(stats.path("critical").asInt()));
            lblHigh    .setText(String.valueOf(stats.path("high")    .asInt()));
            lblMedium  .setText(String.valueOf(stats.path("medium")  .asInt()));
        } else {
            lblTotal   .setText(String.valueOf(allAlerts.size()));
            lblCritical.setText(String.valueOf(allAlerts.stream().filter(a -> "CRITICAL".equals(a.getSeverity())).count()));
            lblHigh    .setText(String.valueOf(allAlerts.stream().filter(a -> "HIGH"    .equals(a.getSeverity())).count()));
            lblMedium  .setText(String.valueOf(allAlerts.stream().filter(a -> "MEDIUM"  .equals(a.getSeverity())).count()));
        }
    }

    // ── FXML ACTIONS ──────────────────────────────────────────────────────────

    @FXML private void onClearFilters() { alertManager.clearFilters(); }
    @FXML private void onRefresh()      { if (isReady()) loadAllData(); }
    @FXML private void onClearFeed()    { liveEntries.clear(); }

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
        if (!isReady()) { setStatus("Not connected", false); return; }
        if (selected.getId() <= 0) {
            setStatus("Cannot dismiss: no database ID — press Refresh first.", false);
            return;
        }
        dataLoader.submit("ids-dismiss-alert",
                () -> backend.deleteAlertSummary(selected.getId()),
                // The WS broadcast handles removing the row — no manual removeById here.
                () -> setStatus("Alert dismissed from database.", false),
                err -> setStatus("Dismiss failed: " + err, true));
    }

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
        attackers.clear();            // clears Attackers tab — DB untouched
        alertManager.rebuildIndex();  // reset dedup index so next upsertAlert() works cleanly
        setStatus("View cleared. Data preserved in database.", false);
    }

    // ── WHITELIST ACTIONS ─────────────────────────────────────────────────────

    @FXML private void onAddMyWhitelist() {
        if (!isReady()) return;
        String ip = tfNewMyWlIp.getText().trim();
        if (ip.isEmpty()) return;
        dataLoader.submit("ids-add-wl",
                () -> backend.addMyWhitelistEntry(ip, tfNewMyWlMac.getText().trim(), tfNewMyWlLabel.getText().trim()),
                () -> {
                    tfNewMyWlIp.clear(); tfNewMyWlMac.clear(); tfNewMyWlLabel.clear();
                    dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {});
                },
                msg -> setStatus("Add failed: " + msg, true));
    }

    @FXML private void onDeleteMyWhitelist() {
        MyWhitelistItem sel = myWhitelistTable.getSelectionModel().getSelectedItem();
        if (sel == null || !isReady()) return;
        dataLoader.submit("ids-del-wl",
                () -> backend.deleteMyWhitelistEntry(sel.getId()),
                () -> dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}),
                msg -> setStatus("Delete failed: " + msg, true));
    }

    @FXML private void onSelectAllFlagged() {
        boolean v = cbSelectAllFlagged.isSelected();
        flaggedIps.forEach(i -> i.setSelected(v));
        flaggedIpTable.refresh();
    }

    @FXML private void onAcceptFlagged() {
        if (!isReady()) return;
        var selected = flaggedIps.stream().filter(FlaggedIpItem::isSelected).toList();
        if (selected.isEmpty()) return;
        dataLoader.submit("ids-accept-flagged",
                () -> { for (var i : selected)
                    backend.addMyWhitelistEntry(i.getIp(), i.getMac(), "Accepted from " + i.getThreatType()); },
                () -> { cbSelectAllFlagged.setSelected(false);
                    dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}); },
                msg -> setStatus("Accept failed: " + msg, true));
    }

    @FXML private void onRemoveFlagged() {
        flaggedIps.forEach(i -> i.setSelected(false));
        cbSelectAllFlagged.setSelected(false);
        flaggedIpTable.refresh();
    }

    @FXML private void onSelectAllPendingOrgs() {
        boolean v = cbSelectAllPendingOrg.isSelected();
        orgPending.forEach(i -> i.setSelected(v));
        orgPendingTable.refresh();
    }

    @FXML private void onAcceptPendingOrgs() {
        if (!isReady()) return;
        var selected = orgPending.stream().filter(OrgWhitelistItem::isSelected).toList();
        if (selected.isEmpty()) return;
        dataLoader.submit("ids-approve-orgs",
                () -> { for (var i : selected) backend.approveOrg(i.getId()); },
                () -> { cbSelectAllPendingOrg.setSelected(false);
                    dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}); },
                msg -> setStatus("Approve failed: " + msg, true));
    }

    @FXML private void onAcceptAllPendingOrgs() {
        if (!isReady()) return;
        dataLoader.submit("ids-approve-all",
                backend::approveAllOrgs,
                () -> dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}),
                msg -> setStatus("Approve all failed: " + msg, true));
    }

    @FXML private void onApproveAllOrgs() { onAcceptAllPendingOrgs(); }

    @FXML private void onRemovePendingOrg() {
        var selected = orgPending.stream().filter(OrgWhitelistItem::isSelected).toList();
        if (selected.isEmpty() || !isReady()) return;
        dataLoader.submit("ids-del-pending",
                () -> { for (var i : selected) backend.deleteOrgEntry(i.getId()); },
                () -> dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}),
                msg -> setStatus("Remove failed: " + msg, true));
    }

    @FXML private void onRemoveAcceptedOrg() {
        OrgWhitelistItem sel = orgAcceptedTable.getSelectionModel().getSelectedItem();
        if (sel == null || !isReady()) return;
        dataLoader.submit("ids-del-accepted",
                () -> backend.deleteOrgEntry(sel.getId()),
                () -> dataLoader.loadWhitelist(this::onWhitelistLoaded, e -> {}),
                msg -> setStatus("Remove failed: " + msg, true));
    }

    // ── CASE ACTIONS ──────────────────────────────────────────────────────────

    @FXML private void onCreateCase() {
        if (!isReady()) return;
        String title = tfNewCaseTitle.getText().trim();
        if (title.isEmpty()) { lblCaseStatus.setText("Title is required"); return; }
        dataLoader.submit("ids-create-case",
                () -> backend.createCase(title, "",
                        tfNewCaseSuspectIp.getText().trim(),
                        tfNewCaseSuspectMac.getText().trim(),
                        cbNewCaseSeverity.getValue(), ""),
                () -> {
                    tfNewCaseTitle.clear(); tfNewCaseSuspectIp.clear(); tfNewCaseSuspectMac.clear();
                    lblCaseStatus.setText("Case created");
                    dataLoader.loadCases(caseEntries::setAll, e -> {});
                },
                msg -> lblCaseStatus.setText("Failed: " + msg));
    }

    @FXML private void onCloseCase() {
        if (!isReady()) return;
        CaseItem sel = casesTable.getSelectionModel().getSelectedItem();
        if (sel == null) { lblCaseStatus.setText("Select a case first"); return; }
        dataLoader.submit("ids-close-case",
                () -> backend.updateCaseStatus(sel.getId(), "CLOSED", sel.getFindings()),
                () -> {
                    lblCaseStatus.setText("Case closed");
                    dataLoader.loadCases(caseEntries::setAll, e -> {});
                },
                msg -> lblCaseStatus.setText("Failed: " + msg));
    }

    // ── HELPERS ───────────────────────────────────────────────────────────────

    private boolean isReady() { return backend != null && backend.isLoggedIn(); }

    private void setStatus(String msg, boolean connected) {
        lblStatus.setText(msg);
        if (dotLive != null)
            dotLive.setFill(connected ? Color.web("#22c55e") : Color.web("#ef4444"));
    }

    private String fmtInstantSafe(String raw) {
        if (raw == null || raw.isBlank()) return FMT.format(Instant.now());
        try   { return FMT.format(Instant.parse(raw)); }
        catch (Exception e) { return raw; }
    }

    private void handleSessionError(String prefix, String msg) {
        setStatus(prefix + ": " + msg, false);
        if (msg != null && msg.contains("Session expired"))
            backend.invalidateSession();
    }

    // ── CELL FACTORIES ────────────────────────────────────────────────────────

    private <T> TableCell<T, String> cyanCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                setText(empty ? null : s);
                setStyle(empty ? "" : "-fx-text-fill:#00d4ff; -fx-font-weight:bold;");
            }
        };
    }

    private <T> TableCell<T, String> amberCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null) { setText(null); setStyle(""); return; }
                setText(s);
                setStyle("-fx-text-fill:#f59e0b; -fx-font-weight:bold;");
            }
        };
    }

    private <T> TableCell<T, Integer> hitCountCell() {
        return new TableCell<>() {
            @Override protected void updateItem(Integer v, boolean empty) {
                super.updateItem(v, empty);
                if (empty || v == null) { setText(null); setStyle(""); return; }
                setText(String.valueOf(v));
                setStyle(v >= 10
                        ? "-fx-text-fill:#ef4444; -fx-font-weight:bold;"
                        : "-fx-text-fill:#f59e0b;");
            }
        };
    }

    @SuppressWarnings("unchecked")
    private <T> TableCell<T, Boolean> checkBoxCell(Class<T> type) {
        return new TableCell<>() {
            private final CheckBox cb = new CheckBox();
            @Override protected void updateItem(Boolean val, boolean empty) {
                super.updateItem(val, empty);
                if (empty) { setGraphic(null); return; }
                T item = getTableView().getItems().get(getIndex());
                if (item instanceof FlaggedIpItem f) {
                    cb.setSelected(f.isSelected());
                    cb.setOnAction(e -> f.setSelected(cb.isSelected()));
                } else if (item instanceof OrgWhitelistItem o) {
                    cb.setSelected(o.isSelected());
                    cb.setOnAction(e -> o.setSelected(cb.isSelected()));
                }
                setGraphic(cb);
            }
        };
    }

    // ── WHITELIST LOADED ──────────────────────────────────────────────────────

    private void onWhitelistLoaded(List<MyWhitelistItem> my,
                                   List<OrgWhitelistItem> org,
                                   List<FlaggedIpItem> flagged) {
        myWlEntries.setAll(my);
        List<OrgWhitelistItem> accepted = org.stream().filter(OrgWhitelistItem::getApproved).collect(Collectors.toList());
        List<OrgWhitelistItem> pending  = org.stream().filter(o -> !o.getApproved()).collect(Collectors.toList());
        orgAcceptedRaw.setAll(accepted);
        orgPendingRaw .setAll(pending);
        flaggedIps    .setAll(flagged);
        lblFlaggedCount   .setText("Flagged IPs — "            + flagged.size() + " pending");
        lblPendingOrgCount.setText("Pending Organizations — " + pending.size() + " awaiting approval");
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
        colAtkIp.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String ip, boolean empty) {
                super.updateItem(ip, empty);
                if (empty || ip == null) { setText(null); setStyle(""); setOnMouseClicked(null); return; }
                setText(ip);
                setStyle("-fx-text-fill:#00d4ff; -fx-font-weight:bold; -fx-cursor:hand;");
                setOnMouseClicked(e -> openInvestigation(ip));
            }
        });
    }

    private void openInvestigation(String ip) {
        if (!isReady() || ip == null || ip.isBlank()) return;
        caseDetailPanel.setVisible(false);
        caseDetailPanel.setManaged(false);

        investigationPanel.setVisible(true);
        investigationPanel.setManaged(true);
        investigationPanel.investigate(ip);
    }

    private void closeInvestigationPanel() {
        investigationPanel.setVisible(false);
        investigationPanel.setManaged(false);
    }

    // ── SHUTDOWN ──────────────────────────────────────────────────────────────

    public void shutdown() {
        scheduler.shutdownNow();
        try { scheduler.awaitTermination(2, TimeUnit.SECONDS); }
        catch (InterruptedException ignored) {}
        if (wsFeed != null) try { wsFeed.close(); } catch (Exception ignored) {}
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

     StackPane sidePanelContainer = new StackPane(investigationPanel, caseDetailPanel);

     Platform.runLater(() -> {
         javafx.scene.layout.Pane root = findRootPane();
         if (root instanceof HBox hbox) {
             hbox.getChildren().add(sidePanelContainer);
             HBox.setHgrow(sidePanelContainer, Priority.NEVER);
         } else if (root instanceof BorderPane bp) {
             bp.setRight(sidePanelContainer);
         }
     });

     wireIpColumnClick();
 }

    private void closeCaseDetailPanel() {
        caseDetailPanel.setVisible(false);
        caseDetailPanel.setManaged(false);
    }
    private void wireCaseTableDoubleClick() {

        casesTable.setRowFactory(tv -> {

            TableRow<CaseItem> row = new TableRow<>();

            row.setOnMouseClicked(event -> {

                if (event.getClickCount() == 2 && !row.isEmpty()) {

                    CaseItem item = row.getItem();

                    openCaseDetail(item.getId(), item.getCaseNumber());
                }
            });

            return row;
        });
        
    }
    private void openCaseDetail(long caseId, String caseNumber) {

        if (!isReady())
            return;

        investigationPanel.setVisible(false);
        investigationPanel.setManaged(false);

        caseDetailPanel.setBackend(backend);

        caseDetailPanel.setVisible(true);
        caseDetailPanel.setManaged(true);

        caseDetailPanel.openCase(caseId, caseNumber);
    }
}