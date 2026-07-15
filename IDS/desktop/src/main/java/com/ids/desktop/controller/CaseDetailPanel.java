package com.ids.desktop.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ids.desktop.model.AlertItem;
import com.ids.desktop.service.BackendClient;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Map;

/**
 * CaseDetailPanel — a full-screen overlay that shows when an analyst
 * double-clicks a case in the Cases table.
 *
 * ARCHITECTURE NOTE
 * -----------------
 * This is a VBox (the root) that replaces the centre of the scene.
 * MainController shows/hides it the same way IpInvestigationPanel works:
 *
 *   caseDetailPanel.setVisible(true);
 *   caseDetailPanel.setManaged(true);
 *   caseDetailPanel.openCase(caseId, caseNumber);
 *
 * THREADING
 * ---------
 * Every HTTP call runs on a single-threaded executor ("ids-case-detail").
 * Results are dispatched back to the JavaFX thread via Platform.runLater().
 * The UI thread never blocks — that is the golden rule of JavaFX.
 *
 * TAB STRUCTURE
 * -------------
 *  1. Overview  — metadata, stats, quick actions
 *  2. Alerts    — table of linked alerts, filterable
 *  3. Notes     — analyst notes with add/delete
 */
public class CaseDetailPanel extends VBox {

    private static final DateTimeFormatter FMT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                         .withZone(ZoneId.systemDefault());

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // ── State ──────────────────────────────────────────────
    private BackendClient backend;
    private final Runnable onClose;
    private final ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ids-case-detail");
        t.setDaemon(true);
        return t;
    });

    private long   activeCaseId;
    private String activeCaseNumber;

    // ── Overview tab widgets ────────────────────────────────
    private Label lblCaseNum, lblTitle, lblStatus, lblPriority,
                  lblSeverity, lblSuspectIp, lblAssignedTo, lblCreatedBy,
                  lblOpenedAt, lblClosedAt, lblFirstSeen, lblLastSeen,
                  lblAlertCount;

    // ── Alerts tab widgets ─────────────────────────────────
    private final ObservableList<AlertItem> allLinkedAlerts = FXCollections.observableArrayList();
    private FilteredList<AlertItem> filteredAlerts;
    private TableView<AlertItem> alertsTable;
    private TextField tfAlertSearch;
    private ComboBox<String> cbAlertSeverity;

    // ── Notes tab widgets ───────────────────────────────────
    private VBox  notesContainer;
    private TextArea taNoteInput;
    private Label  lblNoteStatus;

    // ── Status bar ──────────────────────────────────────────
    private Label  lblPanelStatus;
    private Circle dotLoading;

    // ──────────────────────────────────────────────────────────────────────
    // CONSTRUCTOR
    // ──────────────────────────────────────────────────────────────────────

    public CaseDetailPanel(BackendClient backend, Runnable onClose) {
        this.backend = backend;
        this.onClose  = onClose;

        setStyle("-fx-background-color: #0d1117; -fx-border-color: #30363d; -fx-border-width: 0 0 0 1;");
        setPrefWidth(900);
        setMinWidth(700);

        buildUI();
    }

    public void setBackend(BackendClient backend) {
        this.backend = backend;
    }

    // ──────────────────────────────────────────────────────────────────────
    // PUBLIC ENTRY POINT
    // ──────────────────────────────────────────────────────────────────────

    /**
     * Opens the panel and loads all data for the given case.
     * Safe to call from the JavaFX thread.
     */
    public void openCase(long caseId, String caseNumber) {
        this.activeCaseId     = caseId;
        this.activeCaseNumber = caseNumber;

        // Reset state
        allLinkedAlerts.clear();
        notesContainer.getChildren().clear();
        taNoteInput.clear();
        lblNoteStatus.setText("");
        setLoading(true);

        loadDetail(caseId);
    }

    // ──────────────────────────────────────────────────────────────────────
    // UI CONSTRUCTION
    // ─────────────────────────────────────────────────────────────────────

    private void buildUI() {
        // ── Header bar ────────────────────────────────────
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(12, 16, 12, 16));
        header.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d; -fx-border-width: 0 0 1 0;");

        Label title = new Label("Case Investigation");
        title.setStyle("-fx-text-fill: #c9d1d9; -fx-font-size: 15; -fx-font-weight: bold;");

        dotLoading = new Circle(5, Color.TRANSPARENT);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        // Quick-action buttons in header
        Button btnRefresh    = mkBtn("⟳ Refresh", "#1f6feb", e -> loadDetail(activeCaseId));
        Button btnBlockIp    = mkBtn("⛔ Block IP", "#dc2626", e -> quickAction("block-ip", "IP_BLOCKED"));
        Button btnClose      = mkBtn("✕ Close", "#374151", e -> onClose.run());

        header.getChildren().addAll(title, dotLoading, spacer,
                                     btnRefresh, btnBlockIp, btnClose);

        // ── Status bar ────────────────────────────────────
        lblPanelStatus = new Label("Loading...");
        lblPanelStatus.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11; -fx-padding: 4 16;");
        lblPanelStatus.setMaxWidth(Double.MAX_VALUE);

        // ── Tab pane ──────────────────────────────────────
        TabPane tabs = new TabPane();
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);
        tabs.setStyle("-fx-background-color: #0d1117;");
        tabs.getTabs().addAll(
            buildOverviewTab(),
            buildAlertsTab(),
            buildNotesTab()
        );
        VBox.setVgrow(tabs, Priority.ALWAYS);

        getChildren().addAll(header, lblPanelStatus, tabs);
    }

    // ─── Tab 1: Overview ──────────────────────────────────

    private Tab buildOverviewTab() {
        GridPane grid = new GridPane();
        grid.setHgap(16);
        grid.setVgap(10);
        grid.setPadding(new Insets(20));
        grid.setStyle("-fx-background-color: #0d1117;");

        // left column = field names, right column = values
        lblCaseNum    = infoLabel("—");
        lblTitle      = infoLabel("—");
        lblStatus     = infoLabel("—");
        lblPriority   = infoLabel("—");
        lblSeverity   = infoLabel("—");
        lblSuspectIp  = infoLabel("—");
        lblAssignedTo = infoLabel("—");
        lblCreatedBy  = infoLabel("—");
        lblOpenedAt   = infoLabel("—");
        lblClosedAt   = infoLabel("—");
        lblFirstSeen  = infoLabel("—");
        lblLastSeen   = infoLabel("—");
        lblAlertCount = infoLabel("—");

        String[][] rows = {
            {"Case Number",  null}, {"Title",       null},
            {"Status",       null}, {"Priority",    null},
            {"Severity",     null}, {"Suspect IP",  null},
            {"Assigned To",  null}, {"Created By",  null},
            {"Opened At",    null}, {"Closed At",   null},
            {"First Seen",   null}, {"Last Seen",   null},
            {"Alert Count",  null}
        };
        Label[] vals = { lblCaseNum, lblTitle, lblStatus, lblPriority, lblSeverity,
                          lblSuspectIp, lblAssignedTo, lblCreatedBy, lblOpenedAt,
                          lblClosedAt, lblFirstSeen, lblLastSeen, lblAlertCount };

        for (int i = 0; i < rows.length; i++) {
            Label key = new Label(rows[i][0] + ":");
            key.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 12;");
            grid.add(key,     0, i);
            grid.add(vals[i], 1, i);
        }

        // Assign case form
        TitledPane assignPane = buildAssignForm();
        VBox root = new VBox(16, grid, assignPane);
        root.setPadding(new Insets(10));
        root.setStyle("-fx-background-color: #0d1117;");

        ScrollPane scroll = new ScrollPane(root);
        scroll.setFitToWidth(true);
        scroll.setStyle("-fx-background-color: #0d1117; -fx-background: #0d1117;");

        Tab tab = new Tab("📋 Overview", scroll);
        return tab;
    }

    private TitledPane buildAssignForm() {
        TextField tfAssign  = new TextField();
        tfAssign.setPromptText("Analyst username");
        tfAssign.setStyle(fieldStyle());

        ComboBox<String> cbStatus = new ComboBox<>(
            FXCollections.observableArrayList("OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"));
        cbStatus.setPromptText("Change status…");
        cbStatus.setStyle(fieldStyle());

        Button btnAssign = mkBtn("Assign", "#1f6feb", e -> {
            String assignee = tfAssign.getText().trim();
            if (assignee.isEmpty()) { lblPanelStatus.setText("Enter an analyst username"); return; }
            assignAnalyst(assignee);
        });
        Button btnStatus = mkBtn("Set Status", "#7c3aed", e -> {
            String s = cbStatus.getValue();
            if (s == null) { lblPanelStatus.setText("Pick a status first"); return; }
            updateStatus(s);
        });

        HBox row1 = new HBox(8, new Label("Assign:"), tfAssign, btnAssign);
        HBox row2 = new HBox(8, new Label("Status:"), cbStatus, btnStatus);
        row1.setAlignment(Pos.CENTER_LEFT);
        row2.setAlignment(Pos.CENTER_LEFT);
        styleLabels(row1, row2);
        // Override the muted styleLabels colour here only — #8b949e at 11px is
        // near-invisible on the #161b22 pane background
        for (HBox row : new HBox[]{ row1, row2 }) {
            row.getChildrenUnmodifiable().stream()
               .filter(n -> n instanceof Label)
               .forEach(n -> ((Label) n).setStyle("-fx-text-fill: #c9d1d9; -fx-font-size: 11;"));
        }

        VBox content = new VBox(8, row1, row2);
        content.setPadding(new Insets(10));

        TitledPane pane = new TitledPane("Quick Updates", content);
        pane.setStyle("-fx-text-fill: #c9d1d9; -fx-background-color: #161b22;");
        pane.setExpanded(true);
        return pane;
    }

    // ─── Tab 2: Alerts ────────────────────────────────────

    private Tab buildAlertsTab() {
        // Filter bar
        tfAlertSearch = new TextField();
        tfAlertSearch.setPromptText("Search IP, type, detail…");
        tfAlertSearch.setStyle(fieldStyle());
        tfAlertSearch.textProperty().addListener((o, ov, nv) -> applyAlertFilter());

        cbAlertSeverity = new ComboBox<>(FXCollections.observableArrayList(
            "", "CRITICAL", "HIGH", "MEDIUM", "LOW"));
        cbAlertSeverity.setValue("");
        cbAlertSeverity.setStyle(fieldStyle());
        cbAlertSeverity.valueProperty().addListener((o, ov, nv) -> applyAlertFilter());

        HBox filterBar = new HBox(8,
            new Label("Search:"), tfAlertSearch,
            new Label("Severity:"), cbAlertSeverity);
        filterBar.setAlignment(Pos.CENTER_LEFT);
        filterBar.setPadding(new Insets(8, 12, 8, 12));
        filterBar.setStyle("-fx-background-color: #161b22;");
        styleLabels(filterBar);

        // Table
        alertsTable = new TableView<>();
        alertsTable.setStyle("-fx-background-color: #0d1117;");

        TableColumn<AlertItem, String> colTime  = col("Time",      "timestamp",   120);
        TableColumn<AlertItem, String> colSev   = col("Severity",  "severity",     80);
        TableColumn<AlertItem, String> colType  = col("Type",      "threatType",  140);
        TableColumn<AlertItem, String> colSrc   = col("Source IP", "sourceIp",    120);
        TableColumn<AlertItem, String> colDst   = col("Dest IP",   "destIp",      120);
        TableColumn<AlertItem, String> colProto = col("Protocol",  "protocol",     70);
        TableColumn<AlertItem, String> colDet   = col("Details",   "details",     220);

        colSev.setCellFactory(c -> severityCell());

        alertsTable.getColumns().addAll(colTime, colSev, colType, colSrc, colDst, colProto, colDet);
        alertsTable.setPlaceholder(new Label("No alerts linked to this case."));
        VBox.setVgrow(alertsTable, Priority.ALWAYS);

        filteredAlerts = new FilteredList<>(allLinkedAlerts, p -> true);
        alertsTable.setItems(filteredAlerts);

        VBox root = new VBox(filterBar, alertsTable);
        VBox.setVgrow(root, Priority.ALWAYS);

        return new Tab("Alerts", root);
    }

    private void applyAlertFilter() {
        String search = tfAlertSearch.getText().toLowerCase().trim();
        String sev    = cbAlertSeverity.getValue();
        filteredAlerts.setPredicate(a -> {
            if (!search.isEmpty()) {
                boolean match = contains(a.getSourceIp(),   search)
                             || contains(a.getThreatType(), search)
                             || contains(a.getDetails(),    search)
                             || contains(a.getDestIp(),     search);
                if (!match) return false;
            }
            if (sev != null && !sev.isEmpty() && !sev.equals(a.getSeverity())) return false;
            return true;
        });
    }

    // ─── Tab 3: Notes ─────────────────────────────────────

    private Tab buildNotesTab() {
        // Notes list
        notesContainer = new VBox(6);
        notesContainer.setPadding(new Insets(10));
        notesContainer.setStyle("-fx-background-color: #0d1117;");

        ScrollPane scrollNotes = new ScrollPane(notesContainer);
        scrollNotes.setFitToWidth(true);
        scrollNotes.setStyle("-fx-background-color: #0d1117; -fx-background: #0d1117;");
        VBox.setVgrow(scrollNotes, Priority.ALWAYS);

        // Add note form
        taNoteInput = new TextArea();
        taNoteInput.setPromptText("Write your investigation notes, findings, or recommendations here...");
        taNoteInput.setPrefRowCount(4);
        taNoteInput.setWrapText(true);
        taNoteInput.setStyle("-fx-background-color: #161b22; -fx-text-fill: #c9d1d9; -fx-control-inner-background: #161b22;");

        lblNoteStatus = new Label("");
        lblNoteStatus.setStyle("-fx-text-fill: #22c55e; -fx-font-size: 11;");

        Button btnAddNote = mkBtn("➕ Add Note", "#1f6feb", e -> submitNote());

        HBox noteBar = new HBox(8, btnAddNote, lblNoteStatus);
        noteBar.setAlignment(Pos.CENTER_LEFT);

        VBox addForm = new VBox(6, new Label("New Note:"), taNoteInput, noteBar);
        addForm.setPadding(new Insets(10));
        addForm.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d; -fx-border-width: 1 0 0 0;");
        styleLabels(addForm);

        VBox root = new VBox(scrollNotes, addForm);
        VBox.setVgrow(root, Priority.ALWAYS);

        return new Tab("Notes", root);
    }

    private void populateNotes(JsonNode arr) {
        notesContainer.getChildren().clear();
        if (arr == null || !arr.isArray() || arr.isEmpty()) {
            Label empty = new Label("No notes yet. Add your first note below.");
            empty.setStyle("-fx-text-fill: #6b7280;");
            notesContainer.getChildren().add(empty);
            return;
        }
        for (JsonNode note : arr) {
            notesContainer.getChildren().add(buildNoteCard(note));
        }
    }

    private VBox buildNoteCard(JsonNode note) {
        long   noteId  = note.path("id").asLong(0);
        String author  = note.path("author").asText("analyst");
        String content = note.path("content").asText("");
        String created = fmtInstant(note.path("createdAt").asText(""));

        Label lblMeta = new Label(author + " · " + created);
        lblMeta.setStyle("-fx-text-fill: #6b7280; -fx-font-size: 11;");

        Label lblContent = new Label(content);
        lblContent.setStyle("-fx-text-fill: #c9d1d9; -fx-font-size: 12;");
        lblContent.setWrapText(true);

        Button btnDel = new Button("✕");
        btnDel.setStyle("-fx-background-color: transparent; -fx-text-fill: #6b7280; -fx-cursor: hand;");
        btnDel.setOnAction(e -> deleteNote(noteId));

        HBox meta = new HBox(lblMeta);
        HBox.setHgrow(meta, Priority.ALWAYS);
        HBox topRow = new HBox(meta, btnDel);
        topRow.setAlignment(Pos.CENTER_LEFT);

        VBox card = new VBox(4, topRow, lblContent);
        card.setPadding(new Insets(10));
        card.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d; " +
                      "-fx-border-width: 1; -fx-border-radius: 4;");
        return card;
    }

    // ──────────────────────────────────────────────────────────────────────
    // DATA LOADING
    // ─────────────────────────────────────────────────────────────────────

    private void loadDetail(long caseId) {
        setLoading(true);
        pool.submit(() -> {
            try {
                String json = backend.getRaw("/api/forensics/cases/" + caseId + "/detail");
                JsonNode root = MAPPER.readTree(json);
                Platform.runLater(() -> {
                    populateOverview(root);
                    populateAlertsFromDetail(root.path("linkedAlerts"));
                    populateNotes(root.path("notes"));
                    setLoading(false);
                    lblPanelStatus.setText("Case " + activeCaseNumber + " loaded · " +
                        root.path("alertCount").asInt(0) + " linked alerts");
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    setLoading(false);
                    lblPanelStatus.setText("Error loading case: " + ex.getMessage());
                });
            }
        });
    }

    private void populateOverview(JsonNode r) {
        lblCaseNum    .setText(text(r, "caseNumber"));
        lblTitle      .setText(text(r, "title"));
        lblStatus     .setText(text(r, "status"));
        lblPriority   .setText(text(r, "priority"));
        lblSeverity   .setText(text(r, "severity"));
        lblSuspectIp  .setText(text(r, "suspectIp"));
        lblAssignedTo .setText(text(r, "assignedTo"));
        lblCreatedBy  .setText(text(r, "createdBy"));
        lblOpenedAt   .setText(fmtInstant(text(r, "openedAt")));
        lblClosedAt   .setText(fmtInstant(text(r, "closedAt")));
        lblFirstSeen  .setText(fmtInstant(text(r, "firstSeen")));
        lblLastSeen   .setText(fmtInstant(text(r, "lastSeen")));
        lblAlertCount .setText(r.path("alertCount").asText("0"));

        // Colour-code status
        String statusColour = switch (r.path("status").asText("")) {
            case "OPEN"        -> "#ef4444";
            case "IN_PROGRESS" -> "#f59e0b";
            case "RESOLVED"    -> "#3b82f6";
            case "CLOSED"      -> "#22c55e";
            default            -> "#8b949e";
        };
        lblStatus.setStyle("-fx-text-fill: " + statusColour + "; -fx-font-weight: bold;");
    }

    private void populateAlertsFromDetail(JsonNode arr) {
        allLinkedAlerts.clear();
        if (arr == null || !arr.isArray()) return;
        for (JsonNode a : arr) {
            AlertItem item = new AlertItem(
                fmtInstant(a.path("timestamp").asText("")),
                a.path("severity").asText(),
                a.path("threatType").asText(),
                a.path("sourceIp").asText(),
                a.path("sourceMac").asText(),
                a.path("destIp").asText(),
                a.path("protocol").asText(),
                a.path("requestType").asText(),
                a.path("packetCount").asInt(0),
                a.path("details").asText()
            );
            item.setId(a.path("id").asLong(0));
            allLinkedAlerts.add(item);
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // ACTIONS
    // ──────────────────────────────────────────────────────────────────────

    private void submitNote() {
        String content = taNoteInput.getText().trim();
        if (content.isEmpty()) {
            lblNoteStatus.setText("Please write a note first.");
            lblNoteStatus.setStyle("-fx-text-fill: #ef4444;");
            return;
        }
        lblNoteStatus.setText("Saving…");
        pool.submit(() -> {
            try {
                backend.postJson("/api/forensics/cases/" + activeCaseId + "/notes",
                                  "{\"content\": " + MAPPER.writeValueAsString(content) + "}");
                Platform.runLater(() -> {
                    taNoteInput.clear();
                    lblNoteStatus.setText("Note saved ✓");
                    lblNoteStatus.setStyle("-fx-text-fill: #22c55e;");
                    loadDetail(activeCaseId); // reload to show the new note + timeline entry
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    lblNoteStatus.setText("Failed: " + ex.getMessage());
                    lblNoteStatus.setStyle("-fx-text-fill: #ef4444;");
                });
            }
        });
    }

    private void deleteNote(long noteId) {
        pool.submit(() -> {
            try {
                backend.delete("/api/forensics/cases/notes/" + noteId);
                Platform.runLater(() -> loadDetail(activeCaseId));
            } catch (Exception ex) {
                Platform.runLater(() ->
                    lblPanelStatus.setText("Delete note failed: " + ex.getMessage()));
            }
        });
    }

    private void quickAction(String endpoint, String kind) {
        pool.submit(() -> {
            try {
                backend.postJson("/api/forensics/cases/" + activeCaseId + "/" + endpoint, "{}");
                Platform.runLater(() -> {
                    lblPanelStatus.setText(kind.replace("_", " ") + " recorded");
                    loadDetail(activeCaseId);
                });
            } catch (Exception ex) {
                Platform.runLater(() ->
                    lblPanelStatus.setText("Action failed: " + ex.getMessage()));
            }
        });
    }

    /** PATCH /cases/{id}/status — body {"status": "..."} */
    private void updateStatus(String status) {
        submitUpdate("/api/forensics/cases/" + activeCaseId + "/status",
                     Map.of("status", status),
                     "Status updated");
    }

    /** PATCH /cases/{id}/assign — body {"analyst": "..."}  (NOT "assignedTo") */
    private void assignAnalyst(String analyst) {
        submitUpdate("/api/forensics/cases/" + activeCaseId + "/assign",
                     Map.of("analyst", analyst),
                     "Case assigned");
    }

    private void submitUpdate(String path, Map<String, String> body, String okMsg) {
        if (activeCaseId <= 0) {
            lblPanelStatus.setText("No case loaded");
            return;
        }
        pool.submit(() -> {
            try {
                backend.patch(path, MAPPER.writeValueAsString(body));
                Platform.runLater(() -> {
                    lblPanelStatus.setText(okMsg + " ✓");
                    loadDetail(activeCaseId);
                });
            } catch (Exception ex) {
                Platform.runLater(() ->
                    lblPanelStatus.setText("Update failed: " + ex.getMessage()));
            }
        });
    }

    // ──────────────────────────────────────────────────────────────────────
    // HELPERS
    // ──────────────────────────────────────────────────────────────────────

    private void setLoading(boolean on) {
        dotLoading.setFill(on ? Color.web("#f59e0b") : Color.TRANSPARENT);
        if (on) lblPanelStatus.setText("Loading…");
    }

    private String text(JsonNode n, String field) {
        String v = n.path(field).asText("");
        return v.isBlank() ? "—" : v;
    }

    private String fmtInstant(String raw) {
        if (raw == null || raw.isBlank() || raw.equals("—")) return "—";
        try { return FMT.format(Instant.parse(raw)); }
        catch (Exception e) { return raw; }
    }

    private boolean contains(String haystack, String needle) {
        return haystack != null && haystack.toLowerCase().contains(needle);
    }

    private Label infoLabel(String text) {
        Label l = new Label(text);
        l.setStyle("-fx-text-fill: #c9d1d9; -fx-font-size: 12;");
        return l;
    }

    private Button mkBtn(String label, String color, javafx.event.EventHandler<javafx.event.ActionEvent> handler) {
        Button b = new Button(label);
        b.setStyle("-fx-background-color: " + color + "; -fx-text-fill: white; -fx-font-size: 11; " +
                   "-fx-cursor: hand; -fx-padding: 4 10;");
        b.setOnAction(handler);
        return b;
    }

    private <T> TableColumn<T, String> col(String header, String prop, double width) {
        TableColumn<T, String> c = new TableColumn<>(header);
        c.setCellValueFactory(new PropertyValueFactory<>(prop));
        c.setPrefWidth(width);
        c.setStyle("-fx-text-fill: #c9d1d9;");
        return c;
    }

    private <T> TableCell<T, String> severityCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                if (empty || val == null) { setText(null); setStyle(""); return; }
                setText(val);
                setStyle(switch (val) {
                    case "CRITICAL" -> "-fx-text-fill:#ef4444; -fx-font-weight:bold;";
                    case "HIGH"     -> "-fx-text-fill:#f97316; -fx-font-weight:bold;";
                    case "MEDIUM"   -> "-fx-text-fill:#f59e0b;";
                    default         -> "-fx-text-fill:#22c55e;";
                });
            }
        };
    }

    private String fieldStyle() {
        return "-fx-background-color: #161b22; -fx-text-fill: #c9d1d9; " +
               "-fx-border-color: #30363d; -fx-border-width: 1; -fx-border-radius: 3; -fx-padding: 4 8;";
    }

    private void styleLabels(Pane... panes) {
        for (Pane p : panes) {
            p.getChildrenUnmodifiable().stream()
             .filter(n -> n instanceof Label)
             .map(n -> (Label) n)
             .forEach(l -> l.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11;"));
        }
    }
}