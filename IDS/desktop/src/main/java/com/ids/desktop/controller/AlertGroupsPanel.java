package com.ids.desktop.controller;

import com.ids.desktop.model.AlertGroupItem;
import com.ids.desktop.service.BackendClient;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BiConsumer;

/**
 * AlertGroupsPanel — the "Create Cases from Alerts" screen.
 *
 * ARCHITECTURE NOTE
 * ------------------
 * Same overlay pattern as CaseDetailPanel and IpInvestigationPanel: a VBox
 * that MainController shows/hides inside the shared side-panel StackPane.
 * One row per source IP (from GET /cases/alert-groups). Rows that already
 * have a case show "View Case" instead of "Create Case" — the backend is
 * the source of truth for that distinction (ForensicCaseService.getBySuspectIp),
 * this panel never decides dedup logic itself.
 *
 * THREADING
 * ---------
 * All HTTP calls run on a dedicated single-thread executor
 * ("ids-alert-groups"). Results always come back to the FX thread via
 * Platform.runLater() before touching any UI control.
 */
public class AlertGroupsPanel extends VBox {

    private BackendClient backend;
    private final Runnable onClose;
    private final BiConsumer<Long, String> onOpenCase; // (caseId, caseNumber) -> show CaseDetailPanel

    private final ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "ids-alert-groups");
        t.setDaemon(true);
        return t;
    });

    private final ObservableList<AlertGroupItem> rows = FXCollections.observableArrayList();
    private TableView<AlertGroupItem> table;
    private Label lblStatus;
    private Circle dotLoading;

    public AlertGroupsPanel(BackendClient backend, Runnable onClose, BiConsumer<Long, String> onOpenCase) {
        this.backend    = backend;
        this.onClose    = onClose;
        this.onOpenCase = onOpenCase;

        setStyle("-fx-background-color: #0d1117; -fx-border-color: #30363d; -fx-border-width: 0 0 0 1;");
        setPrefWidth(900);
        setMinWidth(700);

        buildUI();
    }

    public void setBackend(BackendClient backend) {
        this.backend = backend;
    }

    // ── PUBLIC ENTRY POINT ───────────────────────────────────────────────

    /** Opens the panel and loads the current alert groups. Call from the FX thread. */
    public void open() {
        refresh();
    }

    // ── UI CONSTRUCTION ──────────────────────────────────────────────────

    private void buildUI() {
        HBox header = new HBox(10);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(12, 16, 12, 16));
        header.setStyle("-fx-background-color: #161b22; -fx-border-color: #30363d; -fx-border-width: 0 0 1 0;");

        Label title = new Label("Create Cases from Alerts");
        title.setStyle("-fx-text-fill: #c9d1d9; -fx-font-size: 15; -fx-font-weight: bold;");

        dotLoading = new Circle(5, Color.TRANSPARENT);

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Button btnRefresh = mkBtn("⟳ Refresh", "#1f6feb", e -> refresh());
        Button btnClose   = mkBtn("✕ Close",   "#374151", e -> onClose.run());

        header.getChildren().addAll(title, dotLoading, spacer, btnRefresh, btnClose);

        lblStatus = new Label("Loading…");
        lblStatus.setStyle("-fx-text-fill: #8b949e; -fx-font-size: 11; -fx-padding: 4 16;");
        lblStatus.setMaxWidth(Double.MAX_VALUE);

        table = buildTable();
        VBox.setVgrow(table, Priority.ALWAYS);

        getChildren().addAll(header, lblStatus, table);
    }

    private TableView<AlertGroupItem> buildTable() {
        TableView<AlertGroupItem> tv = new TableView<>();
        tv.setStyle("-fx-background-color: #0d1117;");
        tv.setItems(rows);
        tv.setPlaceholder(new Label("No alerts recorded yet."));

        TableColumn<AlertGroupItem, String> colIp = col("Source IP", "sourceIp", 130);
        TableColumn<AlertGroupItem, String> colMac = col("MAC", "sourceMac", 130);
        TableColumn<AlertGroupItem, Number> colCount = numCol("Alerts", "alertCount", 70);
        TableColumn<AlertGroupItem, String> colSev = col("Severity", "severity", 90);
        TableColumn<AlertGroupItem, String> colTypes = col("Threat Types", "threatTypes", 220);
        TableColumn<AlertGroupItem, String> colFirst = col("First Seen", "firstSeen", 140);
        TableColumn<AlertGroupItem, String> colLast = col("Last Seen", "lastSeen", 140);
        TableColumn<AlertGroupItem, Void> colAction = new TableColumn<>("Action");
        colAction.setPrefWidth(150);
        colAction.setCellFactory(c -> actionCell());

        colSev.setCellFactory(c -> severityCell());

        tv.getColumns().addAll(colIp, colMac, colCount, colSev, colTypes, colFirst, colLast, colAction);
        return tv;
    }

    /**
     * One button per row. Rows with an existing case show "View Case" —
     * clicking it opens CaseDetailPanel directly rather than re-creating
     * anything, since the backend already told us the case exists.
     */
    private TableCell<AlertGroupItem, Void> actionCell() {
        return new TableCell<>() {
            private final Button btn = new Button();
            {
                btn.setOnAction(e -> {
                    AlertGroupItem item = getTableView().getItems().get(getIndex());
                    if (item.isHasExistingCase()) {
                        onOpenCase.accept(item.getExistingCaseId(), item.getExistingCaseNumber());
                    } else {
                        createCase(item.getSourceIp());
                    }
                });
            }
            @Override protected void updateItem(Void v, boolean empty) {
                super.updateItem(v, empty);
                if (empty) { setGraphic(null); return; }
                AlertGroupItem item = getTableView().getItems().get(getIndex());
                if (item.isHasExistingCase()) {
                    btn.setText("View Case " + item.getExistingCaseNumber());
                    btn.setStyle(btnStyle("#374151"));
                } else {
                    btn.setText("⚑ Create Case");
                    btn.setStyle(btnStyle("#1f6feb"));
                }
                setGraphic(btn);
            }
        };
    }

    // ── DATA LOADING ─────────────────────────────────────────────────────

    private void refresh() {
        setLoading(true);
        pool.submit(() -> {
            try {
                var groups = backend.fetchAlertGroups();
                Platform.runLater(() -> {
                    rows.setAll(groups);
                    setLoading(false);
                    lblStatus.setText(groups.size() + " source IP" + (groups.size() == 1 ? "" : "s")
                            + " with recorded alerts");
                });
            } catch (Exception ex) {
                Platform.runLater(() -> {
                    setLoading(false);
                    lblStatus.setText("Error loading alert groups: " + ex.getMessage());
                });
            }
        });
    }

    private void createCase(String ip) {
        lblStatus.setText("Creating case for " + ip + "…");
        pool.submit(() -> {
            try {
                var caseNode = backend.createCaseFromIp(ip);
                long id = caseNode.path("id").asLong(0);
                String caseNumber = caseNode.path("caseNumber").asText("");
                Platform.runLater(() -> {
                    lblStatus.setText("Case " + caseNumber + " created for " + ip);
                    refresh();
                    if (id > 0) onOpenCase.accept(id, caseNumber);
                });
            } catch (Exception ex) {
                Platform.runLater(() -> lblStatus.setText("Create failed: " + ex.getMessage()));
            }
        });
    }

    // ── HELPERS ──────────────────────────────────────────────────────────

    private void setLoading(boolean on) {
        dotLoading.setFill(on ? Color.web("#f59e0b") : Color.TRANSPARENT);
        if (on) lblStatus.setText("Loading…");
    }

    private Button mkBtn(String label, String color, javafx.event.EventHandler<javafx.event.ActionEvent> handler) {
        Button b = new Button(label);
        b.setStyle(btnStyle(color));
        b.setOnAction(handler);
        return b;
    }

    private String btnStyle(String color) {
        return "-fx-background-color: " + color + "; -fx-text-fill: white; -fx-font-size: 11; " +
               "-fx-cursor: hand; -fx-padding: 4 10;";
    }

    private <T> TableColumn<AlertGroupItem, T> col(String header, String prop, double width) {
        TableColumn<AlertGroupItem, T> c = new TableColumn<>(header);
        c.setCellValueFactory(new PropertyValueFactory<>(prop));
        c.setPrefWidth(width);
        c.setStyle("-fx-text-fill: #c9d1d9;");
        return c;
    }

    @SuppressWarnings("unchecked")
    private TableColumn<AlertGroupItem, Number> numCol(String header, String prop, double width) {
        TableColumn<AlertGroupItem, Number> c = new TableColumn<>(header);
        c.setCellValueFactory(new PropertyValueFactory(prop));
        c.setPrefWidth(width);
        c.setStyle("-fx-text-fill: #c9d1d9;");
        return c;
    }

    private TableCell<AlertGroupItem, String> severityCell() {
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
}