package com.ids.desktop.controller;

import com.ids.desktop.model.AlertItem;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.HashMap;
import java.util.Map;

public class AlertTableManager {

    private final TableView<AlertItem> alertTable;

    private final TextField        tfIp, tfMac, tfType;
    private final ComboBox<String> cbSeverity, cbProtocol;

    // Canonical list owned by MainController — we only read/mutate, never replace
    private final ObservableList<AlertItem> allAlerts;

    private FilteredList<AlertItem> filteredAlerts;

    // ── Dedup index: (sourceIp\0threatType) → AlertItem ──────────────────────
    // Kept in sync with allAlerts at all times.
    // Used by upsertAlert() so we never do an O(n) scan per WS message.
    private final Map<String, AlertItem> summaryIndex = new HashMap<>();

    public AlertTableManager(
            TableView<AlertItem> alertTable,
            TextField tfIp, TextField tfMac, TextField tfType,
            ComboBox<String> cbSeverity, ComboBox<String> cbProtocol,
            ObservableList<AlertItem> allAlerts) {

        this.alertTable    = alertTable;
        this.tfIp          = tfIp;
        this.tfMac         = tfMac;
        this.tfType        = tfType;
        this.cbSeverity    = cbSeverity;
        this.cbProtocol    = cbProtocol;
        this.allAlerts     = allAlerts;
    }

    public void setup(
            TableColumn<AlertItem, String>  colTimestamp,
            TableColumn<AlertItem, String>  colSeverity,
            TableColumn<AlertItem, String>  colThreatType,
            TableColumn<AlertItem, String>  colSourceIp,
            TableColumn<AlertItem, String>  colSourceMac,
            TableColumn<AlertItem, String>  colDestIp,
            TableColumn<AlertItem, String>  colProtocol,
            TableColumn<AlertItem, String>  colRequestType,
            TableColumn<AlertItem, Integer> colPackets,
            TableColumn<AlertItem, String>  colDetails,
            TableColumn<AlertItem, Integer> colOccurrences) {

        setupAlertColumns(colTimestamp, colSeverity, colThreatType,
                colSourceIp, colSourceMac, colDestIp,
                colProtocol, colRequestType, colPackets, colDetails, colOccurrences);

        setupFilters();
    }

    private void setupAlertColumns(
            TableColumn<AlertItem, String>  colTimestamp,
            TableColumn<AlertItem, String>  colSeverity,
            TableColumn<AlertItem, String>  colThreatType,
            TableColumn<AlertItem, String>  colSourceIp,
            TableColumn<AlertItem, String>  colSourceMac,
            TableColumn<AlertItem, String>  colDestIp,
            TableColumn<AlertItem, String>  colProtocol,
            TableColumn<AlertItem, String>  colRequestType,
            TableColumn<AlertItem, Integer> colPackets,
            TableColumn<AlertItem, String>  colDetails,
            TableColumn<AlertItem, Integer> colOccurrences) {

        colTimestamp  .setCellValueFactory(new PropertyValueFactory<>("timestamp"));
        colSeverity   .setCellValueFactory(new PropertyValueFactory<>("severity"));
        colThreatType .setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colSourceIp   .setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        colSourceMac  .setCellValueFactory(new PropertyValueFactory<>("sourceMac"));
        colDestIp     .setCellValueFactory(new PropertyValueFactory<>("destIp"));
        colProtocol   .setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colRequestType.setCellValueFactory(new PropertyValueFactory<>("requestType"));
        colPackets    .setCellValueFactory(new PropertyValueFactory<>("packetCount"));
        colDetails    .setCellValueFactory(new PropertyValueFactory<>("details"));
        colOccurrences.setCellValueFactory(new PropertyValueFactory<>("occurrences"));

        // Severity colour-coding
        colSeverity.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null) { setText(null); setStyle(""); return; }
                setText(s);
                setStyle(switch (s) {
                    case "CRITICAL" -> "-fx-text-fill:#ff4444; -fx-font-weight:bold;";
                    case "HIGH"     -> "-fx-text-fill:#ff8800; -fx-font-weight:bold;";
                    case "MEDIUM"   -> "-fx-text-fill:#f59e0b;";
                    default         -> "-fx-text-fill:#22c55e;";
                });
            }
        });

        // Source IP in cyan — visually marks it as the primary key field
        colSourceIp.setCellFactory(col -> new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                setText(empty ? null : s);
                setStyle(empty ? "" : "-fx-text-fill:#00d4ff; -fx-font-weight:bold;");
            }
        });

        filteredAlerts = new FilteredList<>(allAlerts, p -> true);
        alertTable.setItems(filteredAlerts);
        alertTable.setPlaceholder(new Label("No alerts yet."));
    }

    private void setupFilters() {
        tfIp.textProperty()      .addListener((o, ov, nv) -> applyFilter());
        tfMac.textProperty()     .addListener((o, ov, nv) -> applyFilter());
        tfType.textProperty()    .addListener((o, ov, nv) -> applyFilter());
        cbSeverity.valueProperty().addListener((o, ov, nv) -> applyFilter());
        cbProtocol.valueProperty().addListener((o, ov, nv) -> applyFilter());
    }

    private void applyFilter() {
        String ip       = tfIp.getText().toLowerCase().trim();
        String mac      = tfMac.getText().toLowerCase().trim();
        String type     = tfType.getText().toLowerCase().trim();
        String severity = cbSeverity.getValue();
        String protocol = cbProtocol.getValue();

        filteredAlerts.setPredicate(a -> {
            if (!ip.isEmpty()   && !a.getSourceIp().toLowerCase().contains(ip))   return false;
            if (!mac.isEmpty()  && (a.getSourceMac() == null
                                 || !a.getSourceMac().toLowerCase().contains(mac)))  return false;
            if (!type.isEmpty() && !a.getThreatType().toLowerCase().contains(type)) return false;
            if (severity != null && !severity.isEmpty()
                                 && !severity.equals(a.getSeverity()))              return false;
            if (protocol != null && !protocol.isEmpty()
                                 && !protocol.equals(a.getProtocol()))              return false;
            return true;
        });
    }

    // ── INDEX MANAGEMENT ──────────────────────────────────────────────────────

    private String keyOf(String sourceIp, String threatType) {
        return sourceIp + "\u0000" + threatType;
    }

    /**
     * Rebuild the dedup index after allAlerts.setAll() on initial load / refresh.
     * Must be called on the JavaFX thread.
     */
    public void rebuildIndex() {
        summaryIndex.clear();
        for (AlertItem item : allAlerts)
            summaryIndex.put(keyOf(item.getSourceIp(), item.getThreatType()), item);
    }

    /**
     * Upsert: update an existing row or prepend a new one.
     * Called for every WebSocket push — O(1) via the index, never O(n).
     * Must be called on the JavaFX thread.
     */
    public void upsertAlert(AlertItem incoming) {
        String key = keyOf(incoming.getSourceIp(), incoming.getThreatType());
        AlertItem existing = summaryIndex.get(key);
        if (existing != null) {
            existing.setOccurrences(incoming.getOccurrences());
            existing.setTimestamp(incoming.getTimestamp());
            existing.setFirstSeen(incoming.getFirstSeen());
            existing.setId(incoming.getId());
            allAlerts.remove(existing);
            allAlerts.add(0, existing);
        } else {
            summaryIndex.put(key, incoming);
            allAlerts.add(0, incoming);
        }
    }

    /**
     * Remove an alert from the table by its database summary id.
     * Called when the WebSocket delivers a deletion event: {"id": 42} on
     * /topic/alerts/deleted. Must be called on the JavaFX thread.
     */
    public void removeById(long id) {
        summaryIndex.entrySet().removeIf(e -> e.getValue().getId() == id);
        allAlerts.removeIf(a -> a.getId() == id);
    }

    public void clearFilters() {
        tfIp.clear(); tfMac.clear(); tfType.clear();
        cbSeverity.getSelectionModel().clearSelection();
        cbProtocol.getSelectionModel().clearSelection();
    }
}