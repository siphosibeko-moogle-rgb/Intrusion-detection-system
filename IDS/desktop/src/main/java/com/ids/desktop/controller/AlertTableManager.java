package com.ids.desktop.controller;

import com.ids.desktop.model.AlertItem;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class AlertTableManager {

    // The two tables this class manages
    private final TableView<AlertItem> alertTable;
    private final TableView<AlertItem> attackerTable;

    // Filter fields — read-only references, never written here
    private final TextField tfIp, tfMac, tfType;
    private final ComboBox<String> cbSeverity, cbProtocol;
    private final TextField tfFilterAtkIp;

    // The shared observable lists — MainController holds the canonical reference
    private final ObservableList<AlertItem> allAlerts;
    private final ObservableList<AlertItem> attackers;

    private FilteredList<AlertItem> filteredAlerts;
    private long lastAttackerRebuild = 0L;

    public AlertTableManager(
            TableView<AlertItem> alertTable,
            TableView<AlertItem> attackerTable,
            TextField tfIp, TextField tfMac, TextField tfType,
            ComboBox<String> cbSeverity, ComboBox<String> cbProtocol,
            TextField tfFilterAtkIp,
            ObservableList<AlertItem> allAlerts,
            ObservableList<AlertItem> attackers) {

        this.alertTable    = alertTable;
        this.attackerTable = attackerTable;
        this.tfIp          = tfIp;
        this.tfMac         = tfMac;
        this.tfType        = tfType;
        this.cbSeverity    = cbSeverity;
        this.cbProtocol    = cbProtocol;
        this.tfFilterAtkIp = tfFilterAtkIp;
        this.allAlerts     = allAlerts;
        this.attackers     = attackers;
    }

    /** Call once from MainController.initialize() */
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
            TableColumn<AlertItem, String>  colAtkIp,
            TableColumn<AlertItem, String>  colAtkMac,
            TableColumn<AlertItem, Integer> colAtkCount) {

        setupAlertColumns(colTimestamp, colSeverity, colThreatType,
                colSourceIp, colSourceMac, colDestIp,
                colProtocol, colRequestType, colPackets, colDetails);

        setupAttackerColumns(colAtkIp, colAtkMac, colAtkCount);
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
            TableColumn<AlertItem, String>  colDetails) {

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

        // Severity colour-coding — RED for critical, orange for high, etc.
        colSeverity.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String s, boolean empty) {
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

        // Cyan source IP — visually indicates it's the key field
        colSourceIp.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                setText(empty ? null : s);
                setStyle(empty ? "" : "-fx-text-fill:#00d4ff; -fx-font-weight:bold;");
            }
        });

        filteredAlerts = new FilteredList<>(allAlerts, p -> true);
        alertTable.setItems(filteredAlerts);
        alertTable.setPlaceholder(new Label("No alerts yet."));
    }

    private void setupAttackerColumns(
            TableColumn<AlertItem, String>  colAtkIp,
            TableColumn<AlertItem, String>  colAtkMac,
            TableColumn<AlertItem, Integer> colAtkCount) {

        colAtkIp   .setCellValueFactory(new PropertyValueFactory<>("sourceIp"));
        colAtkMac  .setCellValueFactory(new PropertyValueFactory<>("sourceMac"));
        colAtkCount.setCellValueFactory(new PropertyValueFactory<>("packetCount"));

        colAtkIp.setCellFactory(col -> new TableCell<>() {
            @Override
            protected void updateItem(String val, boolean empty) {
                super.updateItem(val, empty);
                setText(empty ? null : val);
                setStyle(empty ? "" : "-fx-text-fill:#ef4444; -fx-font-weight:bold;");
            }
        });

        FilteredList<AlertItem> filteredAttackers = new FilteredList<>(attackers, p -> true);
        attackerTable.setItems(filteredAttackers);
        attackerTable.setPlaceholder(new Label("No threat actors detected yet."));

        tfFilterAtkIp.textProperty().addListener((o, ov, nv) -> {
            String f = nv.toLowerCase().trim();
            filteredAttackers.setPredicate(a ->
                    f.isEmpty() || a.getSourceIp().toLowerCase().contains(f));
        });
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
                                 || !a.getSourceMac().toLowerCase().contains(mac))) return false;
            if (!type.isEmpty() && !a.getThreatType().toLowerCase().contains(type)) return false;
            if (severity != null && !severity.isEmpty()
                                 && !severity.equals(a.getSeverity()))              return false;
            if (protocol != null && !protocol.isEmpty()
                                 && !protocol.equals(a.getProtocol()))              return false;
            return true;
        });
    }

    /**
     * Rebuild the top-20 attackers list from allAlerts.
     * Must be called on the JavaFX thread.
     * Throttled externally — caller checks the time delta before calling.
     */
    public void rebuildAttackers() {
        Map<String, Long> counts = allAlerts.stream()
                .filter(a -> a.getSourceIp() != null && !a.getSourceIp().isEmpty())
                .collect(Collectors.groupingBy(AlertItem::getSourceIp, Collectors.counting()));

        List<AlertItem> top = counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(20)
                .map(e -> {
                    String mac = allAlerts.stream()
                            .filter(a -> e.getKey().equals(a.getSourceIp()))
                            .map(AlertItem::getSourceMac)
                            .findFirst().orElse("");
                    return new AlertItem("", "", "", e.getKey(), mac, "", "", "",
                            e.getValue().intValue(), "");
                })
                .collect(Collectors.toList());

        attackers.setAll(top);
        lastAttackerRebuild = System.currentTimeMillis();
    }

    public long getLastAttackerRebuild() { return lastAttackerRebuild; }

    public void clearFilters() {
        tfIp.clear(); tfMac.clear(); tfType.clear();
        cbSeverity.getSelectionModel().clearSelection();
        cbProtocol.getSelectionModel().clearSelection();
    }
}