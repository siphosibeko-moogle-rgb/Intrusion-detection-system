package com.ids.desktop.controller;

import com.ids.desktop.model.FlaggedIpItem;
import com.ids.desktop.model.MyWhitelistItem;
import com.ids.desktop.service.BackendClient;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Owns the two whitelist views (My Whitelist — Trusted Devices, and
 * Flagged IPs): table wiring, filtering, and every add/accept/remove
 * action against the backend.
 *
 * Extracted from MainController (same decomposition pattern as
 * AlertTableManager / DashboardPanel). MainController keeps the @FXML
 * fields — the FXML loader injects into the controller class named in
 * fx:controller, so the controls themselves must stay there — and hands
 * them over via the bind*() methods; its @FXML action handlers are
 * one-line delegations here.
 *
 * BackendClient and DataLoader are recreated on every login, so they are
 * passed as Suppliers rather than captured once.
 *
 * NOTE: the org-whitelist UI (accepted/pending organization tables) was
 * removed from the desktop in July 2026. The backend org-whitelist API
 * still exists and the ENGINE still loads approved org IPs/CIDR ranges
 * from it into its detection whitelist — manage those entries via the
 * backend API directly.
 */
public class WhitelistPanelManager {

    private final Supplier<DataLoader>    dataLoader;
    private final Supplier<BackendClient> backend;
    private final BooleanSupplier         ready;
    private final Consumer<String>        status;

    private final ObservableList<MyWhitelistItem> myWlEntries = FXCollections.observableArrayList();
    private final ObservableList<FlaggedIpItem>   flaggedIps  = FXCollections.observableArrayList();

    private FilteredList<MyWhitelistItem> filteredMyWl;

    // Controls handed over from MainController via bind*()
    private TableView<MyWhitelistItem>  myWhitelistTable;
    private TextField tfNewIp, tfNewMac, tfNewLabel, tfFilter;

    private TableView<FlaggedIpItem> flaggedIpTable;
    private CheckBox cbSelectAllFlagged;
    private Label    lblFlaggedCount;

    public WhitelistPanelManager(Supplier<DataLoader> dataLoader,
                                 Supplier<BackendClient> backend,
                                 BooleanSupplier ready,
                                 Consumer<String> status) {
        this.dataLoader = dataLoader;
        this.backend    = backend;
        this.ready      = ready;
        this.status     = status;
    }

    // ── BINDING ─────────────────────────────────────────────────────────────

    public void bindMyWhitelist(TableView<MyWhitelistItem> table,
                                TableColumn<MyWhitelistItem, String> colIp,
                                TableColumn<MyWhitelistItem, String> colMac,
                                TableColumn<MyWhitelistItem, String> colLabel,
                                TableColumn<MyWhitelistItem, String> colAddedAt,
                                TextField tfNewIp, TextField tfNewMac,
                                TextField tfNewLabel, TextField tfFilter) {
        this.myWhitelistTable = table;
        this.tfNewIp    = tfNewIp;
        this.tfNewMac   = tfNewMac;
        this.tfNewLabel = tfNewLabel;
        this.tfFilter   = tfFilter;

        colIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colMac    .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colLabel  .setCellValueFactory(new PropertyValueFactory<>("label"));
        colAddedAt.setCellValueFactory(new PropertyValueFactory<>("addedAt"));
        colIp.setCellFactory(col -> cyanCell());
        filteredMyWl = new FilteredList<>(myWlEntries, p -> true);
        table.setItems(filteredMyWl);
        table.setPlaceholder(new Label("No trusted devices."));

        tfFilter.textProperty().addListener((obs, o, n) -> applyFilter());
    }

    public void bindFlaggedIps(TableView<FlaggedIpItem> table,
                               TableColumn<FlaggedIpItem, Boolean> colSel,
                               TableColumn<FlaggedIpItem, String>  colIp,
                               TableColumn<FlaggedIpItem, String>  colMac,
                               TableColumn<FlaggedIpItem, String>  colThreat,
                               TableColumn<FlaggedIpItem, String>  colProto,
                               TableColumn<FlaggedIpItem, Integer> colHits,
                               TableColumn<FlaggedIpItem, String>  colSeen,
                               CheckBox cbSelectAll, Label lblCount) {
        this.flaggedIpTable     = table;
        this.cbSelectAllFlagged = cbSelectAll;
        this.lblFlaggedCount    = lblCount;

        colSel   .setCellValueFactory(new PropertyValueFactory<>("selected"));
        colSel   .setCellFactory(col -> checkBoxCell());
        colIp    .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colMac   .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colThreat.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colProto .setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colHits  .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colSeen  .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colThreat.setCellFactory(col -> amberCell());
        colHits  .setCellFactory(col -> hitCountCell());
        table.setItems(flaggedIps);
        table.setPlaceholder(new Label("No flagged IPs."));
    }

    // ── LOADING / FILTERING ─────────────────────────────────────────────────

    public void reload() {
        dataLoader.get().loadWhitelist(this::onWhitelistLoaded, e -> {});
    }

    public void onWhitelistLoaded(List<MyWhitelistItem> my,
                                  List<FlaggedIpItem> flagged) {
        myWlEntries.setAll(my);
        flaggedIps .setAll(flagged);
        lblFlaggedCount.setText("Flagged IPs — " + flagged.size() + " pending");
    }

    private void applyFilter() {
        String f = tfFilter.getText().toLowerCase().trim();
        filteredMyWl.setPredicate(w ->
                f.isEmpty()
                || w.getIp().toLowerCase().contains(f)
                || (w.getMac()   != null && w.getMac().toLowerCase().contains(f))
                || (w.getLabel() != null && w.getLabel().toLowerCase().contains(f)));
    }

    // ── MY WHITELIST ACTIONS ────────────────────────────────────────────────

    public void addMyEntry() {
        if (!ready.getAsBoolean()) return;
        String ip = tfNewIp.getText().trim();
        if (ip.isEmpty()) return;
        dataLoader.get().submit("ids-add-wl",
                () -> backend.get().addMyWhitelistEntry(ip, tfNewMac.getText().trim(), tfNewLabel.getText().trim()),
                () -> {
                    tfNewIp.clear(); tfNewMac.clear(); tfNewLabel.clear();
                    reload();
                },
                msg -> status.accept("Add failed: " + msg));
    }

    public void deleteSelectedMyEntry() {
        MyWhitelistItem sel = myWhitelistTable.getSelectionModel().getSelectedItem();
        if (sel == null || !ready.getAsBoolean()) return;
        dataLoader.get().submit("ids-del-wl",
                () -> backend.get().deleteMyWhitelistEntry(sel.getId()),
                this::reload,
                msg -> status.accept("Delete failed: " + msg));
    }

    // ── FLAGGED IP ACTIONS ──────────────────────────────────────────────────

    public void toggleSelectAllFlagged() {
        boolean v = cbSelectAllFlagged.isSelected();
        flaggedIps.forEach(i -> i.setSelected(v));
        flaggedIpTable.refresh();
    }

    public void acceptSelectedFlagged() {
        if (!ready.getAsBoolean()) return;
        var selected = flaggedIps.stream().filter(FlaggedIpItem::isSelected).toList();
        if (selected.isEmpty()) return;
        dataLoader.get().submit("ids-accept-flagged",
                () -> { for (var i : selected)
                    backend.get().addMyWhitelistEntry(i.getIp(), i.getMac(), "Accepted from " + i.getThreatType()); },
                () -> { cbSelectAllFlagged.setSelected(false); reload(); },
                msg -> status.accept("Accept failed: " + msg));
    }

    public void clearFlaggedSelection() {
        flaggedIps.forEach(i -> i.setSelected(false));
        cbSelectAllFlagged.setSelected(false);
        flaggedIpTable.refresh();
    }

    // ── CELL FACTORIES ──────────────────────────────────────────────────────

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

    private <T> TableCell<T, Boolean> checkBoxCell() {
        return new TableCell<>() {
            private final CheckBox cb = new CheckBox();
            @Override protected void updateItem(Boolean val, boolean empty) {
                super.updateItem(val, empty);
                if (empty) { setGraphic(null); return; }
                T item = getTableView().getItems().get(getIndex());
                if (item instanceof FlaggedIpItem f) {
                    cb.setSelected(f.isSelected());
                    cb.setOnAction(e -> f.setSelected(cb.isSelected()));
                }
                setGraphic(cb);
            }
        };
    }
}
