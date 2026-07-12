package com.ids.desktop.controller;

import com.ids.desktop.model.FlaggedIpItem;
import com.ids.desktop.model.MyWhitelistItem;
import com.ids.desktop.model.OrgWhitelistItem;
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
import java.util.stream.Collectors;

/**
 * Owns the three whitelist-related views (My Whitelist, Org Whitelist
 * accepted/pending, Flagged IPs): table wiring, filtering, and every
 * add/approve/remove action against the backend.
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
 */
public class WhitelistPanelManager {

    private final Supplier<DataLoader>    dataLoader;
    private final Supplier<BackendClient> backend;
    private final BooleanSupplier         ready;
    private final Consumer<String>        status;

    private final ObservableList<MyWhitelistItem>  myWlEntries    = FXCollections.observableArrayList();
    private final ObservableList<OrgWhitelistItem> orgAcceptedRaw = FXCollections.observableArrayList();
    private final ObservableList<OrgWhitelistItem> orgPendingRaw  = FXCollections.observableArrayList();
    private final ObservableList<FlaggedIpItem>    flaggedIps     = FXCollections.observableArrayList();

    private FilteredList<MyWhitelistItem>  filteredMyWl;
    private FilteredList<OrgWhitelistItem> orgAccepted, orgPending;

    // Controls handed over from MainController via bind*()
    private TableView<MyWhitelistItem>  myWhitelistTable;
    private TextField tfNewIp, tfNewMac, tfNewLabel, tfFilter;

    private TableView<FlaggedIpItem> flaggedIpTable;
    private CheckBox cbSelectAllFlagged;
    private Label    lblFlaggedCount;

    private TableView<OrgWhitelistItem> orgAcceptedTable, orgPendingTable;
    private CheckBox cbSelectAllPendingOrg;
    private Label    lblPendingOrgCount;

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

    public void bindOrgTables(TableView<OrgWhitelistItem> acceptedTable,
                              TableColumn<OrgWhitelistItem, String>  colAccIp,
                              TableColumn<OrgWhitelistItem, String>  colAccName,
                              TableColumn<OrgWhitelistItem, String>  colAccAsn,
                              TableColumn<OrgWhitelistItem, String>  colAccCountry,
                              TableColumn<OrgWhitelistItem, Integer> colAccHits,
                              TableColumn<OrgWhitelistItem, String>  colAccSeen,
                              TableView<OrgWhitelistItem> pendingTable,
                              TableColumn<OrgWhitelistItem, Boolean> colPendSel,
                              TableColumn<OrgWhitelistItem, String>  colPendIp,
                              TableColumn<OrgWhitelistItem, String>  colPendMac,
                              TableColumn<OrgWhitelistItem, String>  colPendName,
                              TableColumn<OrgWhitelistItem, String>  colPendAsn,
                              TableColumn<OrgWhitelistItem, String>  colPendCountry,
                              TableColumn<OrgWhitelistItem, Integer> colPendHits,
                              TableColumn<OrgWhitelistItem, String>  colPendSeen,
                              CheckBox cbSelectAllPending, Label lblPendingCount) {
        this.orgAcceptedTable      = acceptedTable;
        this.orgPendingTable       = pendingTable;
        this.cbSelectAllPendingOrg = cbSelectAllPending;
        this.lblPendingOrgCount    = lblPendingCount;

        colAccIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colAccName   .setCellValueFactory(new PropertyValueFactory<>("orgName"));
        colAccAsn    .setCellValueFactory(new PropertyValueFactory<>("asn"));
        colAccCountry.setCellValueFactory(new PropertyValueFactory<>("country"));
        colAccHits   .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colAccSeen   .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colAccIp.setCellFactory(col -> cyanCell());
        orgAccepted = new FilteredList<>(orgAcceptedRaw, p -> true);
        acceptedTable.setItems(orgAccepted);

        colPendSel    .setCellValueFactory(new PropertyValueFactory<>("selected"));
        colPendSel    .setCellFactory(col -> checkBoxCell());
        colPendIp     .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colPendMac    .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colPendName   .setCellValueFactory(new PropertyValueFactory<>("orgName"));
        colPendAsn    .setCellValueFactory(new PropertyValueFactory<>("asn"));
        colPendCountry.setCellValueFactory(new PropertyValueFactory<>("country"));
        colPendHits   .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colPendSeen   .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colPendHits.setCellFactory(col -> hitCountCell());
        orgPending = new FilteredList<>(orgPendingRaw, p -> true);
        pendingTable.setItems(orgPending);
        pendingTable.setPlaceholder(new Label("No pending organizations."));
    }

    // ── LOADING / FILTERING ─────────────────────────────────────────────────

    public void reload() {
        dataLoader.get().loadWhitelist(this::onWhitelistLoaded, e -> {});
    }

    public void onWhitelistLoaded(List<MyWhitelistItem> my,
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

    private void applyFilter() {
        String f = tfFilter.getText().toLowerCase().trim();
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

    // ── ORG WHITELIST ACTIONS ───────────────────────────────────────────────

    public void toggleSelectAllPendingOrgs() {
        boolean v = cbSelectAllPendingOrg.isSelected();
        orgPending.forEach(i -> i.setSelected(v));
        orgPendingTable.refresh();
    }

    public void acceptSelectedPendingOrgs() {
        if (!ready.getAsBoolean()) return;
        var selected = orgPending.stream().filter(OrgWhitelistItem::isSelected).toList();
        if (selected.isEmpty()) return;
        dataLoader.get().submit("ids-approve-orgs",
                () -> { for (var i : selected) backend.get().approveOrg(i.getId()); },
                () -> { cbSelectAllPendingOrg.setSelected(false); reload(); },
                msg -> status.accept("Approve failed: " + msg));
    }

    public void acceptAllPendingOrgs() {
        if (!ready.getAsBoolean()) return;
        dataLoader.get().submit("ids-approve-all",
                () -> backend.get().approveAllOrgs(),
                this::reload,
                msg -> status.accept("Approve all failed: " + msg));
    }

    public void removeSelectedPendingOrgs() {
        var selected = orgPending.stream().filter(OrgWhitelistItem::isSelected).toList();
        if (selected.isEmpty() || !ready.getAsBoolean()) return;
        dataLoader.get().submit("ids-del-pending",
                () -> { for (var i : selected) backend.get().deleteOrgEntry(i.getId()); },
                this::reload,
                msg -> status.accept("Remove failed: " + msg));
    }

    public void removeSelectedAcceptedOrg() {
        OrgWhitelistItem sel = orgAcceptedTable.getSelectionModel().getSelectedItem();
        if (sel == null || !ready.getAsBoolean()) return;
        dataLoader.get().submit("ids-del-accepted",
                () -> backend.get().deleteOrgEntry(sel.getId()),
                this::reload,
                msg -> status.accept("Remove failed: " + msg));
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
                } else if (item instanceof OrgWhitelistItem o) {
                    cb.setSelected(o.isSelected());
                    cb.setOnAction(e -> o.setSelected(cb.isSelected()));
                }
                setGraphic(cb);
            }
        };
    }
}
