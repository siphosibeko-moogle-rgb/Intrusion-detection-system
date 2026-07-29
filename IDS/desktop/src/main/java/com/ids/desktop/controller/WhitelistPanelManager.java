package com.ids.desktop.controller;

import com.ids.desktop.model.FlaggedIpItem;
import com.ids.desktop.model.MyWhitelistItem;
import com.ids.desktop.model.TrustedNetworkItem;
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
 * Owns the three whitelist views (My Whitelist — Trusted Devices,
 * Trusted Networks — provider CIDR ranges, and Flagged IPs): table
 * wiring, filtering, and every add/accept/remove action against the
 * backend.
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

    private final ObservableList<MyWhitelistItem>     myWlEntries     = FXCollections.observableArrayList();
    private final ObservableList<TrustedNetworkItem>  trustedNetworks = FXCollections.observableArrayList();
    private final ObservableList<FlaggedIpItem>       flaggedIps      = FXCollections.observableArrayList();

    private FilteredList<MyWhitelistItem>    filteredMyWl;
    private FilteredList<TrustedNetworkItem> filteredTrustedNets;

    // Controls handed over from MainController via bind*()
    private TableView<MyWhitelistItem>  myWhitelistTable;
    private TextField tfNewIp, tfNewMac, tfNewLabel, tfFilter;

    private TableView<TrustedNetworkItem> trustedNetworkTable;
    private TextField tfNewTnCidr, tfNewTnProvider, tfNewTnCategory;
    private CheckBox  cbNewTnSuppressBeaconing;

    private TableView<FlaggedIpItem> flaggedIpTable;
    private CheckBox cbSelectAllFlagged;
    private Label    lblFlaggedCount;
    private Tab      triageTab;

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

        // Label is the free-text column; the rest have bounded content.
        TableLayout.constrain(table);
        TableLayout.bounded(colIp,      100, 120, 150);
        TableLayout.bounded(colMac,     120, 135, 155);
        TableLayout.flex   (colLabel,   120, 220);
        TableLayout.bounded(colAddedAt, 110, 140, 180);

        filteredMyWl = new FilteredList<>(myWlEntries, p -> true);
        table.setItems(filteredMyWl);
        table.setPlaceholder(new Label("No trusted devices."));

        tfFilter.textProperty().addListener((obs, o, n) -> applyFilter());
    }

    public void bindTrustedNetworks(TableView<TrustedNetworkItem> table,
                                    TableColumn<TrustedNetworkItem, String>  colCidr,
                                    TableColumn<TrustedNetworkItem, String>  colProvider,
                                    TableColumn<TrustedNetworkItem, String>  colCategory,
                                    TableColumn<TrustedNetworkItem, Boolean> colEnabled,
                                    TableColumn<TrustedNetworkItem, Boolean> colSuppress,
                                    TextField tfCidr, TextField tfProvider,
                                    TextField tfCategory, CheckBox cbSuppressBeaconing) {
        this.trustedNetworkTable      = table;
        this.tfNewTnCidr              = tfCidr;
        this.tfNewTnProvider          = tfProvider;
        this.tfNewTnCategory          = tfCategory;
        this.cbNewTnSuppressBeaconing = cbSuppressBeaconing;

        colCidr    .setCellValueFactory(new PropertyValueFactory<>("cidr"));
        colProvider.setCellValueFactory(new PropertyValueFactory<>("provider"));
        colCategory.setCellValueFactory(new PropertyValueFactory<>("category"));
        colEnabled .setCellValueFactory(new PropertyValueFactory<>("enabled"));
        colSuppress.setCellValueFactory(new PropertyValueFactory<>("suppressBeaconing"));
        colCidr.setCellFactory(col -> cyanCell());
        colEnabled .setCellFactory(col -> yesNoCell(false));
        // Amber "Yes": suppressing beaconing for a range is a deliberate
        // security trade-off, so it should stand out in the table.
        colSuppress.setCellFactory(col -> yesNoCell(true));

        // Provider is the free-text column; a CIDR is at most 18 chars.
        TableLayout.constrain(table);
        TableLayout.bounded(colCidr,     120, 150, 180);
        TableLayout.flex   (colProvider, 110, 180);
        TableLayout.bounded(colCategory,  90, 120, 160);
        TableLayout.bounded(colEnabled,   70,  80, 100);
        TableLayout.bounded(colSuppress, 100, 140, 170);

        filteredTrustedNets = new FilteredList<>(trustedNetworks, p -> true);
        table.setItems(filteredTrustedNets);
        table.setPlaceholder(new Label("No trusted networks."));
    }

    public void bindFlaggedIps(TableView<FlaggedIpItem> table,
                               TableColumn<FlaggedIpItem, Boolean> colSel,
                               TableColumn<FlaggedIpItem, String>  colIp,
                               TableColumn<FlaggedIpItem, String>  colMac,
                               TableColumn<FlaggedIpItem, String>  colOrg,
                               TableColumn<FlaggedIpItem, String>  colThreat,
                               TableColumn<FlaggedIpItem, String>  colSeverity,
                               TableColumn<FlaggedIpItem, String>  colProto,
                               TableColumn<FlaggedIpItem, Integer> colHits,
                               TableColumn<FlaggedIpItem, String>  colSeen,
                               CheckBox cbSelectAll, Label lblCount) {
        this.flaggedIpTable     = table;
        this.cbSelectAllFlagged = cbSelectAll;
        this.lblFlaggedCount    = lblCount;

        colSel     .setCellValueFactory(new PropertyValueFactory<>("selected"));
        colSel     .setCellFactory(col -> checkBoxCell());
        colIp      .setCellValueFactory(new PropertyValueFactory<>("ip"));
        colMac     .setCellValueFactory(new PropertyValueFactory<>("mac"));
        colOrg     .setCellValueFactory(new PropertyValueFactory<>("organization"));
        colThreat  .setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colSeverity.setCellValueFactory(new PropertyValueFactory<>("severity"));
        colProto   .setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colHits    .setCellValueFactory(new PropertyValueFactory<>("hits"));
        colSeen    .setCellValueFactory(new PropertyValueFactory<>("lastSeen"));
        colOrg     .setCellFactory(col -> organizationCell());
        colThreat  .setCellFactory(col -> amberCell());
        colSeverity.setCellFactory(col -> severityCell());
        colHits    .setCellFactory(col -> hitCountCell());

        // Organization is the free-text column here; it already has its own
        // cell factory (organizationCell), so it gets width hints only.
        TableLayout.constrain(table);
        TableLayout.bounded(colSel,       34,  36,  42);
        TableLayout.bounded(colIp,       100, 120, 150);
        TableLayout.bounded(colMac,      120, 135, 155);
        TableLayout.flex   (colOrg,      120, 180);
        TableLayout.bounded(colThreat,   110, 150, 240);
        TableLayout.bounded(colSeverity,  70,  85, 110);
        TableLayout.bounded(colProto,     60,  75, 100);
        TableLayout.bounded(colHits,      55,  65,  95);
        TableLayout.bounded(colSeen,     100, 120, 160);

        table.setItems(flaggedIps);
        table.setPlaceholder(new Label("No flagged IPs."));
    }

    /** The top-level Triage tab whose title shows the pending count as a badge. */
    public void bindTriageTab(Tab triageTab) {
        this.triageTab = triageTab;
    }

    // ── LOADING / FILTERING ─────────────────────────────────────────────────

    public void reload() {
        reloadWhitelists();
        dataLoader.get().loadTrustedNetworks(trustedNetworks::setAll,
                msg -> status.accept("Trusted networks load failed: " + msg));
    }

    /** Trusted devices + flagged IPs only — polled every 30s so the Flagged
     *  IPs table updates itself (new detections, async org lookups landing)
     *  without clearing the trusted-networks table's row selection. */
    public void reloadWhitelists() {
        dataLoader.get().loadWhitelist(this::onWhitelistLoaded, e -> {});
    }

    public void onWhitelistLoaded(List<MyWhitelistItem> my,
                                  List<FlaggedIpItem> flagged) {
        myWlEntries.setAll(my);
        // Carry checkbox selections across the periodic reload — otherwise
        // the 30s auto-refresh would silently untick rows mid-triage.
        java.util.Set<String> selectedIps = new java.util.HashSet<>();
        for (FlaggedIpItem i : flaggedIps) if (i.isSelected()) selectedIps.add(i.getIp());
        flaggedIps.setAll(flagged);
        if (!selectedIps.isEmpty()) {
            for (FlaggedIpItem i : flaggedIps) {
                if (selectedIps.contains(i.getIp())) i.setSelected(true);
            }
        }
        lblFlaggedCount.setText("Flagged IPs — " + flagged.size() + " pending");
        if (triageTab != null) triageTab.setText("Triage (" + flagged.size() + ")");
    }

    private void applyFilter() {
        String f = tfFilter.getText().toLowerCase().trim();
        filteredMyWl.setPredicate(w ->
                f.isEmpty()
                || w.getIp().toLowerCase().contains(f)
                || (w.getMac()   != null && w.getMac().toLowerCase().contains(f))
                || (w.getLabel() != null && w.getLabel().toLowerCase().contains(f)));
        if (filteredTrustedNets != null) {
            filteredTrustedNets.setPredicate(t ->
                    f.isEmpty()
                    || (t.getCidr()     != null && t.getCidr().toLowerCase().contains(f))
                    || (t.getProvider() != null && t.getProvider().toLowerCase().contains(f))
                    || (t.getCategory() != null && t.getCategory().toLowerCase().contains(f)));
        }
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

    // ── TRUSTED NETWORK ACTIONS ─────────────────────────────────────────────

    public void addTrustedNetwork() {
        if (!ready.getAsBoolean()) return;
        String cidr     = tfNewTnCidr.getText().trim();
        String provider = tfNewTnProvider.getText().trim();
        if (cidr.isEmpty() || provider.isEmpty()) {
            status.accept("Trusted network needs a CIDR and a provider.");
            return;
        }
        String  category = tfNewTnCategory.getText().trim();
        boolean suppress = cbNewTnSuppressBeaconing.isSelected();
        dataLoader.get().submit("ids-add-trusted-net",
                () -> backend.get().addTrustedNetwork(cidr, provider, category, suppress),
                () -> {
                    tfNewTnCidr.clear(); tfNewTnProvider.clear(); tfNewTnCategory.clear();
                    cbNewTnSuppressBeaconing.setSelected(false);
                    reload();
                },
                msg -> status.accept("Add trusted network failed: " + msg));
    }

    public void deleteSelectedTrustedNetwork() {
        TrustedNetworkItem sel = trustedNetworkTable.getSelectionModel().getSelectedItem();
        if (sel == null || !ready.getAsBoolean()) return;
        dataLoader.get().submit("ids-del-trusted-net",
                () -> backend.get().deleteTrustedNetwork(sel.getId()),
                this::reload,
                msg -> status.accept("Delete trusted network failed: " + msg));
    }

    public void syncTrustedNetworkFeeds() {
        if (!ready.getAsBoolean()) return;
        status.accept("Syncing provider feeds… (can take up to a minute)");
        // submit() only reports success/failure, so smuggle the summary out
        // through a holder — the callback runs on the FX thread after the
        // background call finished, so this is safe.
        final String[] summary = new String[1];
        dataLoader.get().submit("ids-sync-trusted-nets",
                () -> summary[0] = backend.get().syncTrustedNetworkFeeds(),
                () -> { status.accept("Feed sync: " + summary[0]); reload(); },
                msg -> status.accept("Feed sync failed: " + msg));
    }

    public void toggleSelectedTrustedNetwork() {
        TrustedNetworkItem sel = trustedNetworkTable.getSelectionModel().getSelectedItem();
        if (sel == null || !ready.getAsBoolean()) return;
        boolean enable = !sel.isEnabled();
        dataLoader.get().submit("ids-toggle-trusted-net",
                () -> backend.get().setTrustedNetworkEnabled(sel.getId(), enable),
                this::reload,
                msg -> status.accept("Toggle trusted network failed: " + msg));
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

    /** Organization column: real org names in blue, "Unknown"/"Private (LAN)"
     *  muted; ASN + country surface as a tooltip rather than extra columns. */
    private TableCell<FlaggedIpItem, String> organizationCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null || s.isBlank()) {
                    setText(null); setTooltip(null); setStyle(""); return;
                }
                setText(s);
                boolean known = !"Unknown".equals(s) && !"Private (LAN)".equals(s);
                setStyle(known ? "-fx-text-fill:#60a5fa; -fx-font-weight:bold;"
                               : "-fx-text-fill:#6b7280;");
                Tooltip tip = null;
                if (getIndex() >= 0 && getIndex() < getTableView().getItems().size()) {
                    FlaggedIpItem row = getTableView().getItems().get(getIndex());
                    StringBuilder sb = new StringBuilder();
                    if (row.getAsn()     != null && !row.getAsn().isBlank())
                        sb.append("ASN: ").append(row.getAsn());
                    if (row.getCountry() != null && !row.getCountry().isBlank())
                        sb.append(sb.length() > 0 ? "\n" : "").append("Country: ").append(row.getCountry());
                    if (sb.length() > 0) tip = new Tooltip(sb.toString());
                }
                setTooltip(tip);
            }
        };
    }

    private <T> TableCell<T, String> severityCell() {
        return new TableCell<>() {
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null) { setText(null); setStyle(""); return; }
                setText(s);
                setStyle(com.ids.desktop.util.SeverityStyle.toStyle(s));
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

    /** Yes/No cell for boolean columns. warnOnYes renders Yes in amber
     *  (used for Suppress Beaconing, where "Yes" is a security trade-off). */
    private <T> TableCell<T, Boolean> yesNoCell(boolean warnOnYes) {
        return new TableCell<>() {
            @Override protected void updateItem(Boolean v, boolean empty) {
                super.updateItem(v, empty);
                if (empty || v == null) { setText(null); setStyle(""); return; }
                setText(v ? "Yes" : "No");
                setStyle(v
                        ? (warnOnYes ? "-fx-text-fill:#f59e0b; -fx-font-weight:bold;"
                                     : "-fx-text-fill:#22c55e; -fx-font-weight:bold;")
                        : "-fx-text-fill:#6b7280;");
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
