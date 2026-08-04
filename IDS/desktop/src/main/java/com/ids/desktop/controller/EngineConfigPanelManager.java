package com.ids.desktop.controller;

import com.ids.desktop.service.EngineConfig;
import com.ids.desktop.service.EngineConfigClient;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.CheckBoxListCell;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Owns the Config sub-tab's Section 2 — the engine's host-local config:
 * capture interfaces (checkbox list, Section 2a) plus a fixed set of
 * structured network/capture settings (form, Section 2b). Sibling of
 * WhitelistPanelManager / CaseBoardManager rather than an extension of
 * WhitelistPanelManager: that class is all DB-backed CRUD-table wiring
 * against BackendClient, whereas this talks to a different client
 * (EngineConfigClient, engine loopback), has no table CRUD, and has distinct
 * "engine not reachable" failure semantics. Keeping it separate is the lowest-
 * coupling fit with the existing decomposition.
 *
 * <p>Section 1 (the "trust data is live, edit it in the other tabs" pointer) is
 * static FXML — no logic — so it isn't managed here.
 *
 * <p>The capture-interface list and the settings form are two independent
 * concerns with their own Save buttons (one writer per key — see
 * EngineConfigServer), but share a single Reload: GET /engine/config returns
 * both in one response.
 *
 * <p>All ObservableList/control mutations happen inside DataLoader.submit's
 * success callback, which DataLoader dispatches via Platform.runLater — so
 * FX controls are only ever touched on the FX thread. The HTTP GET/POST run
 * on submit's background thread; the FX thread never blocks on them.
 */
public class EngineConfigPanelManager {

    private final Supplier<DataLoader>  dataLoader;
    private final EngineConfigClient    client;
    private final Consumer<String>      status;   // header status echo

    private final ObservableList<InterfaceChoice> choices = FXCollections.observableArrayList();

    // Controls handed over from MainController via bind()
    private Label            lblCurrent;
    private ListView<InterfaceChoice> listView;
    private Label            lblBanner;

    // Settings form (Section 2b). Keyed by the exact property-key strings
    // EngineConfigServer.ALLOWED_SETTINGS_KEYS uses — the same map both
    // populates the form on load and is read back on save, so there's no
    // separate name for each field to keep in sync by hand.
    private Map<String, TextField> settingsFields;
    private ComboBox<String>       cbCaptureMode;

    // EngineConfigClient has no per-login state, so it's passed as a plain
    // instance; DataLoader is recreated on login, hence the Supplier (same
    // convention as the other panel managers).
    public EngineConfigPanelManager(Supplier<DataLoader> dataLoader,
                                    EngineConfigClient client,
                                    Consumer<String> status) {
        this.dataLoader = dataLoader;
        this.client     = client;
        this.status     = status;
    }

    // ── BINDING ─────────────────────────────────────────────────────────────

    public void bind(Label lblCurrent, ListView<InterfaceChoice> listView, Label lblBanner,
                      TextField tfSubnet, TextField tfGateway, TextField tfDockerSubnets,
                      TextField tfTrustedScanners, TextField tfBeaconDestinations,
                      TextField tfDhcpMacs, ComboBox<String> cbCaptureMode) {
        this.lblCurrent = lblCurrent;
        this.listView   = listView;
        this.lblBanner  = lblBanner;
        this.cbCaptureMode = cbCaptureMode;

        this.settingsFields = new LinkedHashMap<>();
        settingsFields.put("network.subnet", tfSubnet);
        settingsFields.put("network.gateway", tfGateway);
        settingsFields.put("network.docker.subnets", tfDockerSubnets);
        settingsFields.put("network.trusted.scanners", tfTrustedScanners);
        settingsFields.put("network.beacon.trusted.destinations", tfBeaconDestinations);
        settingsFields.put("network.dhcp.trusted.servers", tfDhcpMacs);

        cbCaptureMode.setItems(FXCollections.observableArrayList("PROMISCUOUS", "NORMAL"));

        listView.setItems(choices);
        // CheckBoxListCell binds each row's checkbox to its selectedProperty;
        // the default converter renders InterfaceChoice.toString().
        listView.setCellFactory(CheckBoxListCell.forListView(InterfaceChoice::selectedProperty));
        listView.setPlaceholder(new Label("No interfaces loaded — press Reload with the engine running."));
        hideBanner();
    }

    // ── LOAD / SAVE ─────────────────────────────────────────────────────────

    /** GET the engine's current config + host interfaces and repopulate both the list and the form. */
    public void reload() {
        // Holder smuggles the background result to the FX-thread success
        // callback — same pattern WhitelistPanelManager.syncTrustedNetworkFeeds
        // uses, since submit() itself only signals success/failure.
        final EngineConfig[] holder = new EngineConfig[1];
        dataLoader.get().submit("ids-engine-config-load",
                () -> holder[0] = client.fetchConfig(),
                () -> onLoaded(holder[0]),
                // A failed load is almost always "engine not running / not co-located":
                // show it as a non-alarming info banner, not a red error.
                msg -> banner(msg, Kind.INFO));
    }

    private void onLoaded(EngineConfig cfg) {
        String current = cfg.getCaptureInterfaces();
        lblCurrent.setText(displayValue(current));

        Set<String> configured = new HashSet<>();
        if (current != null) {
            for (String s : current.split(",")) {
                String t = s.trim();
                if (!t.isEmpty()) configured.add(t.toLowerCase());
            }
        }
        List<InterfaceChoice> rows = new ArrayList<>();
        for (EngineConfig.HostInterface hi : cfg.getHostInterfaces()) {
            boolean checked = configured.contains(hi.getName().toLowerCase());
            rows.add(new InterfaceChoice(hi.getName(), hi.getIp(), checked));
        }
        choices.setAll(rows);   // FX thread (submit success callback)

        // Section 2b: populate the settings form. "" (absent key) is the
        // consistent blank representation on both read and write — see
        // saveSettings() below and EngineConfigServer's "leave absent if
        // blank" write policy.
        Map<String, String> settings = cfg.getSettings();
        for (Map.Entry<String, TextField> e : settingsFields.entrySet()) {
            e.getValue().setText(settings.getOrDefault(e.getKey(), ""));
        }
        String mode = settings.getOrDefault("capture.mode", "");
        cbCaptureMode.setValue(mode.isBlank() ? "PROMISCUOUS" : mode);

        hideBanner();           // clear any prior "not reachable" message
    }

    /** POST the checked interfaces and make the restart requirement unmissable. */
    public void save() {
        List<String> selected = new ArrayList<>();
        for (InterfaceChoice c : choices) {
            if (c.isSelected()) selected.add(c.getName());
        }
        final boolean[] restartRequired = new boolean[1];
        dataLoader.get().submit("ids-engine-config-save",
                () -> restartRequired[0] = client.saveCaptureInterfaces(selected),
                () -> {
                    lblCurrent.setText(displayValue(String.join(",", selected)));
                    // restartRequired is read from the engine but is always true
                    // today — the whole point of this section is that the change
                    // is inert until the engine restarts, so say so loudly.
                    banner("Saved. The engine must be RESTARTED for interface changes to take effect.",
                           Kind.SUCCESS);
                    status.accept("Engine capture interfaces saved — restart the engine to apply.");
                },
                msg -> banner("Save failed: " + msg, Kind.ERROR));
    }

    /**
     * POST the settings form. Independent of {@link #save()} — this never
     * reads or writes {@code ids.capture.interfaces}. Server-side validation
     * mirrors the engine's own parser (see EngineConfigServer); a rejected
     * value comes back as an error naming the bad key, and nothing is
     * written — the form fields are left as the user typed them so they can
     * fix the flagged value and retry.
     */
    public void saveSettings() {
        Map<String, String> values = new LinkedHashMap<>();
        for (Map.Entry<String, TextField> e : settingsFields.entrySet()) {
            String text = e.getValue().getText();
            values.put(e.getKey(), text == null ? "" : text.trim());
        }
        String mode = cbCaptureMode.getValue();
        values.put("capture.mode", mode == null ? "" : mode);

        final boolean[] restartRequired = new boolean[1];
        dataLoader.get().submit("ids-engine-settings-save",
                () -> restartRequired[0] = client.saveSettings(values),
                () -> {
                    banner("Saved. The engine must be RESTARTED for these settings to take effect.",
                           Kind.SUCCESS);
                    status.accept("Engine settings saved — restart the engine to apply.");
                },
                msg -> banner("Save failed: " + msg, Kind.ERROR));
    }

    // ── HELPERS ─────────────────────────────────────────────────────────────

    private String displayValue(String raw) {
        return (raw == null || raw.isBlank())
                ? "(none — engine auto-discovers all interfaces)"
                : raw;
    }

    private enum Kind { SUCCESS, ERROR, INFO }

    private void banner(String text, Kind kind) {
        lblBanner.setText(text);
        lblBanner.setVisible(true);
        lblBanner.setManaged(true);
        String base = "-fx-padding:8; -fx-background-radius:4; ";
        lblBanner.setStyle(switch (kind) {
            case SUCCESS -> base + "-fx-font-weight:bold; -fx-text-fill:#052e16; -fx-background-color:#22c55e;";
            case ERROR   -> base + "-fx-font-weight:bold; -fx-text-fill:white;   -fx-background-color:#ef4444;";
            // INFO (e.g. engine unreachable): amber, deliberately non-alarming.
            case INFO    -> base + "-fx-text-fill:#0f172a; -fx-background-color:#fcd34d;";
        });
    }

    private void hideBanner() {
        lblBanner.setText("");
        lblBanner.setVisible(false);
        lblBanner.setManaged(false);   // collapse so it takes no layout space
    }

    // ── DEFERRED (not implemented this session — see Prompt 2 notes) ──────────
    // 1. Migrating local subnet / gateway / trusted-DHCP-MAC out of the engine's
    //    properties file into the DB config store so they sync live like Trusted
    //    Networks. Correct long-term home, but a backend change for its own session.
    // 2. Backend-proxied, cross-host engine config (configure a remote sensor).
    //    Needs an authenticated backend->engine channel; deliberately out of scope,
    //    which is why this client hardcodes the 127.0.0.1 loopback endpoint.
}
