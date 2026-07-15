package com.ids.desktop.controller;

import com.ids.desktop.model.CaseItem;
import com.ids.desktop.service.BackendClient;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;

import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/**
 * Owns the forensic-cases board: table wiring, filtering, the create/close
 * actions, and open-detail navigation (double-click + context menu).
 *
 * Extracted from MainController — same decomposition pattern as
 * AlertTableManager / WhitelistPanelManager. The @FXML controls stay in
 * MainController (FXML injection target) and are handed over via bind().
 */
public class CaseBoardManager {

    /** Navigation callback: (caseId, caseNumber) → open the detail panel. */
    @FunctionalInterface
    public interface CaseOpener { void open(long caseId, String caseNumber); }

    private final Supplier<DataLoader>    dataLoader;
    private final Supplier<BackendClient> backend;
    private final BooleanSupplier         ready;
    private final CaseOpener              opener;

    private final ObservableList<CaseItem> caseEntries = FXCollections.observableArrayList();
    private FilteredList<CaseItem> filteredCases;

    private TableView<CaseItem> casesTable;
    private TextField tfFilterStatus, tfFilterIp;
    private TextField tfNewTitle, tfNewSuspectIp, tfNewSuspectMac;
    private ComboBox<String> cbNewSeverity;
    private Label lblStatus;

    public CaseBoardManager(Supplier<DataLoader> dataLoader,
                            Supplier<BackendClient> backend,
                            BooleanSupplier ready,
                            CaseOpener opener) {
        this.dataLoader = dataLoader;
        this.backend    = backend;
        this.ready      = ready;
        this.opener     = opener;
    }

    public void bind(TableView<CaseItem> table,
                     TableColumn<CaseItem, String> colNum,
                     TableColumn<CaseItem, String> colTitle,
                     TableColumn<CaseItem, String> colStatus,
                     TableColumn<CaseItem, String> colSeverity,
                     TableColumn<CaseItem, String> colSuspectIp,
                     TableColumn<CaseItem, String> colSuspectMac,
                     TableColumn<CaseItem, String> colThreatType,
                     TableColumn<CaseItem, String> colAssignedTo,
                     TableColumn<CaseItem, String> colOpenedAt,
                     TextField tfFilterStatus, TextField tfFilterIp,
                     TextField tfNewTitle, TextField tfNewSuspectIp,
                     TextField tfNewSuspectMac, ComboBox<String> cbNewSeverity,
                     Label lblStatus) {
        this.casesTable      = table;
        this.tfFilterStatus  = tfFilterStatus;
        this.tfFilterIp      = tfFilterIp;
        this.tfNewTitle      = tfNewTitle;
        this.tfNewSuspectIp  = tfNewSuspectIp;
        this.tfNewSuspectMac = tfNewSuspectMac;
        this.cbNewSeverity   = cbNewSeverity;
        this.lblStatus       = lblStatus;

        colNum       .setCellValueFactory(new PropertyValueFactory<>("caseNumber"));
        colTitle     .setCellValueFactory(new PropertyValueFactory<>("title"));
        colStatus    .setCellValueFactory(new PropertyValueFactory<>("status"));
        colSeverity  .setCellValueFactory(new PropertyValueFactory<>("severity"));
        colSuspectIp .setCellValueFactory(new PropertyValueFactory<>("suspectIp"));
        colSuspectMac.setCellValueFactory(new PropertyValueFactory<>("suspectMac"));
        colThreatType.setCellValueFactory(new PropertyValueFactory<>("threatType"));
        colAssignedTo.setCellValueFactory(new PropertyValueFactory<>("assignedTo"));
        colOpenedAt  .setCellValueFactory(new PropertyValueFactory<>("openedAt"));

        colStatus.setCellFactory(col -> new TableCell<>() {
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
        table.setItems(filteredCases);
        table.setPlaceholder(new Label("No forensic cases opened yet."));

        // Single- or double-click opens the detail panel; PRIMARY guard keeps
        // right-click (context menu) from also firing the opener
        table.setRowFactory(tv -> {
            TableRow<CaseItem> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (row.isEmpty()) return;
                if (event.getButton() != javafx.scene.input.MouseButton.PRIMARY) return;
                CaseItem item = row.getItem();
                if (item == null) return;
                opener.open(item.getId(), item.getCaseNumber());
            });
            return row;
        });

        // Context menu: open / close
        ContextMenu menu = new ContextMenu();
        MenuItem open = new MenuItem("Open Investigation");
        open.setOnAction(e -> {
            CaseItem selected = table.getSelectionModel().getSelectedItem();
            if (selected != null) opener.open(selected.getId(), selected.getCaseNumber());
        });
        MenuItem close = new MenuItem("Close Case");
        close.setOnAction(e -> closeSelectedCase());
        menu.getItems().addAll(open, close);
        table.setContextMenu(menu);

        tfFilterStatus.textProperty().addListener((obs, o, n) -> applyFilter());
        tfFilterIp    .textProperty().addListener((obs, o, n) -> applyFilter());
    }

    // ── LOADING / FILTERING ─────────────────────────────────────────────────

    public void reload() {
        dataLoader.get().loadCases(caseEntries::setAll,
                msg -> System.err.println("[Desktop] Cases load error: " + msg));
    }

    private void applyFilter() {
        String status = tfFilterStatus.getText().toLowerCase().trim();
        String ip     = tfFilterIp.getText().toLowerCase().trim();
        filteredCases.setPredicate(c -> {
            if (!status.isEmpty() && !c.getStatus().toLowerCase().contains(status)) return false;
            if (!ip.isEmpty()     && !c.getSuspectIp().toLowerCase().contains(ip))  return false;
            return true;
        });
    }

    // ── ACTIONS ─────────────────────────────────────────────────────────────

    public void createCase() {
        if (!ready.getAsBoolean()) return;
        String title = tfNewTitle.getText().trim();
        if (title.isEmpty()) { lblStatus.setText("Title is required"); return; }
        dataLoader.get().submit("ids-create-case",
                () -> backend.get().createCase(title, "",
                        tfNewSuspectIp.getText().trim(),
                        tfNewSuspectMac.getText().trim(),
                        cbNewSeverity.getValue(), ""),
                () -> {
                    tfNewTitle.clear(); tfNewSuspectIp.clear(); tfNewSuspectMac.clear();
                    lblStatus.setText("Case created");
                    reload();
                },
                msg -> lblStatus.setText("Failed: " + msg));
    }

    public void closeSelectedCase() {
        if (!ready.getAsBoolean()) return;
        CaseItem sel = casesTable.getSelectionModel().getSelectedItem();
        if (sel == null) { lblStatus.setText("Select a case first"); return; }
        dataLoader.get().submit("ids-close-case",
                () -> backend.get().updateCaseStatus(sel.getId(), "CLOSED", sel.getFindings()),
                () -> {
                    lblStatus.setText("Case closed");
                    reload();
                },
                msg -> lblStatus.setText("Failed: " + msg));
    }
}
