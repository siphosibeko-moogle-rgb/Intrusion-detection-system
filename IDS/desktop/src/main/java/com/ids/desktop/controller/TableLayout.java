package com.ids.desktop.controller;

import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;

/**
 * Shared column-sizing helpers so every table in the app behaves the same
 * way: columns fill the table width (no dead space on the right), columns
 * with bounded content stay near their natural size, and one free-text
 * column per table absorbs whatever width is left.
 */
final class TableLayout {

    private TableLayout() {}

    /** Columns share the table width instead of leaving unused space on the right. */
    static void constrain(TableView<?> table) {
        table.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY_FLEX_LAST_COLUMN);
    }

    /**
     * Bounded-content column (timestamps, severities, IPs, MACs, counts).
     * The max cap is what pushes surplus width into the table's flex column.
     */
    static void bounded(TableColumn<?, ?> col, double min, double pref, double max) {
        col.setMinWidth(min);
        col.setPrefWidth(pref);
        col.setMaxWidth(max);
    }

    /** Free-text column: absorbs all width the bounded columns don't claim. */
    static void flex(TableColumn<?, ?> col, double min, double pref) {
        col.setMinWidth(min);
        col.setPrefWidth(pref);
        col.setMaxWidth(Double.MAX_VALUE);
    }

    /**
     * Cell factory that mirrors the cell text into a hover tooltip, for
     * free-text columns whose content can never fully fit at any width.
     * Only for columns with no cell factory of their own — a second
     * setCellFactory silently replaces the first (e.g. the Source IP
     * hyperlink cells), so never combine this with a styled column.
     */
    static <S> void tooltipCells(TableColumn<S, String> col) {
        col.setCellFactory(c -> new TableCell<>() {
            private final Tooltip tip = new Tooltip();
            { tip.setWrapText(true); tip.setMaxWidth(480); }
            @Override protected void updateItem(String s, boolean empty) {
                super.updateItem(s, empty);
                if (empty || s == null || s.isBlank()) {
                    setText(null);
                    setTooltip(null);
                    return;
                }
                setText(s);
                tip.setText(s);
                setTooltip(tip);
            }
        });
    }
}
