package com.ids.desktop.controller;

import javafx.scene.effect.DropShadow;
import javafx.scene.paint.Color;

/**
 * Theme — single source of truth for the light SOC theme.
 *
 * WHY THIS EXISTS
 * ----------------
 * DashboardPanel already isolated its palette into local constants — good
 * pattern, wrong scope. CaseDetailPanel, IpInvestigationPanel, and
 * AlertGroupsPanel each have raw hex literals baked directly into dozens of
 * setStyle() calls. That works until you need to change the theme, at which
 * point every scattered literal is a place the change can be missed —
 * exactly the "silent misconfiguration" failure mode we keep running into
 * elsewhere in this app, just in CSS instead of Java config.
 *
 * This class doesn't introduce a stylesheet cascade (that's a bigger
 * refactor than a color swap justifies). It's a constants holder — every
 * panel keeps building its inline -fx-* strings, they just reference
 * Theme.BG_CARD instead of "#161b22". One place to change, many places
 * that read it.
 *
 * SEMANTIC SEPARATION
 * --------------------
 * STATUS colors (OK/WARN/ERROR/UNKNOWN) describe system health.
 * SEVERITY colors (CRITICAL/HIGH/MEDIUM/LOW) describe threat severity.
 * They are kept as separate palettes on purpose — reusing green for both
 * "database is healthy" and "low-severity threat" makes an analyst do a
 * double-take to figure out which one they're looking at.
 */
public final class Theme {

    private Theme() {} // constants only, never instantiated

    // ── Surfaces ─────────────────────────────────────────────────────────
    public static final String BG_ROOT   = "#f5f6f8"; // page background, very light gray
    public static final String BG_CARD   = "#ffffff"; // card/panel background, white
    public static final String BG_HOVER  = "#f0f2f5"; // row hover / subtle highlight
    public static final String BORDER    = "#e5e7eb"; // hairline borders on cards/tables

    // ── Text ─────────────────────────────────────────────────────────────
    public static final String TEXT_MAIN = "#111827"; // primary text, near-black
    public static final String TEXT_SUB  = "#6b7280"; // secondary/muted text
    public static final String TEXT_ON_ACCENT = "#ffffff"; // text on filled accent buttons

    // ── Accent ───────────────────────────────────────────────────────────
    public static final String ACCENT        = "#2563eb"; // primary blue
    public static final String ACCENT_HOVER  = "#1d4ed8"; // darker blue for :hover/:pressed
    public static final String ACCENT_MUTED  = "#dbeafe"; // pale blue for selected-row backgrounds

    // ── System status (health widgets) ──────────────────────────────────
    public static final String STATUS_OK      = "#22c55e"; // green — reserved for health only
    public static final String STATUS_WARN    = "#f59e0b"; // amber
    public static final String STATUS_ERROR   = "#ef4444"; // red
    public static final String STATUS_UNKNOWN = "#9ca3af"; // gray

    // ── Threat severity (alerts, cases, threat actors) ──────────────────
    public static final String SEVERITY_CRITICAL = "#ef4444"; // red — reserved for critical only
    public static final String SEVERITY_HIGH     = "#f97316"; // deep orange, visually distinct from medium
    public static final String SEVERITY_MEDIUM   = "#f59e0b"; // amber
    public static final String SEVERITY_LOW      = "#3b82f6"; // neutral blue — NOT green, see class doc

    // ── Utility: soft card shadow ────────────────────────────────────────
    /**
     * Standard soft drop shadow for elevated cards. Usage:
     *   myVBox.setEffect(Theme.cardShadow());
     * Kept as a method (not a shared static instance) because JavaFX
     * Effects are stateful per-node — sharing one DropShadow instance
     * across multiple nodes causes them to silently steal it from each
     * other (only the last node to render keeps the shadow).
     */
    public static DropShadow cardShadow() {
        DropShadow shadow = new DropShadow();
        shadow.setColor(Color.rgb(15, 23, 42, 0.08)); // near-black at 8% opacity
        shadow.setRadius(12);
        shadow.setOffsetY(2);
        shadow.setSpread(0.02);
        return shadow;
    }

    // ── Utility: standard rounded-card style string ─────────────────────
    /**
     * Common "white rounded card with hairline border" style, reused by
     * every panel container. Returns the -fx-* string; caller still needs
     * to call node.setEffect(Theme.cardShadow()) separately for the shadow
     * since JavaFX shadows are an Effect, not a CSS-string property here.
     */
    public static String cardStyle() {
        return "-fx-background-color: " + BG_CARD + "; "
                + "-fx-border-color: " + BORDER + "; "
                + "-fx-border-width: 1; "
                + "-fx-background-radius: 10; "
                + "-fx-border-radius: 10;";
    }
}