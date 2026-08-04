package com.ids.mobile.util;

import android.os.Handler;
import android.os.Looper;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Poller — one background thread, fixed-delay repeat, results delivered on the
 * main thread.
 *
 * WHY THIS CLASS EXISTS
 * ---------------------
 * This is the direct Android counterpart of the desktop HealthPoller, and it
 * exists for the same reason: a screen that refreshes itself must own exactly
 * one thread and must be able to give it back. The desktop client shipped a
 * real bug where re-login left the old poller running alongside the new one.
 * On a phone that failure mode is worse — a leaked poller keeps hitting the
 * network while the app is backgrounded and drains the battery invisibly.
 *
 * The contract that prevents it: start() in onResume(), stop() in onPause().
 * start() calls stop() first, so double-start cannot leak.
 *
 * scheduleWithFixedDelay (not scheduleAtFixedRate) is deliberate. Fixed-delay
 * measures the gap AFTER the task finishes. If the backend is slow or
 * unreachable and a call takes the full 10s timeout, fixed-rate would queue up
 * a backlog of overdue executions and fire them back-to-back the moment the
 * network recovers. Fixed-delay simply spaces them out and self-throttles.
 */
public class Poller {

    /** Result callback, always invoked on the main thread. */
    public interface Callback<T> {
        void onSuccess(T result);
        void onError(Exception e);
    }

    /** The blocking work, run on the poller thread. */
    public interface Task<T> {
        T run() throws Exception;
    }

    private final Handler main = new Handler(Looper.getMainLooper());
    private final String threadName;
    private final long periodSeconds;

    private ScheduledExecutorService scheduler;

    public Poller(String threadName, long periodSeconds) {
        this.threadName = threadName;
        this.periodSeconds = periodSeconds;
    }

    /** Starts (or restarts) the loop. Fires once immediately, then on the period. */
    public synchronized <T> void start(final Task<T> task, final Callback<T> callback) {
        stop();

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, threadName);
            t.setDaemon(true);   // never hold the process open
            return t;
        });

        final ScheduledExecutorService mine = scheduler;

        mine.scheduleWithFixedDelay(() -> {
            try {
                final T result = task.run();
                // Guard against a result arriving after stop(): the fragment
                // view may already be gone, and touching it would crash.
                if (mine.isShutdown()) return;
                main.post(() -> callback.onSuccess(result));
            } catch (Exception e) {
                if (mine.isShutdown()) return;
                main.post(() -> callback.onError(e));
            }
        }, 0, periodSeconds, TimeUnit.SECONDS);
    }

    /** Idempotent. Safe to call when never started. */
    public synchronized void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    public synchronized boolean isRunning() {
        return scheduler != null;
    }
}
