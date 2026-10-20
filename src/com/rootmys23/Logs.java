package com.rootmys23;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/** 全局日志 + 状态，Activity 和 Service 之间唯一的通信通道。 */
public final class Logs {

    public interface Listener { void onLog(String line); }

    private static final int MAX = 3000;
    private static final ArrayDeque<String> LINES = new ArrayDeque<>();
    private static final List<Listener> LISTENERS = new CopyOnWriteArrayList<>();
    private static final SimpleDateFormat HMS =
            new SimpleDateFormat("HH:mm:ss", Locale.US);

    /** 顶部那一行大字状态。 */
    public static volatile String status = "空闲";
    public static volatile boolean running = false;
    /** adbd 弹了授权框：Activity 看到就把自己退到后台，否则会挡住弹窗。 */
    public static volatile boolean authNeeded = false;

    private Logs() {}

    /** 设备 uptime（秒）。排查「为什么这次开打晚了」全靠它。 */
    public static String uptime() {
        // 别读 /proc/uptime：untrusted_app 读 /proc 会被 SELinux 挡掉，
        // 之前满屏 t=?s 就是这么来的。elapsedRealtime 含深睡，等价内核 uptime。
        return String.valueOf(android.os.SystemClock.elapsedRealtime() / 1000);
    }

    public static void add(String s) {
        // 设备端脚本自己带时间戳，别叠两层
        String line = s.startsWith("[")
                ? s
                : "[" + HMS.format(new Date()) + " t=" + uptime() + "s] " + s;
        android.util.Log.i("rootmys23", line);
        synchronized (LINES) {
            LINES.addLast(line);
            while (LINES.size() > MAX) LINES.removeFirst();
        }
        for (Listener l : LISTENERS) {
            try { l.onLog(line); } catch (Exception ignored) {}
        }
    }

    public static void clear() {
        synchronized (LINES) { LINES.clear(); }
    }

    public static List<String> snapshot() {
        synchronized (LINES) { return new ArrayList<>(LINES); }
    }

    public static void subscribe(Listener l) { LISTENERS.add(l); }

    public static void unsubscribe(Listener l) { LISTENERS.remove(l); }

    public static void setStatus(String s) { status = s; }
}
