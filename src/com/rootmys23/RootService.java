package com.rootmys23;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * 恢复流程的宿主。
 *
 * 两条铁律（都是实测踩出来的）：
 *   1. 真重启和 soft-reboot 都会杀掉本进程，所以流程是
 *      「持久化状态机 + 开机广播续跑」，不是一个 while 跑到底。
 *   2. exploit 会 SIGSTOP 一大批进程，包括承载脚本的那条 adbd shell。
 *      所以长流程必须脱离 adb 会话独立跑，进度和结论全部落盘再轮询。
 *      旧版把 try 寄生在一条 shell 上，结果整条会话被冻住，App 干等
 *      420s 超时后误判 unknown —— 白烧一个 boot。
 */
public class RootService extends Service {

    public static final String ACTION_START = "com.rootmys23.START";
    public static final String ACTION_STOP = "com.rootmys23.STOP";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";

    private static final String CHANNEL = "root-my-s23";
    private static final int NOTI_ID = 1;
    private static final String D = "/data/local/tmp/root-my-s23";

    /** assets/payload 下的文件；EXEC 里的会被 chmod 755。 */
    private static final String[] PAYLOAD = {
            "root.sh", "cve-2026-43499-root", "rmg-app.so", "ksud-dm2q", "kernelsu-dm2q.ko"
    };
    private static final Set<String> EXEC = new HashSet<>();
    static {
        EXEC.add("root.sh");
        EXEC.add("cve-2026-43499-root");
        EXEC.add("ksud-dm2q");
    }

    private static final int MAX_BOOTS = 6;
    /** try 阶段总预算：exploit 自己 240s + 重试余量。 */
    private static final long TRY_BUDGET_MS = 330_000;

    private SharedPreferences sp;
    private volatile boolean cancelled = false;
    private AdbClient c;
    private PrivateKey key;
    private PowerManager.WakeLock wake;
    private String host = "127.0.0.1";
    private int port = 5555;

    // ------------------------------------------------------------------ 生命周期

    @Override public void onCreate() {
        super.onCreate();
        sp = getSharedPreferences("rootmys23", MODE_PRIVATE);
        createChannel();
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            cancelled = true;
            Logs.add("已请求停止");
            Logs.setStatus("已停止");
            stopSelf();
            return START_NOT_STICKY;
        }
        if (intent != null) {
            host = intent.getStringExtra(EXTRA_HOST) != null ? intent.getStringExtra(EXTRA_HOST) : host;
            port = intent.getIntExtra(EXTRA_PORT, port);
        }
        if (Logs.running) {
            Logs.add("流程已在跑，忽略重复启动");
            return START_STICKY;
        }
        startForeground(NOTI_ID, buildNotification("正在准备"));
        acquireWake();
        Logs.running = true;
        Logs.setStatus("启动中");
        Logs.add("服务启动 uptime=" + uptime() + "s / phase=" + sp.getString("phase", "try"));
        Thread t = new Thread(this::safeRun, "root-flow");
        t.setDaemon(true);
        t.start();
        return START_STICKY;
    }

    @Override public void onDestroy() {
        cancelled = true;
        releaseWake();
        if (c != null) c.close();
        Logs.running = false;
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent i) { return null; }

    // ------------------------------------------------------------------ 主流程

    private void safeRun() {
        try {
            runFlow();
        } catch (Throwable e) {
            Logs.add("出错: " + e);
            Logs.setStatus("出错: " + e.getMessage());
        } finally {
            Logs.running = false;
            releaseWake();
            stopForeground(true);
            stopSelf();
        }
    }

    private void runFlow() throws Exception {
        int unknowns = 0;
        for (int guard = 0; guard < 24 && !cancelled; guard++) {
            String phase = sp.getString("phase", "try");
            Logs.add("—— 阶段: " + phase + " / 已用 boot " + sp.getInt("boots", 0)
                    + " / uptime=" + uptime() + "s ——");

            ensureConn();

            // 已经好了就别折腾（否则会白跑一次 soft-reboot）
            if (isLoaded() && doVerify()) { finishOk(); return; }

            if ("verify".equals(phase)) {
                if (doVerify()) { finishOk(); return; }
                setPhase("try");
                continue;
            }
            if ("late".equals(phase)) {
                if (doLate()) {
                    setPhase("verify");
                    softReboot();
                    continue;
                }
                setPhase("try");
                continue;
            }

            // phase == try
            ensurePayload();
            int boots = sp.getInt("boots", 0) + 1;
            sp.edit().putInt("boots", boots).apply();
            if (boots > MAX_BOOTS) {
                Logs.add("连续 " + MAX_BOOTS + " 个 boot 都没打中，先停手");
                Logs.setStatus("没打中（概率问题，再点一次）");
                return;
            }

            String v = doTry();
            if ("root".equals(v)) {
                unknowns = 0;
                setPhase("late");
                continue;
            }
            if ("unknown".equals(v)) {
                // 结论没落地不代表失败（可能是我们自己的轮询被冻）。
                // 先当没事发生重试，别急着烧掉一个 boot。
                if (++unknowns <= 2) {
                    Logs.add("没拿到结论，重试一次 (" + unknowns + "/2)");
                    Thread.sleep(5000);
                    continue;
                }
            }
            doReboot();
        }
        Logs.setStatus("已停止");
    }

    // ------------------------------------------------------------------ 各阶段

    /**
     * 打一枪。
     *
     * 只负责「点火 + 收结果」，绝不把流程挂在一条 shell 上：
     *   - 点火：一条秒回的短命令，nohup/setsid 把 root.sh 顶到后台
     *   - 收结果：每 4s 一次 poll，读设备上的 verdict / run.log
     * 这样即使 exploit 冻住了进程、adbd 掉了连接，重连回来照样能拿到结论。
     */
    private String doTry() throws Exception {
        Logs.setStatus("等待触发窗口");
        Logs.add("点火 root.sh try（uptime=" + uptime() + "s，窗口 90-120s）");

        try {
            // 点火逻辑放在 root.sh 里（do_fire），这里只调一条短命令。
            // 复合命令 `rm …; setsid nohup … &` 在这里曾经静默失败过一次，
            // 让 App 白等了 330s —— 现在任何失败都会原样回显。
            String r = sh("sh " + D + "/root.sh fire", 20_000);
            Logs.add(r.trim().isEmpty() ? "点火：无回显（可疑）" : "点火：" + r.trim());
        } catch (Exception e) {
            Logs.add("点火失败: " + e.getMessage());
            return "unknown";
        }

        long t0 = System.currentTimeMillis();
        long lastLine = 0;
        String lastRun = "";
        while (!cancelled && System.currentTimeMillis() - t0 < TRY_BUDGET_MS) {
            Thread.sleep(4000);
            String out;
            try {
                ensureConn();
                out = c.shell("sh " + D + "/root.sh poll", 12_000);
            } catch (Exception e) {
                Logs.add("轮询断了（" + e.getMessage() + "），重连");
                dropConn();
                continue;
            }

            String v = field(out, "verdict");
            String up = field(out, "uptime");
            String line = field(out, "line");
            String xlog = field(out, "xlog");

            if (!line.isEmpty() && !line.equals(lastRun)) {
                lastRun = line;
                Logs.add(line);
            }
            if (!v.isEmpty() && !"none".equals(v) && !"stale-boot".equals(v)) {
                Logs.add("结果: " + v);
                return v;
            }
            if ("stale-boot".equals(v)) {
                Logs.add("boot 已换，本发作废");
                return "rebooted";
            }
            // 兜底心跳：保证任何时候至少每 30s 有一行输出
            if (System.currentTimeMillis() - lastLine > 28_000) {
                lastLine = System.currentTimeMillis();
                long el = (System.currentTimeMillis() - t0) / 1000;
                Logs.add("poll " + el + "s / up=" + up + "s / "
                        + (xlog.isEmpty() ? "exploit 还没吐日志" : xlog));
            }
        }
        Logs.add("try 预算用尽，没拿到结论");
        return "unknown";
    }

    /** 重启换 boot，并且等到 boot_id 真的变了才算数。 */
    private void doReboot() throws Exception {
        Logs.setStatus("重启换一个干净 boot");
        String old = bootId();
        Logs.add("重启设备" + (old.isEmpty() ? "" : "（旧 boot " + shortId(old) + "）"));
        try { sh("reboot", 6000); } catch (Exception ignored) {}
        dropConn();

        long deadline = System.currentTimeMillis() + 420_000;
        while (!cancelled && System.currentTimeMillis() < deadline) {
            Thread.sleep(4000);
            try {
                connectOnce(6000);
                String b = bootId();
                if (!b.isEmpty() && !b.equals(old)) {
                    Logs.add("新 boot " + shortId(b) + " / uptime=" + uptime() + "s");
                    return;
                }
            } catch (Exception ignored) { /* 还没起来 */ }
            dropConn();
        }
        throw new IOException("等新 boot 超时");
    }

    /** late-load + 顺带补齐 services 阶段。 */
    private boolean doLate() throws Exception {
        Logs.setStatus("加载 KernelSU");
        String out = sh("sh " + D + "/root.sh late", 360_000, Logs::add);
        boolean ok = "loaded".equals(verdictOf(out));
        if (!ok) Logs.add("late-load 失败");
        return ok;
    }

    /**
     * soft-reboot 不换 boot_id（kernel 没重启，只重启 userspace），
     * 所以只能靠「adbd 掉线再回来」判断。
     */
    private void softReboot() throws Exception {
        Logs.setStatus("补齐 services（soft-reboot）");
        Logs.add("约 20-40 秒后回来");
        try { sh("su -c '/data/adb/ksud soft-reboot'", 12_000); } catch (Exception ignored) {}
        dropConn();

        long deadline = System.currentTimeMillis() + 300_000;
        while (!cancelled && System.currentTimeMillis() < deadline) {
            Thread.sleep(5000);
            try {
                connectOnce(6000);
                c.shell("echo ok", 6000);
                Logs.add("userspace 已回来 / uptime=" + uptime() + "s");
                return;
            } catch (Exception ignored) { dropConn(); }
        }
        throw new IOException("soft-reboot 后等不到 adbd");
    }

    private boolean doVerify() throws Exception {
        Logs.setStatus("验证");
        String out = sh("sh " + D + "/root.sh verify", 120_000, Logs::add);
        boolean ok = out.contains("uid=0(root)");
        if (ok) Logs.add("su 可用，root 已恢复");
        else Logs.add("su 仍不可用");
        return ok;
    }

    private void finishOk() {
        Logs.setStatus("root 已恢复");
        Logs.add("=== 完成 ===");
        sp.edit().putString("phase", "try").putInt("boots", 0).apply();
        // 顺手把 KernelSU 管理器拉起来
        try { sh("monkey -p me.weishu.kernelsu -c android.intent.category.LAUNCHER 1", 15000); }
        catch (Exception ignored) {}
    }

    // ------------------------------------------------------------------ 连接

    /** 单次连接尝试。失败直接抛，由调用方决定要不要重试。 */
    private void connectOnce(int timeoutMs) throws Exception {
        AdbClient cl = new AdbClient(this::adbLog);
        cl.setKey(privateKey());
        cl.connect(host, port, timeoutMs);
        cl.handshake(Math.max(20_000, timeoutMs));
        cl.startReader();
        c = cl;
    }

    private void connect() throws Exception {
        if (c != null) return;
        long deadline = System.currentTimeMillis() + 240_000;
        int n = 0;
        Exception last = null;
        while (!cancelled && System.currentTimeMillis() < deadline) {
            try {
                connectOnce(8000);
                Logs.add("已连接 adbd " + host + ":" + port + " / uptime=" + uptime() + "s");
                return;
            } catch (Exception e) {
                last = e;
                if (n++ % 5 == 0) Logs.add("等 adbd… " + e.getMessage());
                Thread.sleep(2000);
            }
        }
        throw new IOException("连不上 adbd（" + host + ":" + port + "）"
                + (last != null ? ": " + last.getMessage() : ""));
    }

    private void ensureConn() throws Exception {
        if (c == null) connect();
    }

    private void dropConn() {
        if (c != null) {
            try { c.close(); } catch (Exception ignored) {}
            c = null;
        }
    }

    /** 短命令，连接坏了就重连一次再来。 */
    private String sh(String cmd, long timeoutMs) throws Exception {
        ensureConn();
        try {
            return c.shell(cmd, timeoutMs);
        } catch (Exception e) {
            dropConn();
            ensureConn();
            return c.shell(cmd, timeoutMs);
        }
    }

    private String sh(String cmd, long timeoutMs, AdbClient.LineSink ls) throws Exception {
        ensureConn();
        try {
            return c.shell(cmd, timeoutMs, ls);
        } catch (Exception e) {
            dropConn();
            ensureConn();
            return c.shell(cmd, timeoutMs, ls);
        }
    }

    private String bootId() {
        try {
            return c == null ? "" : c.shell("cat /proc/sys/kernel/random/boot_id", 6000).trim();
        } catch (Exception e) {
            return "";
        }
    }

    private static String shortId(String id) {
        return id.length() > 8 ? id.substring(0, 8) : id;
    }

    /** 设备 uptime（秒）。本进程就跑在手机上，SystemClock 就是手机自己的。 */
    private static String uptime() {
        return Logs.uptime();
    }

    private void adbLog(String s) {
        if (s.startsWith("AUTH_REQUIRED")) {
            Logs.authNeeded = true;
            Logs.add("手机需要授权：弹出「允许 USB 调试吗」后，勾选「一律允许」再点允许");
            Logs.setStatus("等待手机授权");
            return;
        }
        Logs.add(s);
    }

    // ------------------------------------------------------------------ payload

    private void ensurePayload() throws Exception {
        StringBuilder cmd = new StringBuilder();
        for (String f : PAYLOAD) {
            cmd.append("stat -c %s ").append(D).append('/').append(f).append(" 2>/dev/null || echo 0;");
        }
        String out = sh(cmd.toString(), 15000);
        String[] lines = out.replace("\r", "").trim().split("\n");
        Map<String, Long> remote = new HashMap<>();
        for (int i = 0; i < PAYLOAD.length && i < lines.length; i++) {
            try { remote.put(PAYLOAD[i], Long.parseLong(lines[i].trim())); }
            catch (NumberFormatException e) { remote.put(PAYLOAD[i], -1L); }
        }

        Map<String, Long> expect = expectedSizes();
        int pushed = 0;
        for (String f : PAYLOAD) {
            long want = expect.containsKey(f) ? expect.get(f) : -1;
            Long have = remote.get(f);
            if (have != null && have == want) continue;
            byte[] blob = readAsset("payload/" + f);
            Logs.add("推送 " + f + " (" + blob.length / 1024 + " KB)");
            ensureConn();
            c.push(blob, D + "/" + f, EXEC.contains(f) ? AdbClient.MODE_EXEC : AdbClient.MODE_FILE, 180_000);
            pushed++;
        }
        if (pushed > 0) {
            Logs.add("已推送 " + pushed + " 个文件");
            StringBuilder ch = new StringBuilder("chmod 755");
            for (String f : EXEC) ch.append(' ').append(D).append('/').append(f);
            sh(ch.toString(), 15000);
        }
    }

    private Map<String, Long> expectedSizes() {
        Map<String, Long> m = new HashMap<>();
        try {
            String txt = new String(readAsset("payload/sizes.txt"), "UTF-8");
            for (String line : txt.split("\n")) {
                String[] p = line.trim().split("\\s+");
                if (p.length == 2) m.put(p[0], Long.parseLong(p[1]));
            }
        } catch (Exception e) {
            Logs.add("读 sizes.txt 失败: " + e);
        }
        return m;
    }

    private byte[] readAsset(String name) throws IOException {
        try (InputStream in = getAssets().open(name)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream(Math.max(1024, in.available()));
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        }
    }

    // ------------------------------------------------------------------ 工具

    private PrivateKey privateKey() throws Exception {
        if (key != null) return key;
        File f = new File(getFilesDir(), "adbkey.der");
        if (f.exists()) {
            byte[] der = new byte[(int) f.length()];
            try (InputStream in = new java.io.FileInputStream(f)) {
                int off = 0, n;
                while (off < der.length && (n = in.read(der, off, der.length - off)) > 0) off += n;
            }
            try { key = AdbClient.loadPkcs8(der); return key; } catch (Exception ignored) { /* 重建 */ }
        }
        byte[] der = AdbClient.generateKeyDer();
        try (FileOutputStream o = new FileOutputStream(f)) { o.write(der); }
        key = AdbClient.loadPkcs8(der);
        return key;
    }

    private static String verdictOf(String out) {
        for (String line : out.replace("\r", "").split("\n")) {
            if (line.startsWith("##VERDICT ")) return line.substring(10).trim();
        }
        return "unknown";
    }

    /** 从 `key=value` 多行输出里取一个字段；没有就返回空串。 */
    private static String field(String out, String k) {
        for (String line : out.replace("\r", "").split("\n")) {
            int eq = line.indexOf('=');
            if (eq > 0 && line.substring(0, eq).trim().equals(k)) {
                return line.substring(eq + 1).trim();
            }
        }
        return "";
    }

    private void setPhase(String p) { sp.edit().putString("phase", p).apply(); }

    private boolean isLoaded() {
        try {
            return sh("grep -q '^kernelsu ' /proc/modules && echo yes", 8000).contains("yes");
        } catch (Exception e) {
            return false;
        }
    }

    private void acquireWake() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wake = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "rootmys23:flow");
            wake.setReferenceCounted(false);
            wake.acquire(60 * 60 * 1000L);
        } catch (Exception ignored) {}
    }

    private void releaseWake() {
        try { if (wake != null && wake.isHeld()) wake.release(); } catch (Exception ignored) {}
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL, "root 恢复", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification(String text) {
        PendingIntent pi = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL)
                : new Notification.Builder(this);
        return b.setContentTitle("root-my-s23")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }
}
