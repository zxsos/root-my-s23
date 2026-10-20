package com.rootmys23;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.View;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * 只负责展示与触发，业务逻辑全在 RootService 里。
 *
 * UI 是「平台控件 + M3 视觉」：颜色一律取 @color/md_* 语义色，
 * 不在这里写死十六进制，换主题只动 res。
 */
public class MainActivity extends Activity {

    private TextView statusView, deviceView, logView;
    private EditText hostView, portView;
    private ScrollView scroll;
    private CompoundButton autoView;
    private ProgressBar progress;
    private Drawable dot;
    private SharedPreferences sp;
    private final Handler ui = new Handler(Looper.getMainLooper());

    private final Logs.Listener listener = line -> ui.post(() -> appendLine(line));

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);
        sp = getSharedPreferences("rootmys23", MODE_PRIVATE);

        statusView = findViewById(R.id.status);
        deviceView = findViewById(R.id.device);
        logView = findViewById(R.id.log);
        hostView = findViewById(R.id.host);
        portView = findViewById(R.id.port);
        scroll = findViewById(R.id.scroll);
        autoView = findViewById(R.id.auto);
        progress = findViewById(R.id.progress);

        // 状态点的 drawable 是共享的，mutate 一份再 tint，避免影响别处
        View dotView = findViewById(R.id.dot);
        dot = dotView.getBackground().mutate();
        dotView.setBackground(dot);

        hostView.setText(sp.getString("host", "127.0.0.1"));
        portView.setText(String.valueOf(sp.getInt("port", 5555)));
        autoView.setChecked(sp.getBoolean("auto", false));
        autoView.setOnCheckedChangeListener((v, checked) ->
                sp.edit().putBoolean("auto", checked).apply());

        findViewById(R.id.btnRoot).setOnClickListener(v -> start());
        findViewById(R.id.btnStop).setOnClickListener(v -> {
            Intent i = new Intent(this, RootService.class).setAction(RootService.ACTION_STOP);
            startService(i);
        });
        findViewById(R.id.btnClear).setOnClickListener(v -> {
            Logs.clear();
            logView.setText("");
        });

        StringBuilder sb = new StringBuilder();
        for (String s : Logs.snapshot()) sb.append(s).append('\n');
        logView.setText(sb.toString());
        scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
        // 进页面先刷一次，别等 500ms 才亮
        render();

        Logs.subscribe(listener);
        ui.post(tick);
        askNotificationPermission();
    }

    @Override protected void onDestroy() {
        Logs.unsubscribe(listener);
        ui.removeCallbacks(tick);
        super.onDestroy();
    }

    private final Runnable tick = new Runnable() {
        @Override public void run() {
            render();
            if (Logs.authNeeded) {
                // 授权弹窗会被前台 Activity 压住，必须让路
                Logs.authNeeded = false;
                moveTaskToBack(true);
            }
            ui.postDelayed(this, 500);
        }
    };

    /** 把 Logs 里的状态映射到 M3 的颜色角色上。 */
    private void render() {
        String st = Logs.status;
        int color;
        if (st.startsWith("出错")) {
            color = getColor(R.color.md_error);
        } else if (Logs.running || st.startsWith("root 已恢复")) {
            color = getColor(R.color.md_primary);
        } else {
            color = getColor(R.color.md_on_surface_variant);
        }

        // tick 是 500ms 一次，这里只在真的变了才动 View，
        // 否则 setText/setTint 会一直触发重绘和布局
        if (!st.contentEquals(statusView.getText())) statusView.setText(st);
        if (color != lastColor) {
            lastColor = color;
            statusView.setTextColor(color);
            dot.setTint(color);
        }

        // 用 INVISIBLE 而不是 GONE：进度条高度一直占着，流程启动时卡片不会跳一下
        int vis = Logs.running ? View.VISIBLE : View.INVISIBLE;
        if (progress.getVisibility() != vis) progress.setVisibility(vis);

        String dev = deviceLine();
        if (!dev.contentEquals(deviceView.getText())) deviceView.setText(dev);
    }

    private int lastColor = 0;

    private String deviceLine() {
        String phase = sp.getString("phase", "try");
        int boots = sp.getInt("boots", 0);
        return "boot " + Build.MODEL + " · phase=" + phase + " · 已尝试 " + boots + " 个 boot";
    }

    private void appendLine(String line) {
        if (logView.getText().length() > 400_000) logView.setText("");
        logView.append(TextUtils.isEmpty(logView.getText()) ? line : "\n" + line);
        scroll.post(() -> scroll.fullScroll(ScrollView.FOCUS_DOWN));
    }

    private void start() {
        String host = hostView.getText().toString().trim();
        int port;
        try { port = Integer.parseInt(portView.getText().toString().trim()); }
        catch (Exception e) { port = 5555; }
        if (host.isEmpty()) host = "127.0.0.1";
        sp.edit().putString("host", host).putInt("port", port).apply();

        // 手动点按钮 = 重新开一局
        sp.edit().putString("phase", "try").putInt("boots", 0).apply();

        Intent i = new Intent(this, RootService.class)
                .setAction(RootService.ACTION_START)
                .putExtra(RootService.EXTRA_HOST, host)
                .putExtra(RootService.EXTRA_PORT, port);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i);
        else startService(i);
    }

    private void askNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
        }
    }
}
