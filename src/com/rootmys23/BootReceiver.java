package com.rootmys23;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

/**
 * 开机自启。BOOT_COMPLETED 大约在 uptime 25-40s 到，
 * 正好赶在 90s 的触发窗口之前。
 */
public class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context ctx, Intent intent) {
        if (!Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) return;
        SharedPreferences sp = ctx.getSharedPreferences("rootmys23", Context.MODE_PRIVATE);
        if (!sp.getBoolean("auto", false)) return;

        Intent i = new Intent(ctx, RootService.class)
                .setAction(RootService.ACTION_START)
                .putExtra(RootService.EXTRA_HOST, sp.getString("host", "127.0.0.1"))
                .putExtra(RootService.EXTRA_PORT, sp.getInt("port", 5555));
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i);
            else ctx.startService(i);
        } catch (Exception ignored) {
            // 后台启动被系统挡住时只能等用户手动点
        }
    }
}
