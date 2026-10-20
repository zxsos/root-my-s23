package com.rootmys23;

import java.io.*;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * 最小 ADB 客户端：只实现 root-my-s23 需要的三件事
 *   1. 握手（RSA AUTH，签名 / 首次送公钥）
 *   2. shell 命令（legacy shell:，raw 字节流）
 *   3. 推文件（官方 sync: 协议，支持大文件）
 *
 * 纯 JDK，无第三方依赖，可直接放进 Android APK（minSdk 26）。
 */
public class AdbClient implements Closeable {

    static final int CNXN = 0x4e584e43;
    static final int AUTH = 0x48545541;
    static final int OPEN = 0x4e45504f;
    static final int OKAY = 0x59414b4f;
    static final int WRTE = 0x45545257;
    static final int CLSE = 0x45534c43;

    static final int AUTH_TOKEN = 1;
    static final int AUTH_SIGNATURE = 2;
    static final int AUTH_RSAPUBLICKEY = 3;

    /** SHA-1 DigestInfo 的 DER 前缀（不含摘要本体）。 */
    static final byte[] SHA1_DI_PREFIX = {
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };

    private static final byte[] EMPTY = new byte[0];

    private Socket sock;
    private InputStream in;
    private OutputStream out;
    private PrivateKey key;
    private RSAPublicKey pub;
    private final Object writeLock = new Object();

    /** 握手/连接阶段的诊断输出；App 里置 null 即静音。 */
    public interface Log { void line(String s); }
    private Log log;

    private volatile int nextLocalId = 1;
    private final ConcurrentHashMap<Integer, Stream> streams = new ConcurrentHashMap<>();
    private volatile boolean closed = false;
    private volatile String banner = "";
    /** 设备要求用户授权（弹了「允许 USB 调试吗」）。UI 据此把自己退到后台，别挡住弹窗。 */
    public volatile boolean authNeeded = false;

    public AdbClient() {}
    public AdbClient(Log log) { this.log = log; }

    private void dbg(String s) { Log l = log; if (l != null) l.line(s); }

    public interface Sink { void onData(byte[] buf, int len); }

    public static class Stream {
        public final int localId;
        public volatile int remoteId;
        public Sink sink;
        final CountDownLatch opened = new CountDownLatch(1);
        final CountDownLatch closedLatch = new CountDownLatch(1);
        /** 发数据流控：adbd 每收一个 WRTE 回一个 OKAY。 */
        final Semaphore credits = new Semaphore(16);
        Stream(int localId, Sink sink) { this.localId = localId; this.sink = sink; }
    }

    // ---------------- 连接 ----------------

    public void connect(String host, int port, int timeoutMs) throws IOException {
        sock = new Socket();
        sock.connect(new InetSocketAddress(host, port), timeoutMs);
        sock.setTcpNoDelay(true);
        sock.setSoTimeout(0);          // 读超时由各调用点自己控制
        in = new BufferedInputStream(sock.getInputStream(), 1 << 16);
        out = new BufferedOutputStream(sock.getOutputStream(), 1 << 16);
    }

    public void setKey(PrivateKey priv) throws Exception {
        this.key = priv;
        this.pub = (RSAPublicKey) derivePublic(priv);
    }

    public String serverBanner() { return banner; }

    /** 发 CNXN 并完成 AUTH，直到收到设备的 CNXN。 */
    public void handshake(long timeoutMs) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        String feats = "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,"
                + "apex,abb,abb_exec,remount_shell,track_app,sendrecv_v2,abi,none";
        sendPacket(CNXN, 0x01000001, 1024 * 1024,
                (feats + "\0").getBytes(StandardCharsets.UTF_8));
        int tokens = 0;
        while (System.currentTimeMillis() < deadline) {
            Msg m;
            try {
                m = readPacket();
            } catch (java.net.SocketTimeoutException te) {
                throw new IOException("握手超时（adbd 没回应）");
            }
            if (m.cmd == CNXN) {
                banner = new String(m.data, 0, m.len, StandardCharsets.UTF_8);
                dbg("device: " + banner.replace('\0', ' ').trim());
                return;
            }
            if (m.cmd != AUTH) throw new IOException("unexpected cmd 0x" + Integer.toHexString(m.cmd));
            if (m.arg0 != AUTH_TOKEN) throw new IOException("unexpected AUTH arg0=" + m.arg0);

            if (pub == null) throw new IOException("设备要求认证，但本地没有密钥");

            if (!authNeeded && key != null && tokens < 2) {
                tokens++;
                sendPacket(AUTH, AUTH_SIGNATURE, 0, signToken(m.data, m.len));
                continue;
            }

            // 签名不被认（或者本机第一次用），改送公钥让手机弹授权框。
            // 弹框期间 adbd 会继续发 TOKEN，就再送一次，直到用户点「允许」或超时。
            if (!authNeeded) {
                authNeeded = true;
                dbg("AUTH_REQUIRED 设备需要授权，正在发送公钥");
            }
            String txt = Base64.getEncoder().encodeToString(encodeAdbPublicKey(pub))
                    + " root-my-s23@android";
            sendPacket(AUTH, AUTH_RSAPUBLICKEY, 0, (txt + "\0").getBytes(StandardCharsets.UTF_8));
            Thread.sleep(500);
        }
        if (authNeeded) throw new IOException("等待手机授权超时（没点「允许」）");
        throw new IOException("握手超时");
    }

    // ---------------- AUTH 签名 ----------------

    /**
     * adbd 把 20 字节 token 直接当作“已经算好的 SHA-1 摘要”做 PKCS#1 v1.5 私钥运算，
     * 不会再 hash 一遍。所以这里必须用手工拼 DigestInfo + Cipher 原始私钥运算，
     * 不能用 Signature("SHA1withRSA")——那会多 hash 一次，adbd 永远不认。
     */
    byte[] signToken(byte[] token, int len) throws Exception {
        byte[] di = new byte[SHA1_DI_PREFIX.length + len];
        System.arraycopy(SHA1_DI_PREFIX, 0, di, 0, SHA1_DI_PREFIX.length);
        System.arraycopy(token, 0, di, SHA1_DI_PREFIX.length, len);
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        return c.doFinal(di);
    }

    // ---------------- 流 ----------------

    public Stream open(String service, Sink sink, long timeoutMs) throws Exception {
        Stream s = new Stream(nextLocalId++, sink);
        streams.put(s.localId, s);
        sendPacket(OPEN, s.localId, 0, (service + "\0").getBytes(StandardCharsets.UTF_8));
        if (!s.opened.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            streams.remove(s.localId);
            throw new IOException("open timeout: " + service);
        }
        if (s.remoteId == 0) {           // adbd 用 remoteId=0 表示拒绝
            streams.remove(s.localId);
            throw new IOException("service rejected: " + service);
        }
        return s;
    }

    public void write(Stream s, byte[] data, int off, int len) throws Exception {
        s.credits.acquire();
        sendPacket(WRTE, s.localId, s.remoteId, data, off, len);
    }

    public void write(Stream s, byte[] data) throws Exception {
        write(s, data, 0, data.length);
    }

    public void closeStdin(Stream s) throws Exception {
        sendPacket(CLSE, s.localId, s.remoteId, EMPTY);
    }

    public void startReader() {
        Thread t = new Thread(() -> {
            try {
                while (!closed) {
                    Msg m = readPacket();
                    Stream s = streams.get(m.arg1);
                    switch (m.cmd) {
                        case OKAY:
                            if (s != null) {
                                if (s.opened.getCount() > 0) { s.remoteId = m.arg0; s.opened.countDown(); }
                                else s.credits.release();
                            }
                            break;
                        case WRTE:
                            if (s != null) {
                                if (s.sink != null) s.sink.onData(m.data, m.len);
                                sendPacket(OKAY, s.localId, s.remoteId, EMPTY);
                            }
                            break;
                        case CLSE:
                            if (s != null) {
                                streams.remove(s.localId);
                                s.opened.countDown();
                                s.closedLatch.countDown();
                            }
                            break;
                        default:
                            break;
                    }
                }
            } catch (Exception e) {
                if (!closed) { dbg("reader 退出: " + e); }
                // 连接断了：把所有等待中的流放开，免得调用方永久挂住
                for (Stream s : streams.values()) { s.opened.countDown(); s.closedLatch.countDown(); }
            }
        }, "adb-reader");
        t.setDaemon(true);
        t.start();
    }

    // ---------------- shell ----------------

    /** 跑一条命令，收集输出（legacy shell，raw 字节流，支持重定向/管道）。 */
    public String shell(String cmd, long timeoutMs) throws Exception {
        StringBuilder sb = new StringBuilder();
        Stream s = open("shell:" + cmd, (b, n) -> sb.append(new String(b, 0, n, StandardCharsets.UTF_8)), 10000);
        s.closedLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        streams.remove(s.localId);
        return sb.toString().replace("\r", "");
    }

    /** 流式 shell：每读到一整行就回调一次，同时把全文攒起来。 */
    public interface LineSink { void line(String s); }

    public String shell(String cmd, long timeoutMs, LineSink ls) throws Exception {
        final ByteArrayOutputStream pending = new ByteArrayOutputStream();
        final StringBuilder all = new StringBuilder();
        Stream s = open("shell:" + cmd, (b, n) -> {
            synchronized (pending) {
                pending.write(b, 0, n);
                byte[] buf = pending.toByteArray();
                int start = 0;
                for (int i = 0; i < buf.length; i++) {
                    if (buf[i] == '\n') {
                        String line = new String(buf, start, i - start, StandardCharsets.UTF_8)
                                .replace("\r", "");
                        all.append(line).append('\n');
                        if (ls != null) ls.line(line);
                        start = i + 1;
                    }
                }
                pending.reset();
                if (start < buf.length) pending.write(buf, start, buf.length - start);
            }
        }, 10000);
        s.closedLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        synchronized (pending) {
            if (pending.size() > 0) {
                String rest = new String(pending.toByteArray(), StandardCharsets.UTF_8);
                all.append(rest);
                if (ls != null) ls.line(rest);
            }
        }
        streams.remove(s.localId);
        return all.toString();
    }

    /** 跑一条命令，把 stdout 当二进制塞进 sink。 */
    public int shellTo(String cmd, OutputStream dst, long timeoutMs) throws Exception {
        Stream s = open("shell:" + cmd, (b, n) -> {
            try { dst.write(b, 0, n); } catch (IOException ignored) {}
        }, 10000);
        s.closedLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
        streams.remove(s.localId);
        return 0;
    }

    // ---------------- sync: 推文件 ----------------

    /**
     * 走官方 sync 协议推一个文件。比 shell+cat 可靠：有明确的 OKAY/FAIL 应答，
     * 不受 shell 引号影响，4.8MB 的 ksud 也没问题。
     */
    public void push(byte[] content, String remotePath, int mode, long timeoutMs) throws Exception {
        SyncStream ss = new SyncStream(open("sync:", null, 10000));
        try {
            // SEND 的负载是 "path,mode"，mode 是十进制 st_mode（0100755 = 33261）
            ss.send("SEND", (remotePath + "," + mode).getBytes(StandardCharsets.UTF_8));
            int chunk = 64 * 1024;
            byte[] slice = new byte[chunk];
            for (int off = 0; off < content.length; off += chunk) {
                int n = Math.min(chunk, content.length - off);
                System.arraycopy(content, off, slice, 0, n);
                ss.send("DATA", n == chunk ? slice : java.util.Arrays.copyOf(slice, n));
            }
            // DONE 的负载就是 8 字节 mtime
            ss.send("DONE", new byte[8]);
            ss.expectOkay(timeoutMs);
        } finally {
            try { ss.send("QUIT", EMPTY); } catch (Exception ignored) {}
            try { closeStdin(ss.raw); } catch (Exception ignored) {}
            ss.raw.closedLatch.await(400, TimeUnit.MILLISECONDS);
            streams.remove(ss.raw.localId);
        }
    }

    /** 常用 st_mode：普通文件 0644 / 可执行 0755。 */
    public static final int MODE_FILE = 0100644;
    public static final int MODE_EXEC = 0100755;

    /** sync 子协议的 4+4 定长头 + 尾巴，包在普通 stream 之上。 */
    final class SyncStream {
        final Stream raw;
        private final ByteArrayOutputStream inbuf = new ByteArrayOutputStream();
        private boolean eof = false;

        SyncStream(Stream raw) {
            this.raw = raw;
            this.raw.sink = (b, n) -> { synchronized (inbuf) { inbuf.write(b, 0, n); inbuf.notifyAll(); } };
        }

        /** 包格式：id(4) + LE32(payload 长度) + payload */
        void send(String id, byte[] payload) throws Exception {
            ByteBuffer h = ByteBuffer.allocate(8 + payload.length).order(ByteOrder.LITTLE_ENDIAN);
            h.put(id.getBytes(StandardCharsets.US_ASCII));
            h.putInt(payload.length);
            h.put(payload);
            AdbClient.this.write(raw, h.array());
        }

        byte[] read(int n, long timeoutMs) throws Exception {
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (true) {
                synchronized (inbuf) {
                    if (inbuf.size() >= n) {
                        byte[] all = inbuf.toByteArray();
                        byte[] r = new byte[n];
                        System.arraycopy(all, 0, r, 0, n);
                        inbuf.reset();
                        inbuf.write(all, n, all.length - n);
                        return r;
                    }
                    if (eof) throw new EOFException("sync 流已关闭");
                    long wait = deadline - System.currentTimeMillis();
                    if (wait <= 0) throw new IOException("sync 读超时");
                    inbuf.wait(Math.min(wait, 200));
                }
            }
        }

        void expectOkay(long timeoutMs) throws Exception {
            byte[] id = read(4, timeoutMs);
            String s = new String(id, StandardCharsets.US_ASCII);
            if (s.equals("OKAY")) return;
            if (s.equals("FAIL")) {
                byte[] l = read(4, timeoutMs);
                int n = ByteBuffer.wrap(l).order(ByteOrder.LITTLE_ENDIAN).getInt();
                String msg = new String(read(n, timeoutMs), StandardCharsets.UTF_8);
                throw new IOException("push 失败: " + msg);
            }
            throw new IOException("sync 应答异常: " + s);
        }
    }

    // ---------------- 报文 ----------------

    static class Msg {
        int cmd, arg0, arg1, len;
        byte[] data = EMPTY;
    }

    void sendPacket(int cmd, int arg0, int arg1, byte[] data) throws Exception {
        sendPacket(cmd, arg0, arg1, data, 0, data.length);
    }

    void sendPacket(int cmd, int arg0, int arg1, byte[] data, int off, int len) throws Exception {
        ByteBuffer h = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        h.putInt(cmd); h.putInt(arg0); h.putInt(arg1); h.putInt(len);
        int sum = 0;
        for (int i = 0; i < len; i++) sum += data[off + i] & 0xff;
        h.putInt(sum);
        h.putInt(cmd ^ 0xffffffff);
        synchronized (writeLock) {
            out.write(h.array());
            if (len > 0) out.write(data, off, len);
            out.flush();
        }
    }

    Msg readPacket() throws Exception {
        byte[] h = new byte[24];
        readFully(h, 24);
        ByteBuffer b = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        Msg m = new Msg();
        m.cmd = b.getInt(); m.arg0 = b.getInt(); m.arg1 = b.getInt(); m.len = b.getInt();
        b.getInt();
        int magic = b.getInt();
        if (magic != (m.cmd ^ 0xffffffff)) throw new IOException("bad magic");
        if (m.len < 0 || m.len > 8 * 1024 * 1024) throw new IOException("bad len " + m.len);
        if (m.len > 0) { m.data = new byte[m.len]; readFully(m.data, m.len); }
        return m;
    }

    void readFully(byte[] buf, int len) throws IOException {
        int off = 0;
        while (off < len) {
            int n = in.read(buf, off, len - off);
            if (n < 0) throw new EOFException();
            off += n;
        }
    }

    @Override public void close() {
        closed = true;
        try { if (sock != null) sock.close(); } catch (IOException ignored) {}
    }

    // ---------------- ADB 公钥编码 ----------------

    public static byte[] encodeAdbPublicKey(RSAPublicKey k) {
        BigInteger n = k.getModulus();
        BigInteger e = k.getPublicExponent();
        int words = (n.bitLength() + 31) / 32;
        int bytes = words * 4;

        byte[] nBytes = toLittleEndianFixed(n, bytes);
        long n0 = new BigInteger(1, new byte[]{nBytes[0], nBytes[1], nBytes[2], nBytes[3]})
                .longValue() & 0xffffffffL;
        long n0inv = (-modInverse32(n0)) & 0xffffffffL;

        BigInteger R = BigInteger.ONE.shiftLeft(bytes * 8);
        byte[] rr = toLittleEndianFixed(R.multiply(R).mod(n), bytes);
        byte[] ex = toLittleEndianFixed(e, 4);

        ByteBuffer b = ByteBuffer.allocate(8 + 2 * bytes + 4).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(words);
        b.putInt((int) n0inv);
        b.put(nBytes);
        b.put(rr);
        b.put(ex);
        return b.array();
    }

    static byte[] toLittleEndianFixed(BigInteger v, int bytes) {
        byte[] be = v.toByteArray();
        byte[] r = new byte[bytes];
        int copy = Math.min(be.length, bytes);
        for (int i = 0; i < copy; i++) r[i] = be[be.length - 1 - i];
        return r;
    }

    /** a^-1 mod 2^32（牛顿迭代，足够）。 */
    static long modInverse32(long a) {
        long x = 1;
        for (int i = 0; i < 6; i++) x = (x * (2 - a * x)) & 0xffffffffL;
        return x & 0xffffffffL;
    }

    // ---------------- 密钥 ----------------

    public static PrivateKey loadPkcs8(byte[] pemOrDer) throws Exception {
        String s = new String(pemOrDer, StandardCharsets.US_ASCII);
        byte[] der = s.contains("-----")
                ? Base64.getDecoder().decode(s.replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""))
                : pemOrDer;
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    public static PublicKey derivePublic(PrivateKey priv) throws Exception {
        RSAPrivateKey rp = (RSAPrivateKey) priv;
        return KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(rp.getModulus(), BigInteger.valueOf(65537)));
    }

    /** 首次运行：生成一把 2048 位 RSA 私钥（PKCS#8 DER）。 */
    public static byte[] generateKeyDer() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair().getPrivate().getEncoded();
    }
}
