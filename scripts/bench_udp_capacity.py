#!/usr/bin/env python3
"""Mirage 透明网关 UDP 带机量压测器 (无 iperf3, 纯 stdlib)。

原理: 网关的 UDP 流 key = (client addr:port, orig_dst)。每条 UDP 流对应一个不同
的源端口, 所以单机开 N 个源端口 = 网关眼里 N 条独立流 = N 台"设备"并发的等效负载。
斜坡拉高并发, 数回包成功率, 成功率跌破阈值的并发数 = 带机量极限。

专测两堵墙 (见 src/proxy/transparent_udp.rs):
  - MAX_FLOWS = 4096         (透明 UDP 总流上限, 直连+隧道)
  - MAX_MIRAGE_UDP_FLOWS = 256 (隧道内加密 UDP 子上限)
目标路由决定撞哪堵: 目标命中 proxy(fake-IP) 约 256 处跌; 命中 direct 约 4096 处跌。

两端用法:
  # 1. 目标机 (网关能到达的一侧: 直连测的对照机 / 走代理测的海外机) 起 echo:
  python3 bench_udp_capacity.py echo --port 9999

  # 2. 网关下游 LAN 客户端 起负载, 目标填 echo 机地址:
  python3 bench_udp_capacity.py load --target 203.0.113.9:9999 \
      --start 100 --max 6000 --step 200 --hold 3

  # 走代理路径 (撞 256 墙): --target 填一个被网关判为海外/proxy 的域名或其 fake-IP。
"""
import argparse
import asyncio
import resource
import socket
import sys
import time


def bump_fd_limit(target):
    """把 RLIMIT_NOFILE 软限提到能容纳目标并发 (每流 1 fd + 余量)。"""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = target + 256
    if soft >= want:
        return soft
    new = min(want, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
    except (ValueError, OSError):
        pass
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < want:
        print(f"[warn] fd 软限 {soft} < 需要 {want}; 并发会被 fd 卡住。"
              f"先 `ulimit -n {want}` (或提高 hard limit) 再跑。", file=sys.stderr)
    return soft


# ── echo 端 ──────────────────────────────────────────────────────────────
def _echo_worker(port, bind, wid):
    """一个 echo worker: 收即回, 每秒打印收包速率 (pps) + 累计。多 worker 靠
    SO_REUSEPORT 内核分流, 排掉单进程 echo 自身成瓶颈。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    s.bind((bind, port))
    s.settimeout(1.0)
    tag = f"echo{wid}" if wid is not None else "echo"
    print(f"[{tag}] 监听 {bind}:{port}/udp (Ctrl-C 退出)")
    buf = bytearray(65535)
    total = 0
    last = 0
    t = time.monotonic()
    try:
        while True:
            try:
                n, addr = s.recvfrom_into(buf)
                s.sendto(buf[:n], addr)
                total += 1
            except socket.timeout:
                pass
            now = time.monotonic()
            if now - t >= 1.0:
                pps = (total - last) / (now - t)
                if pps > 0 or total != last:
                    print(f"[{tag}] recv_total={total} pps={pps:.0f}", flush=True)
                last = total
                t = now
    except KeyboardInterrupt:
        print(f"\n[{tag}] 停止 (recv_total={total})")


def run_echo(port, bind, workers):
    if workers <= 1:
        _echo_worker(port, bind, None)
        return
    import os
    pids = []
    for wid in range(workers):
        pid = os.fork()
        if pid == 0:
            _echo_worker(port, bind, wid)
            os._exit(0)
        pids.append(pid)
    print(f"[echo] {workers} 个 worker (SO_REUSEPORT), pids={pids}")
    try:
        for pid in pids:
            os.waitpid(pid, 0)
    except KeyboardInterrupt:
        for pid in pids:
            try:
                os.kill(pid, 15)
            except OSError:
                pass


# ── load 端 ──────────────────────────────────────────────────────────────
class _EchoProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.recv = 0
        self.first_recv_t = None  # 首个回包到达时刻 (perf_counter)

    def datagram_received(self, data, addr):
        if self.recv == 0:
            self.first_recv_t = time.perf_counter()
        self.recv += 1


async def one_flow(loop, target, src_ip, dgrams, interval, payload):
    """一条流: 绑独立源端口, 发 dgrams 个包, 数回包。返回 (sent, recv, first_rtt_ms)。
    RTT = 首个回包到达时刻 - 首发时刻 (在协议回调里打真实到达戳, 不受发包节拍干扰)。"""
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _EchoProto, local_addr=(src_ip, 0), remote_addr=target)
    except OSError:
        return (0, 0, None)  # fd 耗尽 / 绑定失败
    sent = 0
    first_send_t = None
    try:
        for i in range(dgrams):
            if first_send_t is None:
                first_send_t = time.perf_counter()
            transport.sendto(payload)
            sent += 1
            await asyncio.sleep(interval)
        # 收尾: 给最后的回包一点到达时间
        await asyncio.sleep(0.2)
    finally:
        transport.close()
    rtt = ((proto.first_recv_t - first_send_t) * 1000
           if proto.first_recv_t is not None and first_send_t is not None else None)
    return (sent, proto.recv, rtt)


def cpu_snapshot():
    """/proc/stat 第一行 → (busy, total) jiffies。无 /proc 返回 None。"""
    try:
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = list(map(int, parts))
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        total = sum(vals)
        return (total - idle, total)
    except OSError:
        return None


def cpu_pct(a, b):
    if not a or not b:
        return None
    dt = b[1] - a[1]
    return 100.0 * (b[0] - a[0]) / dt if dt else None


async def _gather_slice(n, target, src_ips, rate, hold, payload):
    loop = asyncio.get_running_loop()
    interval = 1.0 / rate
    dgrams = max(1, int(rate * hold))
    tasks = [one_flow(loop, target, src_ips[i % len(src_ips)], dgrams, interval, payload)
             for i in range(n)]
    return await asyncio.gather(*tasks)


def _run_slice(job):
    """进程worker入口 (top-level, 可pickle): 跑 n 条流的一个切片, 返回聚合 + rtt 列表。
    每进程一个独立 asyncio 事件循环 → 单核 asyncio 天花板被 W 个核分摊。"""
    n, host, port, src_ips, rate, hold, payload_len = job
    bump_fd_limit(n)  # 每进程独立 fd 限
    res = asyncio.run(_gather_slice(n, (host, port), src_ips, rate, hold, b"M" * payload_len))
    opened = sum(1 for s, _, _ in res if s > 0)
    alive = sum(1 for s, r, _ in res if s > 0 and r > 0)
    sent = sum(s for s, _, _ in res)
    recv = sum(r for _, r, _ in res)
    rtts = [rt for _, _, rt in res if rt is not None]
    return (opened, alive, sent, recv, rtts)


def run_level(executor, workers, n, host, port, src_ips, rate, hold, payload_len):
    """一级并发 n 条流。workers>1 时切成 W 片丢进程池并行, 破 load 端单核 asyncio 瓶颈。"""
    c0 = cpu_snapshot()
    t0 = time.perf_counter()
    if workers <= 1 or executor is None:
        parts = [_run_slice((n, host, port, src_ips, rate, hold, payload_len))]
    else:
        base, rem = divmod(n, workers)
        slices = [base + (1 if i < rem else 0) for i in range(workers)]
        jobs = [(s, host, port, src_ips, rate, hold, payload_len) for s in slices if s > 0]
        parts = list(executor.map(_run_slice, jobs))
    elapsed = time.perf_counter() - t0
    cpu = cpu_pct(c0, cpu_snapshot())

    opened = sum(p[0] for p in parts)
    alive = sum(p[1] for p in parts)
    tot_sent = sum(p[2] for p in parts)
    tot_recv = sum(p[3] for p in parts)
    rtts = sorted(rt for p in parts for rt in p[4])
    p50 = rtts[len(rtts) // 2] if rtts else None
    p95 = rtts[int(len(rtts) * 0.95)] if rtts else None
    return {
        "n": n, "opened": opened, "alive": alive,
        "flow_ok_pct": 100.0 * alive / n if n else 0.0,
        "dgram_loss_pct": 100.0 * (tot_sent - tot_recv) / tot_sent if tot_sent else 0.0,
        "p50": p50, "p95": p95, "cpu": cpu, "elapsed": elapsed,
    }


def run_load(args):
    from concurrent.futures import ProcessPoolExecutor
    host, port_s = args.target.rsplit(":", 1)
    port = int(port_s)
    src_ips = [ip.strip() for ip in args.source_ips.split(",")] if args.source_ips else ["0.0.0.0"]
    bump_fd_limit(args.max)
    workers = max(1, args.workers)
    executor = ProcessPoolExecutor(max_workers=workers) if workers > 1 else None

    print(f"[load] target=({host!r}, {port}) src_ips={src_ips} rate={args.rate}/s hold={args.hold}s "
          f"payload={args.payload}B workers={workers}  斜坡 {args.start}→{args.max} step {args.step}")
    print(f"{'flows':>7} {'opened':>7} {'alive':>6} {'flow_ok%':>9} "
          f"{'dgram_loss%':>12} {'p50ms':>7} {'p95ms':>7} {'cpu%':>6}")
    ceiling = None
    loss_at_ceiling = None
    fd_capped = False
    for n in range(args.start, args.max + 1, args.step):
        r = run_level(executor, workers, n, host, port, src_ips, args.rate, args.hold, args.payload)
        p50 = f"{r['p50']:.1f}" if r['p50'] is not None else "-"
        p95 = f"{r['p95']:.1f}" if r['p95'] is not None else "-"
        cpu = f"{r['cpu']:.0f}" if r['cpu'] is not None else "-"
        wall = ""
        # fd/系统限: opened < 请求数 → 是测试机自己的墙, 不算网关带机量极限。
        if r['opened'] < n and r['opened'] > 0:
            fd_capped = True
            wall += f"  [fd/系统限: 仅开 {r['opened']}, 非网关墙]"
        elif r['flow_ok_pct'] < args.threshold and ceiling is None:
            ceiling = n
            loss_at_ceiling = r['dgram_loss_pct']
            wall = "  <-- flow_ok 拐点"
        print(f"{r['n']:>7} {r['opened']:>7} {r['alive']:>6} {r['flow_ok_pct']:>8.1f}% "
              f"{r['dgram_loss_pct']:>11.1f}% {p50:>7} {p95:>7} {cpu:>6}{wall}")
        # 掉到近乎全灭就停, 别空转
        if r['flow_ok_pct'] < 5.0 and n > args.start:
            print("[load] 成功率 <5%, 已达上限, 提前停止斜坡。")
            break

    print()
    if ceiling is None:
        print(f"[结果] 到 {args.max} flow_ok 仍未跌破 {args.threshold}%"
              + ("; 但中途撞 fd/系统限 (见 [fd] 标注), 先 `ulimit -n` 再测。" if fd_capped
                 else " —— 极限更高, 调大 --max 继续。"))
    else:
        # 形态判读: 拐点处丢包已很高 = 吞吐/缓冲退化 (随并发爬升的 dgram_loss), 不是干净流表墙;
        # 干净流表墙应是"墙下低丢、墙上流被拒"。二者别混。
        if loss_at_ceiling is not None and loss_at_ceiling > 30.0:
            shape = (f"退化型: flow_ok 拐点前 dgram_loss 已达 {loss_at_ceiling:.0f}% —— 是吞吐/缓冲/"
                     f"路径退化 (每流还活但大量丢包), 不是流表数量墙。别急着贴 256/4096 标签; "
                     f"去网关读 nstat RcvbufErrors + 盯 echo pps 分上/下行, 才能定位丢在哪一跳。")
        elif 180 <= ceiling <= 340:
            shape = "干净墙, 命中 ≈256 (隧道加密 UDP MAX_MIRAGE_UDP_FLOWS)"
        elif 3500 <= ceiling <= 4600:
            shape = "干净墙, 命中 ≈4096 (透明 UDP MAX_FLOWS)"
        else:
            shape = "干净墙但非已知常量 —— 看 cpu% 与 opened 列排查 CPU/fd/网卡"
        print(f"[结果] flow_ok 拐点 ≈ {ceiling} 条并发流 (跌破 {args.threshold}%)。判读: {shape}")

    if executor is not None:
        executor.shutdown(wait=False, cancel_futures=True)


def main():
    ap = argparse.ArgumentParser(description="Mirage 网关 UDP 带机量压测 (无 iperf3)")
    sub = ap.add_subparsers(dest="mode", required=True)

    e = sub.add_parser("echo", help="目标机: UDP echo 服务")
    e.add_argument("--port", type=int, default=9999)
    e.add_argument("--bind", default="0.0.0.0")
    e.add_argument("--workers", type=int, default=1, help="SO_REUSEPORT 多进程 echo, 排掉单进程瓶颈")

    l = sub.add_parser("load", help="LAN 客户端: 斜坡加压找带机量极限")
    l.add_argument("--target", required=True, help="echo 机 HOST:PORT (走代理测则填 proxy 域名/fake-IP)")
    l.add_argument("--start", type=int, default=100, help="起始并发流")
    l.add_argument("--max", type=int, default=6000, help="最大并发流")
    l.add_argument("--step", type=int, default=200, help="每级增量")
    l.add_argument("--hold", type=float, default=3.0, help="每级持续秒 (每流发 rate*hold 个包)")
    l.add_argument("--rate", type=float, default=10.0, help="每流每秒发包数")
    l.add_argument("--payload", type=int, default=64, help="每包字节")
    l.add_argument("--threshold", type=float, default=95.0, help="flow_ok%% 低于此判为拐点")
    l.add_argument("--source-ips", default="", help="逗号分隔源 IP (需先 ip addr add 别名), 默认 0.0.0.0")
    l.add_argument("--workers", type=int, default=1,
                   help="多进程加压 (每进程独立 asyncio 事件循环), 破 load 端单核瓶颈。建议 = 测试机核数")

    args = ap.parse_args()
    if args.mode == "echo":
        run_echo(args.port, args.bind, args.workers)
    else:
        run_load(args)


if __name__ == "__main__":
    main()
