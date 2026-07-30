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
def run_echo(port, bind):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    print(f"[echo] 监听 {bind}:{port}/udp (Ctrl-C 退出)")
    buf = bytearray(65535)
    try:
        while True:
            n, addr = s.recvfrom_into(buf)
            s.sendto(buf[:n], addr)
    except KeyboardInterrupt:
        print("\n[echo] 停止")


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


async def run_level(loop, n, target, src_ips, rate, hold, payload):
    interval = 1.0 / rate
    dgrams = max(1, int(rate * hold))
    c0 = cpu_snapshot()
    t0 = time.perf_counter()
    tasks = [one_flow(loop, target, src_ips[i % len(src_ips)], dgrams, interval, payload)
             for i in range(n)]
    results = await asyncio.gather(*tasks)
    elapsed = time.perf_counter() - t0
    cpu = cpu_pct(c0, cpu_snapshot())

    opened = sum(1 for s, _, _ in results if s > 0)
    alive = sum(1 for s, r, _ in results if s > 0 and r > 0)
    tot_sent = sum(s for s, _, _ in results)
    tot_recv = sum(r for _, r, _ in results)
    rtts = sorted(rt for _, _, rt in results if rt is not None)
    p50 = rtts[len(rtts) // 2] if rtts else None
    p95 = rtts[int(len(rtts) * 0.95)] if rtts else None
    return {
        "n": n, "opened": opened, "alive": alive,
        "flow_ok_pct": 100.0 * alive / n if n else 0.0,
        "dgram_loss_pct": 100.0 * (tot_sent - tot_recv) / tot_sent if tot_sent else 0.0,
        "p50": p50, "p95": p95, "cpu": cpu, "elapsed": elapsed,
    }


async def run_load(args):
    loop = asyncio.get_running_loop()
    host, port = args.target.rsplit(":", 1)
    target = (host, int(port))
    src_ips = [ip.strip() for ip in args.source_ips.split(",")] if args.source_ips else ["0.0.0.0"]
    payload = b"M" * args.payload
    bump_fd_limit(args.max)

    print(f"[load] target={target} src_ips={src_ips} rate={args.rate}/s hold={args.hold}s "
          f"payload={args.payload}B  斜坡 {args.start}→{args.max} step {args.step}")
    print(f"{'flows':>7} {'opened':>7} {'alive':>6} {'flow_ok%':>9} "
          f"{'dgram_loss%':>12} {'p50ms':>7} {'p95ms':>7} {'cpu%':>6}")
    ceiling = None
    for n in range(args.start, args.max + 1, args.step):
        r = await run_level(loop, n, target, src_ips, args.rate, args.hold, payload)
        p50 = f"{r['p50']:.1f}" if r['p50'] is not None else "-"
        p95 = f"{r['p95']:.1f}" if r['p95'] is not None else "-"
        cpu = f"{r['cpu']:.0f}" if r['cpu'] is not None else "-"
        wall = ""
        if r['flow_ok_pct'] < args.threshold and ceiling is None:
            ceiling = n
            wall = "  <-- 拐点 (带机量极限)"
        # 标注已知墙
        if r['opened'] < n and r['opened'] > 0:
            wall += f"  [fd/系统限: 仅开 {r['opened']}]"
        print(f"{r['n']:>7} {r['opened']:>7} {r['alive']:>6} {r['flow_ok_pct']:>8.1f}% "
              f"{r['dgram_loss_pct']:>11.1f}% {p50:>7} {p95:>7} {cpu:>6}{wall}")
        # 掉到近乎全灭就停, 别空转
        if r['flow_ok_pct'] < 5.0 and n > args.start:
            print("[load] 成功率 <5%, 已达上限, 提前停止斜坡。")
            break

    print()
    if ceiling:
        near = "≈256 (隧道加密 UDP 墙 MAX_MIRAGE_UDP_FLOWS)" if 180 <= ceiling <= 340 else (
               "≈4096 (透明 UDP 总墙 MAX_FLOWS)" if 3500 <= ceiling <= 4600 else
               "非已知常量墙 —— 多半是 CPU/fd/网卡, 看 cpu% 列与 opened 列")
        print(f"[结果] 带机量极限 ≈ {ceiling} 条并发流 (flow_ok% 跌破 {args.threshold}%)。判读: {near}")
    else:
        print(f"[结果] 到 {args.max} 仍未跌破 {args.threshold}% —— 极限更高, 调大 --max 继续。")


def main():
    ap = argparse.ArgumentParser(description="Mirage 网关 UDP 带机量压测 (无 iperf3)")
    sub = ap.add_subparsers(dest="mode", required=True)

    e = sub.add_parser("echo", help="目标机: UDP echo 服务")
    e.add_argument("--port", type=int, default=9999)
    e.add_argument("--bind", default="0.0.0.0")

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

    args = ap.parse_args()
    if args.mode == "echo":
        run_echo(args.port, args.bind)
    else:
        asyncio.run(run_load(args))


if __name__ == "__main__":
    main()
