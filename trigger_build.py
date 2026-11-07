#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""本机主动触发一次订阅构建, 绕开 GitHub 对计划任务的降频 (零成本)。

背景: check.yml 写的是 cron "*/30 * * * *", 但 GitHub 对免费仓库的高频计划任务
会降频, 实测最近若干次定时构建间隔 7~8 小时, 配置和实际不符。与其跟平台较劲,
不如把配置改成诚实的低频, 再由本机按需补触发。

为什么这不算"花钱":
  - GitHub 免费账户每月 2000 分钟 Actions; 实测单次构建约 0.9 分钟。
    每 6 小时一次 = 4 次/天 = 约 120 分钟/月, 远低于免费额度。
  - 不需要 VPS、不需要付费 CI、不需要第三方定时服务、不需要常驻后台进程。

令牌: 只从环境变量 GITHUB_TOKEN 或 git credential fill 临时读取,
      **不写入任何文件、不打印、不进日志**。运行完即释放。
      所需权限只有一项: 该仓库的「操作 (Actions): 读写」。

用法 (全部提示为中文):
    python trigger_build.py --check          # 只看最近一次构建时间, 不触发
    python trigger_build.py                  # 距上次构建超过 6 小时才触发 (带节流)
    python trigger_build.py --force          # 忽略节流, 立即触发
    python trigger_build.py --min-hours 3    # 自定义节流窗口
    python trigger_build.py --install-task   # 注册 Windows 计划任务 (每 6 小时)
    python trigger_build.py --remove-task    # 删除该计划任务

计划任务说明: 任务本身免费, 不装任何软件; 命令行里**不含令牌**,
运行时由脚本从 git 凭据管理器临时读取, 所以令牌不会写进任务定义或任何文件。
注册/删除属于系统级改动, 需使用者自己执行, 脚本不会自动注册。
"""
import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "funnyday-py/ggboom"
WORKFLOW = "check.yml"
API = "https://api.github.com"
TASK_NAME = "ggboom-sub-build"
SCRIPT_PATH = os.path.abspath(__file__)
PYEXE = sys.executable


def get_token():
    """取令牌: 环境变量优先 (一次性), 否则读本机凭据管理器。不落盘。"""
    t = os.environ.get("GITHUB_TOKEN", "").strip()
    if t:
        return t, "环境变量 GITHUB_TOKEN"
    p = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True,
    )
    t = next((l.split("=", 1)[1].strip() for l in p.stdout.splitlines()
              if l.startswith("password=")), "")
    if t:
        return t, "本机凭据管理器"
    return "", ""


def api(method, path, token, body=None):
    hdr = {"Authorization": f"Bearer {token}",
           "Accept": "application/vnd.github+json",
           "User-Agent": "ggboom-trigger-build"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdr["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, method=method, data=data, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"message": raw[:200]}
    except Exception as e:
        return 0, {"message": f"{type(e).__name__}: {e}"}


def last_run(token):
    code, d = api("GET", f"/repos/{REPO}/actions/runs?per_page=1", token)
    if code != 200 or not d.get("workflow_runs"):
        return None, f"查询失败 (HTTP {code}: {str(d.get('message',''))[:80]})"
    r = d["workflow_runs"][0]
    return r, None


def manage_task(remove=False):
    """注册/删除 Windows 计划任务。命令行不含令牌, 令牌由脚本运行时临时读取。"""
    if sys.platform != "win32":
        print("计划任务只支持 Windows。其他系统请改用 cron 等自有调度器。")
        return 1
    if remove:
        cmd = ["schtasks", "/Delete", "/TN", TASK_NAME, "/F"]
        ok_msg = f"已删除计划任务 {TASK_NAME}"
    else:
        # /SC HOURLY /MO 6 = 每 6 小时; 脚本内部还有 6 小时节流双保险
        run = f'"{PYEXE}" "{SCRIPT_PATH}" --min-hours 6'
        cmd = ["schtasks", "/Create", "/TN", TASK_NAME, "/TR", run,
               "/SC", "HOURLY", "/MO", "6", "/F"]
        ok_msg = (f"已注册计划任务 {TASK_NAME}: 每 6 小时检查一次, 超过 6 小时才真正触发。\n"
                  f"命令行不含令牌; 运行时从凭据管理器临时读取。\n"
                  f"查看: schtasks /Query /TN {TASK_NAME}\n"
                  f"删除: python trigger_build.py --remove-task")
    p = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode == 0:
        print(ok_msg)
        return 0
    print(f"操作失败 (退出码 {p.returncode}): {(p.stdout or p.stderr or '').strip()[:300]}")
    if not remove and "拒绝" in (p.stdout + p.stderr):
        print("无管理员权限时, 可改用「当前用户」任务; 或直接在需要时手动跑本脚本。")
    return 1


def main():
    ap = argparse.ArgumentParser(description="本机触发 ggboom 订阅构建 (中文提示)")
    ap.add_argument("--check", action="store_true", help="只查看最近构建, 不触发")
    ap.add_argument("--force", action="store_true", help="忽略节流, 立即触发")
    ap.add_argument("--min-hours", type=float, default=6.0, help="节流窗口, 默认 6 小时")
    ap.add_argument("--install-task", action="store_true", help="注册 Windows 计划任务")
    ap.add_argument("--remove-task", action="store_true", help="删除 Windows 计划任务")
    args = ap.parse_args()

    if args.install_task or args.remove_task:
        return manage_task(remove=args.remove_task)

    token, src = get_token()
    if not token:
        print("没找到 GitHub 令牌。请设置环境变量 GITHUB_TOKEN 后重试。")
        print("创建方法: GitHub → 设置 → 开发者设置 → 细粒度令牌 → 仓库权限里把「操作」设为「读写」。")
        return 2

    run, err = last_run(token)
    if err:
        print(f"读取构建记录失败: {err}")
        if "Bad credentials" in err:
            print("令牌已失效, 请重新生成。")
        return 1

    created = dt.datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    age_h = (now - created).total_seconds() / 3600
    print(f"最近一次构建: {run['created_at']}  触发方式={run['event']}  "
          f"状态={run['status']}  结论={run.get('conclusion')}")
    print(f"距今 {age_h:.1f} 小时 (令牌来源: {src})")

    if args.check:
        return 0

    if not args.force and age_h < args.min_hours:
        print(f"距上次构建不足 {args.min_hours:g} 小时, 本次跳过 (避免浪费免费额度)。")
        print("确实需要立刻刷新时, 加 --force。")
        return 0

    code, d = api("POST", f"/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches",
                  token, {"ref": "main"})
    if code == 204:
        print("已触发构建。约 1 分钟后可在仓库「操作」页看到结果。")
        return 0
    print(f"触发失败 (HTTP {code}): {str(d.get('message',''))[:160]}")
    if code == 403:
        print()
        print("权限不足。请在 GitHub 网页上做一次 (只需做一次):")
        print("  1. 打开  https://github.com/settings/personal-access-tokens")
        print("  2. 点开当前这枚细粒度令牌")
        print("  3. 仓库权限 → 找到「操作 / Actions」→ 改成「读写」→ 保存")
        print("  注意: 不要点「重新生成」, 改权限后现有令牌立即生效。")
        print("  也可以新建一枚只授权 ggboom 仓库、只给「操作: 读写」的令牌, ")
        print("  用环境变量 GITHUB_TOKEN 临时传入, 用完即删。")
    elif code == 401:
        print("令牌已失效, 请重新生成后重试。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
