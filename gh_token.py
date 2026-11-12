#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""本机脚本共用的 GitHub 令牌获取 (只进内存, 不落盘、不打印令牌值)。

优先级:
  1. 环境变量 GITHUB_TOKEN  —— 一次性临时令牌, 用完即弃
  2. git credential fill     —— 凭据管理器里的 ggboom-push 细粒度令牌

返回 (token, 来源/错误说明)。取不到时 token 为空串, 由调用方给中文提示。
三个调用方: trigger_build.py / probe_entries.py / push_via_api.py。
此前三者各写一份, 只有 probe_entries.py 的 push_to_github 不支持临时令牌,
导致 --with-probe 用环境变量时「触发构建走临时令牌、推健康数据走长期 PAT」,
或探测已覆盖本地文件后推送失败。统一到这里是为了消除这种分裂。
"""
import os
import subprocess

CREDENTIAL_INPUT = "protocol=https\nhost=github.com\n\n"


def get_token():
    """返回 (token, 来源说明); 失败返回 ('', 中文原因)。"""
    env = os.environ.get("GITHUB_TOKEN", "").strip()
    if env:
        return env, "环境变量 GITHUB_TOKEN"
    try:
        p = subprocess.run(
            ["git", "credential", "fill"],
            input=CREDENTIAL_INPUT,
            capture_output=True, text=True, timeout=20,
        )
    except FileNotFoundError:
        return "", "本机找不到 git 命令"
    except subprocess.TimeoutExpired:
        return "", "git credential 查询超时 (20 秒)"
    except Exception as e:
        return "", f"git credential 调用失败 ({type(e).__name__}: {e})"
    if p.returncode != 0:
        return "", f"git credential 退出码 {p.returncode}"
    token = next((line.split("=", 1)[1].strip()
                  for line in p.stdout.splitlines()
                  if line.startswith("password=")), "")
    if not token:
        return "", "凭据管理器里没有 github.com 令牌"
    return token, "本机凭据管理器"
