#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("u1s1.io 签到")
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from common import Http, ensure, env_seq, is_already_signed, main_guard, mask_str

PREFIX = "U1S1_"
CAPCAT_SITE_KEY = "f8ad0853ed20b00d"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _fnv1a(seed: str) -> int:
    h = 2166136261
    for ch in seed:
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return h


def _prng(seed: str, length: int) -> str:
    """Cap / CapCat 的 xorshift32 伪随机串生成，与前端 wasm 一致。"""
    state = _fnv1a(seed)
    out = []
    while len(out) * 8 < length:
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        out.append(f"{state:08x}")
    return "".join(out)[:length]


def solve_challenge(token: str, challenge: dict | list) -> list[int]:
    """对每个子挑战暴力搜索 nonce，使 sha256(salt+nonce) 以 target 开头。

    兼容两种挑战结构：单个 {c,s,d} 规格 dict，或规格列表（逐项求解、
    全局序号连续，salt 种子派生方式与前端 wasm 一致）。
    """
    specs = [challenge] if isinstance(challenge, dict) else list(challenge)
    solutions: list[int] = []
    idx = 0
    deadline = time.monotonic() + 120

    for spec in specs:
        count = int(spec["c"])
        salt_len = int(spec["s"])
        difficulty = int(spec["d"])
        for _ in range(count):
            idx += 1
            salt = _prng(f"{token}{idx}", salt_len).encode()
            target = _prng(f"{token}{idx}d", difficulty)
            nonce = 0
            while not hashlib.sha256(salt + str(nonce).encode()).hexdigest().startswith(target):
                nonce += 1
                if nonce % 100000 == 0 and time.monotonic() > deadline:
                    raise RuntimeError(f"PoW 验证码求解超时（第 {idx} 个子挑战），放弃求解")
            solutions.append(nonce)
    return solutions


def _solve_sha256_pow(token: str, payload: dict) -> int:
    """sha256-pow 协议：暴力搜索 nonce 使 sha256(salt+nonce) 以 target 开头。"""
    salt = payload["salt"].encode()
    target = payload["target"]
    nonce = 0
    deadline = time.monotonic() + 120
    while not hashlib.sha256(salt + str(nonce).encode()).hexdigest().startswith(target):
        nonce += 1
        if nonce % 100000 == 0 and time.monotonic() > deadline:
            raise RuntimeError("sha256-pow 求解超时，放弃求解")
    return nonce


def _solve_rsw(payload: dict) -> str:
    """RSW 时间锁谜题：y = x^(2^t) mod N（与前端 t 次连续平方等价），返回 hex。"""
    n = int(payload["N"], 16)
    x = int(payload["x"], 16)
    t = int(payload["t"])
    t0 = time.time()
    y = pow(x, 1 << t, n)
    print(f"  🧩 RSW 时间锁求解完成 (t={t}, 耗时 {time.time() - t0:.2f}s)")
    return format(y, "x")


def _run_instr(blob: str) -> dict:
    """执行 instrumentation 挑战：blob 为 base64(deflate(JS))。

    JS 内的 anti-bot 检查只决定通过/超时；回传的 state 是一段与浏览器无关的
    确定性算术（位运算 + DOM 算术），用 Node + 迷你 DOM 垫片真实执行。
    返回 {i, state, ts}（与服务端期望的 postMessage result 结构一致）。
    需要 Node.js（GitHub Actions runner 自带）。
    """
    node = shutil.which("node")
    ensure(bool(node), "instrumentation 挑战需要 Node.js 但未安装")
    js = zlib.decompress(base64.b64decode(blob), wbits=-15).decode("utf-8")

    # 提取算术段：最后一个 blocked 早退之后 → 成功 postMessage 之前
    blocked = js.rfind("'*');return;}")
    post = js.rfind("parent.postMessage({type: 'cap:instr'")
    ensure(blocked != -1 and post != -1 and blocked < post, "instrumentation JS 结构与预期不符，无法提取算术段")
    seg = js[blocked + len("'*');return;}"):post]
    m = re.search(r"return (\w+);\}\)\(\);", seg)
    ensure(bool(m), "instrumentation JS 未找到 state 返回语句")
    seg = seg[: m.start() + len(f"return {m.group(1)};")]
    m_id = re.search(r'result:\{i:"([0-9a-f]+)"', js)
    ensure(bool(m_id), "instrumentation JS 未找到内嵌挑战 id")

    harness = "\n".join([
        'const navigator = {userAgent: ' + json.dumps(UA) + '};',
        'class Div { constructor(){ this.parentNode=null; this._kids=[]; this._text=""; this.style={}; }',
        '  appendChild(c){ this._kids.push(c); c.parentNode=this; return c; }',
        '  removeChild(c){ const i=this._kids.indexOf(c); if(i>=0) this._kids.splice(i,1); return c; }',
        '  get children(){ return this._kids; }',
        '  get lastElementChild(){ return this._kids.length ? this._kids[this._kids.length-1] : null; }',
        '  set innerText(v){ this._text = String(v); }',
        '  get innerText(){ return this._text; }',
        '}',
        'const document = { createElement: () => new Div(), body: new Div() };',
        '(async () => {',
        seg,
        '})().then(s => console.log("STATE:" + JSON.stringify(s)))'
        '.catch(e => { console.error("ERR:" + e.message); process.exit(1); });',
    ])
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(harness)
        path = f.name
    try:
        out = subprocess.run([node, path], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(path)
    ensure(out.returncode == 0 and "STATE:" in out.stdout,
           f"instrumentation 算术执行失败: {(out.stderr or out.stdout)[:200]}")
    state = json.loads(out.stdout.split("STATE:", 1)[1])
    return {"i": m_id.group(1), "state": state, "ts": int(time.time() * 1000)}


def fetch_cap_token(h: Http, site_key: str = CAPCAT_SITE_KEY) -> str:
    """自动完成 CapCat 人机验证求解，换取 cap-token。

    format 2（challenges 列表）：逐项求解 rsw / instrumentation / sha256-pow，
    solutions 数组与 challenges 顺序一一对应（与前端 cap.js 行为一致）。
    format 1（challenge {c,s,d}）：保留原 prng PoW 求解路径。
    """
    headers = {
        "Origin": "https://u1s1.io",
        "Referer": "https://u1s1.io/",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "User-Agent": UA,
    }

    # 1. 获取挑战
    resp = h.request("POST", f"https://api.capcat.ai/{site_key}/challenge", headers=headers, json_data={})
    data = resp.json({})
    ensure(
        bool(data.get("token")),
        f"获取 CapCat 验证码挑战失败 (HTTP {resp.code}): {resp.text[:200]}"
        f" [diag] 响应字段: {list(data.keys()) if isinstance(data, dict) else type(data).__name__}",
    )
    t0 = time.time()

    # 2a. format 2：challenges 列表，solutions 逐项对应
    if data.get("format") == 2 and isinstance(data.get("challenges"), list):
        solutions = []
        for ch in data["challenges"]:
            proto = ch.get("protocol")
            if proto == "rsw":
                solutions.append({"y": _solve_rsw(ch["payload"])})
            elif proto == "instrumentation":
                solutions.append({"instr": _run_instr(ch["payload"]["blob"])})
            elif proto == "sha256-pow":
                nonce = _solve_sha256_pow(data["token"], ch["payload"])
                solutions.append({"nonce": nonce})
            else:
                ensure(False, f"CapCat 未知挑战协议: {proto}")
        redeem_body = {"token": data["token"], "solutions": solutions}
    else:
        # 2b. format 1：单 {c,s,d} 规格，salt 由 prng 派生
        challenge = data.get("challenge")
        ensure(isinstance(challenge, dict), f"CapCat 挑战结构异常: {resp.text[:200]}")
        solutions = solve_challenge(data["token"], challenge)
        redeem_body = {"token": data["token"], "solutions": solutions}

    # 3. 提交解答兑换 cap-token
    redeem_resp = h.request(
        "POST",
        f"https://api.capcat.ai/{site_key}/redeem",
        headers=headers,
        json_data=redeem_body,
    )
    redeem_data = redeem_resp.json({})
    cap_token = redeem_data.get("token")
    ensure(
        bool(redeem_data.get("success") and cap_token),
        f"兑换 CapCat 验证码失败 (HTTP {redeem_resp.code}): {redeem_resp.text[:200]}",
    )
    print(f"🧩 PoW 验证码求解成功 (耗时 {time.time() - t0:.2f}s)")
    return cap_token


def format_tokens(num: int | float | None) -> str:
    """格式化 Token 数量为易读字符串（含逗号分隔与 M/K 辅助单位）。"""
    if num is None:
        return "未知"
    try:
        val = int(num)
        if val >= 1_000_000:
            return f"{val:,} ({val / 1_000_000:.2f}M)"
        elif val >= 1_000:
            return f"{val:,} ({val / 1_000:.1f}K)"
        return f"{val:,}"
    except (ValueError, TypeError):
        return str(num)


def load_accounts() -> list[str]:
    """多账号凭证解析：
    1. 优先读取 U1S1_TOKEN_1, U1S1_TOKEN_2... 或 U1S1_TOKEN
    2. 兼容读取 U1S1_COOKIE_1, U1S1_COOKIE_2... 或 U1S1_COOKIE (提取 u1s1_session)
    3. 支持 Bearer 前缀与 JWT Token 直接填入
    """
    accounts: list[str] = []

    tokens = env_seq(PREFIX, "token", required=False)
    for t in tokens:
        t = t.strip()
        if not t:
            continue
        clean = t.removeprefix("Bearer ").strip()
        if "u1s1_session=" in clean:
            clean = clean.split("u1s1_session=", 1)[1].split(";", 1)[0].strip()
        if clean and clean not in accounts:
            accounts.append(clean)

    cookies = env_seq(PREFIX, "cookie", required=False)
    for c in cookies:
        c = c.strip()
        if not c:
            continue
        clean = c.removeprefix("Bearer ").strip()
        if "u1s1_session=" in clean:
            clean = clean.split("u1s1_session=", 1)[1].split(";", 1)[0].strip()
        if clean and clean not in accounts:
            accounts.append(clean)

    if not accounts:
        raise RuntimeError("未配置 U1S1_TOKEN 或 U1S1_COOKIE 凭证！请配置 U1S1_TOKEN_1 或 U1S1_TOKEN。")

    return accounts


def run_account(idx: int, total_accounts: int, token: str, h: Http) -> tuple[bool, str]:
    tag = f"[{idx}/{total_accounts}]" if total_accounts > 1 else ""
    print(f"\n--- 处理账号 {tag} ---")

    headers = {
        "Cookie": f"u1s1_session={token}",
        "Origin": "https://u1s1.io",
        "Referer": "https://u1s1.io/dashboard",
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    }

    # 1. 求解 CapCat PoW 验证码
    try:
        cap_token = fetch_cap_token(h)
    except Exception as e:
        print(f"⚠️ 获取验证码遇到异常 ({e})，尝试直接打卡")
        cap_token = ""

    # 2. 直接执行签到打卡 POST 请求（不做 GET 预判）
    claim_payload = {"cap-token": cap_token} if cap_token else {}
    resp = h.request("POST", "https://u1s1.io/api/packages/login-checkin/claim", headers=headers, json_data=claim_payload)
    data = resp.json({})

    is_ok = False
    reward_text = ""
    streak_text = ""

    if resp.code == 200 and data.get("ok") is True:
        is_ok = True
        tokens = data.get("tokens", 2000000)
        streak = data.get("streak", 1)
        bonus = data.get("bonus_tokens", 0)
        milestone = data.get("milestone_day")

        reward_text = f"{format_tokens(tokens)} Tokens"
        streak_text = f"连续 {streak} 天"
        bonus_info = f" (达成第 {milestone} 天里程碑额外 +{format_tokens(bonus)})" if bonus else ""
        print(f"🎉 账号 {tag} 打卡成功！今日获得: {reward_text}，{streak_text}{bonus_info}")
    else:
        # 错误信息可能是嵌套结构（如 {"error": {"message": "今天已经打过卡了"}}），逐层展开
        raw_err = data.get("error") or data.get("message") or data.get("msg") or resp.text[:100]
        if isinstance(raw_err, dict):
            raw_err = raw_err.get("message") or raw_err.get("msg") or raw_err.get("error") or str(raw_err)
        err_msg = str(raw_err)
        if is_already_signed(err_msg, extra_phrases=("already_claimed", "已打卡", "打过卡", "重复打卡", "请勿重复", "今日已", "已经打卡", "已完成打卡")):
            is_ok = True
            print(f"ℹ️ 账号 {tag} 今日已完成打卡")
        else:
            err_detail = f"HTTP {resp.code}, msg: {err_msg}"
            if resp.code in (401, 403):
                err_detail += " (Session Cookie 已失效)"
            print(f"❌ 账号 {tag} 打卡失败: {err_detail}")
            return False, err_detail

    # 3. 获取用户资产与打卡进度信息（/api/me，展示性信息非阻断）
    me_resp = h.request("GET", "https://u1s1.io/api/me", headers=headers)
    if me_resp.code == 200:
        me_data = me_resp.json({})
        email = mask_str(me_data.get("email") or "")
        login_checkin = me_data.get("login_checkin") or {}
        streak = login_checkin.get("streak")
        next_milestone_day = login_checkin.get("next_milestone_day")
        next_milestone_tokens = login_checkin.get("next_milestone_tokens")
        next_milestone_in_days = login_checkin.get("next_milestone_in_days")

        print(f"👤 用户信息: {email or '用户'}")
        if streak is not None:
            milestone_hint = ""
            if next_milestone_day and next_milestone_tokens:
                milestone_hint = f" (再连签 {next_milestone_in_days} 天可额外领 {format_tokens(next_milestone_tokens)} Tokens)"
            print(f"📅 连签进度: 连续 {streak} 天{milestone_hint}")

        # 打印活跃套餐 / 配额信息
        packages = me_data.get("packages") or []
        for pkg in packages:
            kind = pkg.get("kind")
            rem = pkg.get("remaining") or pkg.get("total_tokens")
            if kind == "login_checkin" and rem:
                print(f"🎁 打卡赠送额度: {format_tokens(rem)} Tokens (有效期至 {pkg.get('expires_at', '未知')})")
    else:
        print(f"⚠️ 用户资产查询失败 (HTTP {me_resp.code})，跳过")

    return True, "成功"


def main():
    print("【u1s1.io 签到】")
    accounts = load_accounts()
    print(f"📋 共加载到 {len(accounts)} 个 u1s1.io 账号")

    h = Http()
    failures: list[str] = []

    for idx, token in enumerate(accounts, start=1):
        ok, err = run_account(idx, len(accounts), token, h)
        if not ok:
            failures.append(f"账号 #{idx}: {err}")

    if failures:
        print(f"\n🚨 执行完毕，共有 {len(failures)} 个账号打卡失败：")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)

    print("\n✅ 所有 u1s1.io 账号打卡成功！")


main_guard(main)
