#!/usr/bin/env python3
# cron: 0 9 * * *
# new Env("u1s1.io 签到")
import hashlib
import re
import sys
import time
from common import Http, ensure, env_seq, is_already_signed, load_kv_state, main_guard, mask_str, save_kv_state
import cookie_validity as cv

PREFIX = "U1S1_"
CAPCAT_SITE_KEY = "f8ad0853ed20b00d"
# Local resource policy, independent of provider-supplied challenge parameters.
RSW_MAX_T = 1_000_000
RSW_MAX_BITS = 4096
RSW_TIMEOUT = 120

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def _fnv1a(seed: str) -> int:
    h = 2166136261
    for ch in seed:
        h = ((h ^ ord(ch)) * 16777619) & 0xFFFFFFFF
    return h


# Local resource policy for legacy challenges (not advertised protocol maxima).
LEGACY_MAX_SOLUTIONS = 1024
LEGACY_MAX_SALT_LENGTH = 4096
LEGACY_MAX_GENERATED_BYTES = 1024 * 1024


def _check_legacy_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeError("PoW 验证码求解超时，放弃求解")


def _prng(seed: str, length: int, deadline: float | None = None) -> str:
    """Cap / CapCat 的 xorshift32 伪随机串生成，与前端 wasm 一致。"""
    if deadline is not None:
        _check_legacy_deadline(deadline)
    state = _fnv1a(seed)
    out = []
    while len(out) * 8 < length:
        if deadline is not None:
            _check_legacy_deadline(deadline)
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
    deadline = time.monotonic() + 120
    ensure(isinstance(challenge, (dict, list)), "CapCat 挑战结构异常")
    specs = [challenge] if isinstance(challenge, dict) else challenge
    ensure(len(specs) <= LEGACY_MAX_SOLUTIONS, "CapCat 挑战规格数量超限")
    validated = []
    total_count = total_bytes = 0
    # Validate every spec before generating anything; limits apply across the list.
    for spec in specs:
        _check_legacy_deadline(deadline)
        ensure(isinstance(spec, dict), "CapCat 挑战规格异常")
        dimensions = []
        for key, maximum in (("c", LEGACY_MAX_SOLUTIONS),
                             ("s", LEGACY_MAX_SALT_LENGTH), ("d", 64)):
            value = spec.get(key)
            ensure(type(value) is int or
                   (isinstance(value, str) and len(value) <= 10 and
                    value.isascii() and value.isdecimal()),
                   f"CapCat 挑战参数 {key} 必须是非负整数")
            value = int(value)
            ensure(0 <= value <= maximum, f"CapCat 挑战参数 {key} 超限")
            dimensions.append(value)
        count, salt_len, difficulty = dimensions
        total_count += count
        total_bytes += count * (salt_len + difficulty)
        ensure(total_count <= LEGACY_MAX_SOLUTIONS, "CapCat 子挑战总数超限")
        ensure(total_bytes <= LEGACY_MAX_GENERATED_BYTES, "CapCat 生成数据总量超限")
        validated.append((count, salt_len, difficulty))

    solutions: list[int] = []
    idx = 0
    for count, salt_len, difficulty in validated:
        _check_legacy_deadline(deadline)
        for _ in range(count):
            _check_legacy_deadline(deadline)
            idx += 1
            salt = _prng(f"{token}{idx}", salt_len, deadline).encode()
            target = _prng(f"{token}{idx}d", difficulty, deadline)
            nonce = 0
            while True:
                if nonce % 1024 == 0:
                    _check_legacy_deadline(deadline)
                if hashlib.sha256(salt + str(nonce).encode()).hexdigest().startswith(target):
                    break
                nonce += 1
            _check_legacy_deadline(deadline)
            solutions.append(nonce)
    _check_legacy_deadline(deadline)
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
    # Check encoded lengths before int(): hexadecimal conversion has no Python
    # digit limit. Bounded residues also bound every multiplication's allocation.
    operands = []
    for key in ("N", "x"):
        value = payload[key]
        if (not isinstance(value, str) or len(value) > RSW_MAX_BITS // 4 + 2
                or re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", value) is None):
            raise ValueError("RSW 操作数格式错误或超出资源限制")
        operand = int(value, 16)
        if operand.bit_length() > RSW_MAX_BITS:
            raise ValueError("RSW 操作数超出资源限制")
        operands.append(operand)
    n, x = operands
    raw_t = payload["t"]
    if isinstance(raw_t, str):
        if len(raw_t) > len(str(RSW_MAX_T)) or re.fullmatch(r"[0-9]+", raw_t) is None:
            raise ValueError("RSW t 格式错误或超出资源限制")
        t = int(raw_t)
    elif type(raw_t) is int:
        t = raw_t
    else:
        raise ValueError("RSW t 必须是整数")
    if n <= 0 or not 0 <= t <= RSW_MAX_T:
        raise ValueError("RSW 参数无效或超出资源限制")

    t0 = time.monotonic()
    deadline = t0 + RSW_TIMEOUT
    y = x % n
    # x^(2^t) mod N, without allocating the exponentially large exponent.
    for _ in range(t):
        if time.monotonic() >= deadline:
            raise RuntimeError("RSW 求解超时，放弃求解")
        y = (y * y) % n
    print(f"  🧩 RSW 时间锁求解完成 (t={t}, 耗时 {time.monotonic() - t0:.2f}s)")
    return format(y, "x")


def fetch_cap_token(h: Http, site_key: str = CAPCAT_SITE_KEY) -> str:
    """自动完成 CapCat 人机验证求解，换取 cap-token。

    format 2（challenges 列表）：逐项求解 rsw / sha256-pow，拒绝远端 JS，
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
                # 远端 JS 即使清空环境变量仍可访问宿主文件和进程，禁止执行。
                raise RuntimeError("CapCat instrumentation 挑战需要执行远端代码，已拒绝")
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
            # 失败路径拿不到 /api/me 的邮箱，用脱敏 session 标识账号供通知卡片提取
            print(f"❌ 账号 {tag}{mask_str(token)} 打卡失败: {err_detail}")
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

    # 凭据有效期跟踪（共享引擎）：u1s1_session 为登录凭据，JWT 形状时直接出倒计时
    redis_key = f"cat_checkin:state:u1s1_{idx}"
    state_file = f".u1s1_state_{idx}.json"
    cred_match = lambda n: n == "u1s1_session"  # noqa: E731
    learned = cv.learn_from_jar(h.jar, credential_match=cred_match)
    tracked = cv.update_state(load_kv_state(redis_key, state_file) or {}, token, learned)
    cv.mark_ok(tracked)  # 成功运行日入账（无解析有效期凭据按执行天数反推寿命）
    validity_tag = cv.tag_for(token, tracked, learned, credential_match=cred_match)
    try:
        save_kv_state(redis_key, state_file, {**tracked, "updated_at": int(time.time())})
    except Exception:
        pass

    return True, f"成功{validity_tag}"


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
