#!/usr/bin/env python3
"""Migrate legacy combined / unnumbered GitHub Actions secrets to numbered sequence secrets."""
import os
import re
import subprocess
import sys


def set_secret(name: str, value: str) -> bool:
    value = value.strip()
    if not value:
        return False
    print(f"Setting secret: {name} (len={len(value)})")
    try:
        subprocess.run(
            ["gh", "secret", "set", name, "--body", value],
            check=True,
            capture_output=True,
            text=True,
        )
        print(f"✅ Secret {name} set successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error setting {name}: {e.stderr}", file=sys.stderr)
        return False


def split_items(raw: str) -> list[str]:
    if not raw:
        return []
    return [x.strip() for x in re.split(r"\n|&&", raw) if x.strip()]


def main():
    print("Starting GitHub Actions Secrets sequence migration...")

    # 1. WorkBuddy
    wb1 = os.getenv("WORKBUDDY_COOKIE", "")
    if wb1:
        set_secret("WORKBUDDY_COOKIE_1", wb1)
    wb2 = os.getenv("WORKBUDDY_COOKIE_2", "")
    if wb2:
        set_secret("WORKBUDDY_COOKIE_2", wb2)

    # 2. GLaDOS
    glados_cookies = split_items(os.getenv("GLADOS_COOKIES", ""))
    for idx, c in enumerate(glados_cookies, 1):
        set_secret(f"GLADOS_COOKIE_{idx}", c)
    glados_accs = split_items(os.getenv("GLADOS_ACCOUNTS", ""))
    for idx, acc in enumerate(glados_accs, 1):
        if ":" in acc:
            u, _, p = acc.partition(":")
            set_secret(f"GLADOS_EMAIL_{idx}", u.strip())
            set_secret(f"GLADOS_PASSWORD_{idx}", p.strip())
        set_secret(f"GLADOS_ACCOUNT_{idx}", acc)

    # 3. 2Libra
    two_libra = split_items(os.getenv("TWO_LIBRA_COOKIES", ""))
    for idx, c in enumerate(two_libra, 1):
        set_secret(f"TWO_LIBRA_COOKIE_{idx}", c)

    # 4. Bianjie AI
    bianjie = split_items(os.getenv("BIANJIE_AI_ACCOUNTS", ""))
    for idx, acc in enumerate(bianjie, 1):
        if ":" in acc:
            u, _, p = acc.partition(":")
        elif "---" in acc:
            u, _, p = acc.partition("---")
        elif "," in acc:
            u, _, p = acc.partition(",")
        else:
            continue
        set_secret(f"BIANJIE_AI_USERNAME_{idx}", u.strip())
        set_secret(f"BIANJIE_AI_PASSWORD_{idx}", p.strip())
    bj_u = os.getenv("BIANJIE_AI_USERNAME", "")
    bj_p = os.getenv("BIANJIE_AI_PASSWORD", "")
    if bj_u and bj_p:
        set_secret("BIANJIE_AI_USERNAME_1", bj_u)
        set_secret("BIANJIE_AI_PASSWORD_1", bj_p)

    # 5. Sophnet
    sophnet_tokens = split_items(os.getenv("SOPHNET_TOKENS", ""))
    for idx, line in enumerate(sophnet_tokens, 1):
        if "|" in line:
            t, r = line.split("|", 1)
            if t.strip():
                set_secret(f"SOPHNET_TOKEN_{idx}", t.strip())
            if r.strip():
                set_secret(f"SOPHNET_REFRESH_TOKEN_{idx}", r.strip())
        else:
            set_secret(f"SOPHNET_REFRESH_TOKEN_{idx}", line.strip())

    # 6. MonkeyCode
    mc_cookies = split_items(os.getenv("MONKEYCODE_COOKIE", ""))
    for idx, c in enumerate(mc_cookies, 1):
        set_secret(f"MONKEYCODE_COOKIE_{idx}", c)
    mc_accs = split_items(os.getenv("MONKEYCODE_ACCOUNTS", ""))
    for idx, acc in enumerate(mc_accs, 1):
        if ":" in acc:
            u, _, p = acc.partition(":")
            set_secret(f"MONKEYCODE_EMAIL_{idx}", u.strip())
            set_secret(f"MONKEYCODE_PASSWORD_{idx}", p.strip())
    mc_e = os.getenv("MONKEYCODE_EMAIL", "")
    mc_p = os.getenv("MONKEYCODE_PASSWORD", "")
    if mc_e and mc_p:
        set_secret("MONKEYCODE_EMAIL_1", mc_e)
        set_secret("MONKEYCODE_PASSWORD_1", mc_p)

    # 7. AI-ROUTER
    ai_rt = os.getenv("AI_ROUTER_REFRESH_TOKEN", "")
    if ai_rt:
        set_secret("AI_ROUTER_REFRESH_TOKEN_1", ai_rt)
    ai_tok = os.getenv("AI_ROUTER_TOKEN", "")
    if ai_tok:
        set_secret("AI_ROUTER_TOKEN_1", ai_tok)
    ai_email = os.getenv("AI_ROUTER_EMAIL", "") or os.getenv("AI_ROUTER_USERNAME", "")
    ai_pass = os.getenv("AI_ROUTER_PASSWORD", "")
    if ai_email and ai_pass:
        set_secret("AI_ROUTER_EMAIL_1", ai_email)
        set_secret("AI_ROUTER_PASSWORD_1", ai_pass)

    # 8. AgentRouter
    ar_email = os.getenv("AGENTROUTER_EMAIL", "")
    ar_pass = os.getenv("AGENTROUTER_PASSWORD", "")
    if ar_email and ar_pass:
        set_secret("AGENTROUTER_EMAIL_1", ar_email)
        set_secret("AGENTROUTER_PASSWORD_1", ar_pass)

    # 9. ModelScope
    ms_c = split_items(os.getenv("MODELSCOPE_COOKIE", ""))
    for idx, c in enumerate(ms_c, 1):
        set_secret(f"MODELSCOPE_COOKIE_{idx}", c)
    ms_ai = split_items(os.getenv("MODELSCOPE_AI_COOKIE", ""))
    for idx, c in enumerate(ms_ai, 1):
        set_secret(f"MODELSCOPE_AI_COOKIE_{idx}", c)

    # 10. Naixi Forum
    nx_u = os.getenv("NAIXI_USERNAME", "")
    nx_p = os.getenv("NAIXI_PASSWORD", "")
    if nx_u and nx_p:
        set_secret("NAIXI_USERNAME_1", nx_u)
        set_secret("NAIXI_PASSWORD_1", nx_p)

    # 11. PCBETA
    pcb_c = os.getenv("PCBETA_COOKIE", "")
    if pcb_c:
        set_secret("PCBETA_COOKIE_1", pcb_c)
    pcb_u = os.getenv("PCBETA_USERNAME", "")
    pcb_p = os.getenv("PCBETA_PASSWORD", "")
    if pcb_u and pcb_p:
        set_secret("PCBETA_USERNAME_1", pcb_u)
        set_secret("PCBETA_PASSWORD_1", pcb_p)

    # 12. DJI
    dji_c = os.getenv("DJI_COOKIE", "")
    if dji_c:
        set_secret("DJI_COOKIE_1", dji_c)

    # 13. UGNAS
    ug_c = os.getenv("UGNAS_COOKIE", "")
    if ug_c:
        set_secret("UGNAS_COOKIE_1", ug_c)

    # 14. CloudStudio
    cs_c = os.getenv("CLOUDSTUDIO_COOKIE", "")
    if cs_c:
        set_secret("CLOUDSTUDIO_COOKIE_1", cs_c)

    print("Secret migration finished!")


if __name__ == "__main__":
    main()
