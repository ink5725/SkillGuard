# clawhub_unscanned_downloader.py
# 用法示例:
#   python clawhub_unscanned_downloader.py --out ./downloads --max-pages 5 --delay 1.5
#   python clawhub_unscanned_downloader.py --out ./downloads --dry-run
#
# 依赖:
#   pip install requests beautifulsoup4 lxml

import argparse
import datetime
import os
import re
import tarfile
import time
import zipfile
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


BASE = "https://clawhub.ai"
LIST_URL = BASE + "/skills?sort=newest&dir=desc&page={page}"
CONVEX_QUERY_URL = "https://wry-manatee-359.convex.cloud/api/query"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)

# 可能代表“VT 无结果/未扫描”的关键词（按页面文案再补）
VT_UNSCANNED_PATTERNS = [
    r"virus\s*total.*(no result|no results|not scanned|unknown|pending)",
    r"(no result|no results|not scanned|unknown|pending).*virus\s*total",
    r"未扫描",
    r"暂无结果",
    r"无结果",
    r"等待扫描",
]

# 下载链接常见关键词
DOWNLOAD_HINTS = ["download", "下载", "zip", "tar.gz", "tgz", "raw"]


def mk_session():
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
        }
    )
    return s


def is_skill_url(url: str) -> bool:
    # 形如 https://clawhub.ai/{author}/{skill}
    p = urlparse(url)
    if p.netloc != "clawhub.ai":
        return False
    parts = [x for x in p.path.split("/") if x]
    if len(parts) != 2:
        return False
    if parts[0] in {"skills", "about", "login", "signup", "api"}:
        return False
    return True


def extract_skill_links(html: str):
    soup = BeautifulSoup(html, "lxml")
    out = set()
    for a in soup.find_all("a", href=True):
        href = urljoin(BASE, a["href"])
        if is_skill_url(href):
            out.add(href.split("?")[0].rstrip("/"))
    return sorted(out)


def fetch_newest_skill_links_via_convex(session, max_pages: int, max_skills: int, timeout: int, delay: float):
    all_skills = []
    cursor = None
    per_page = 50

    for page in range(1, max_pages + 1):
        args = {
            "numItems": per_page,
            "sort": "newest",
            "dir": "desc",
            "nonSuspiciousOnly": False,
        }
        if cursor:
            args["cursor"] = cursor

        payload = {
            "path": "skills:listPublicPageV4",
            "args": args,
            "format": "convex_encoded_json",
        }

        try:
            r = session.post(CONVEX_QUERY_URL, json=payload, timeout=timeout)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"[WARN] Convex 列表请求失败 page={page}: {e}")
            break

        if data.get("status") != "success":
            print(f"[WARN] Convex 返回非 success page={page}: {data.get('errorMessage')}")
            break

        value = data.get("value") or {}
        items = value.get("page") or []
        links = []
        for it in items:
            owner = (it.get("owner") or {}).get("handle") or it.get("ownerHandle")
            slug = (it.get("skill") or {}).get("slug")
            if owner and slug:
                links.append(f"{BASE}/{owner}/{slug}")

        print(f"[INFO] page={page} (convex) 抓到 skill 链接 {len(links)} 个")
        for u in links:
            if u not in all_skills:
                all_skills.append(u)
                if len(all_skills) >= max_skills:
                    return all_skills[:max_skills]

        if not value.get("hasMore") or not value.get("nextCursor"):
            break
        cursor = value.get("nextCursor")
        time.sleep(delay)

    return all_skills[:max_skills]


def text_matches_unscanned(text: str) -> bool:
    low = " ".join(text.lower().split())
    for pat in VT_UNSCANNED_PATTERNS:
        if re.search(pat, low, flags=re.I):
            return True
    return False


def json_matches_unscanned(html: str) -> bool:
    # 尝试从 script JSON 里找 vt 状态字段
    for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, flags=re.S | re.I):
        body = m.group(1).strip()
        if not body:
            continue
        if "virustotal" not in body.lower() and "virusTotal" not in body:
            continue
        # 粗匹配常见状态词
        if re.search(r"(virus\s*total|virustotal).*(no[_\s-]?result|not[_\s-]?scanned|pending|unknown)", body, re.I):
            return True
    return False


def detect_vt_pending(html: str) -> bool:
    if re.search(r"(virus\s*total|virustotal).{0,160}pending", html, flags=re.I | re.S):
        return True
    if re.search(r"pending.{0,160}(virus\s*total|virustotal)", html, flags=re.I | re.S):
        return True
    soup = BeautifulSoup(html, "lxml")
    text = " ".join(soup.get_text(" ", strip=True).split()).lower()
    if ("virustotal" in text or "virus total" in text) and re.search(r"\bpending\b", text):
        return True
    return False


def detect_unscanned(html: str) -> bool:
    soup = BeautifulSoup(html, "lxml")
    page_text = soup.get_text(" ", strip=True)
    return text_matches_unscanned(page_text) or json_matches_unscanned(html)


def find_download_link(skill_url: str, html: str):
    soup = BeautifulSoup(html, "lxml")

    # 1) 优先找明确 download 按钮/链接
    for a in soup.find_all("a", href=True):
        href = a["href"]
        txt = (a.get_text(" ", strip=True) or "").lower()
        full = urljoin(skill_url, href)
        target = (href + " " + txt).lower()
        if any(h in target for h in DOWNLOAD_HINTS):
            return full

    # 2) 再兜底：在源码里找 zip/tar 下载 URL
    candidates = set(
        re.findall(
            r"""https?://[^\s"'<>]+(?:\.zip|\.tar\.gz|\.tgz|/download[^\s"'<>]*)""",
            html,
            flags=re.I,
        )
    )
    if candidates:
        # 尽量优先 clawhub 域名
        for c in sorted(candidates):
            if "clawhub.ai" in c:
                return c
        return sorted(candidates)[0]

    return None


def safe_name_from_skill_url(skill_url: str):
    p = urlparse(skill_url)
    parts = [x for x in p.path.split("/") if x]
    if len(parts) >= 2:
        return f"{parts[0]}__{parts[1]}"
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", skill_url)


def infer_ext_from_url(url: str):
    path = urlparse(url).path.lower()
    for ext in [".zip", ".tar.gz", ".tgz"]:
        if path.endswith(ext):
            return ext
    return ".bin"


def infer_ext_from_headers(headers):
    cd = (headers.get("content-disposition") or "").lower()
    m = re.search(r'filename\*?=(?:utf-8\'\')?"?([^";]+)"?', cd, flags=re.I)
    if m:
        fn = m.group(1).strip().strip('"')
        low = fn.lower()
        for ext in [".tar.gz", ".tgz", ".zip"]:
            if low.endswith(ext):
                return ext
    ct = (headers.get("content-type") or "").lower()
    if "application/zip" in ct:
        return ".zip"
    if "application/gzip" in ct or "application/x-gzip" in ct:
        return ".tar.gz"
    return None


def probe_out_path(session, url, out_dir, base_name, timeout=30):
    ext = infer_ext_from_url(url)
    try:
        with session.get(url, stream=True, timeout=timeout, allow_redirects=True) as r:
            r.raise_for_status()
            ext = infer_ext_from_headers(r.headers) or infer_ext_from_url(r.url) or ext
    except Exception:
        pass
    return os.path.join(out_dir, base_name + ext)


def download_file(session, url, out_dir, base_name, timeout=60):
    with session.get(url, stream=True, timeout=timeout, allow_redirects=True) as r:
        r.raise_for_status()
        ext = infer_ext_from_headers(r.headers) or infer_ext_from_url(r.url) or infer_ext_from_url(url)
        out_path = os.path.join(out_dir, base_name + ext)
        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)
    return out_path


def extract_archive_and_remove(archive_path, out_dir, base_name):
    low = archive_path.lower()
    if low.endswith(".zip"):
        dst = os.path.join(out_dir, base_name)
        os.makedirs(dst, exist_ok=True)
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(dst)
        os.remove(archive_path)
        return dst
    if low.endswith(".tar.gz") or low.endswith(".tgz"):
        dst = os.path.join(out_dir, base_name)
        os.makedirs(dst, exist_ok=True)
        with tarfile.open(archive_path, "r:gz") as tf:
            tf.extractall(dst)
        os.remove(archive_path)
        return dst
    return None


def todays_out_dir(out_root: str):
    today = datetime.datetime.now().strftime("%Y%m%d")
    out_dir = os.path.join(out_root, today)
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


def already_downloaded(out_dir: str, base_name: str) -> bool:
    dst_dir = os.path.join(out_dir, base_name)
    if os.path.isdir(dst_dir):
        return True
    prefix = base_name + "."
    try:
        for name in os.listdir(out_dir):
            if name.startswith(prefix):
                return True
    except FileNotFoundError:
        return False
    return False


def run_once(out_root: str, vt_status: str, max_pages: int, max_skills: int, delay: float, timeout: int, dry_run: bool):
    out_dir = todays_out_dir(out_root)
    print(f"[INFO] 输出目录: {out_dir}")

    s = mk_session()

    all_skills = fetch_newest_skill_links_via_convex(
        session=s,
        max_pages=max_pages,
        max_skills=max_skills,
        timeout=timeout,
        delay=delay,
    )
    if not all_skills:
        print("[WARN] Convex 未拿到链接，回退到 HTML 列表页解析")
        for page in range(1, max_pages + 1):
            url = LIST_URL.format(page=page)
            try:
                r = s.get(url, timeout=timeout)
                r.raise_for_status()
            except Exception as e:
                print(f"[WARN] 列表页失败: {url} -> {e}")
                continue

            links = extract_skill_links(r.text)
            print(f"[INFO] page={page} (html) 抓到 skill 链接 {len(links)} 个")
            for u in links:
                if u not in all_skills:
                    all_skills.append(u)

            if len(all_skills) >= max_skills:
                all_skills = all_skills[:max_skills]
                break

            time.sleep(delay)

    print(f"[INFO] 待检查 skill 总数: {len(all_skills)}")

    hit = 0
    downloaded = 0
    skipped_existing = 0

    for i, skill_url in enumerate(all_skills, 1):
        base = safe_name_from_skill_url(skill_url)
        if not dry_run and already_downloaded(out_dir, base):
            skipped_existing += 1
            print(f"[SKIP] ({i}/{len(all_skills)}) 已存在: {skill_url}")
            time.sleep(delay)
            continue

        try:
            r = s.get(skill_url, timeout=timeout)
            r.raise_for_status()
            html = r.text
        except Exception as e:
            print(f"[WARN] ({i}/{len(all_skills)}) 打开失败: {skill_url} -> {e}")
            continue

        status_ok = True
        if vt_status == "pending":
            status_ok = detect_vt_pending(html)
        elif vt_status == "unscanned":
            status_ok = detect_unscanned(html)
        elif vt_status == "any":
            status_ok = True

        if not status_ok:
            lab = "Pending" if vt_status == "pending" else ("未扫描" if vt_status == "unscanned" else "任意")
            print(f"[SKIP] ({i}/{len(all_skills)}) 非{lab}: {skill_url}")
            time.sleep(delay)
            continue

        hit += 1
        dl = find_download_link(skill_url, html)
        if not dl:
            print(f"[HIT ] ({i}/{len(all_skills)}) 未扫描但没找到下载链接: {skill_url}")
            time.sleep(delay)
            continue

        if dry_run:
            out_path = probe_out_path(s, dl, out_dir, base, timeout=timeout)
            print(f"[HIT ] {skill_url}\n       download={dl}\n       out={out_path}")
        else:
            try:
                out_path = download_file(s, dl, out_dir, base, timeout=max(60, timeout))
                extracted_dir = extract_archive_and_remove(out_path, out_dir, base)
                downloaded += 1
                if extracted_dir:
                    print(f"[DOWN] {skill_url}\n       extracted={extracted_dir}")
                else:
                    print(f"[DOWN] {skill_url}\n       -> {out_path}")
            except Exception as e:
                print(f"[WARN] 下载失败: {dl} -> {e}")

        time.sleep(delay)

    print(
        f"\n[SUMMARY] 命中未扫描={hit}, 成功下载={downloaded}, 已存在跳过={skipped_existing}, 总检查={len(all_skills)}"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-root",
        default="/home/hejun/project/clawhub",
        help="输出根目录（会在其下按日期创建子目录）",
    )
    ap.add_argument(
        "--vt-status",
        choices=["pending", "unscanned", "any"],
        default="pending",
        help="筛选 VirusTotal 状态: pending=仅Pending, unscanned=未扫描/无结果类, any=不筛选",
    )
    ap.add_argument("--max-pages", type=int, default=5, help="扫描 newest 页数")
    ap.add_argument("--max-skills", type=int, default=200, help="最多检查 skill 数")
    ap.add_argument("--delay", type=float, default=1.5, help="请求间隔秒")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--dry-run", action="store_true", help="只打印，不下载")
    ap.add_argument("--interval-minutes", type=int, default=20, help="循环间隔分钟（默认: 20）")
    ap.add_argument("--once", action="store_true", help="只执行一次（不循环）")
    args = ap.parse_args()

    os.makedirs(args.out_root, exist_ok=True)
    if args.once:
        run_once(
            out_root=args.out_root,
            vt_status=args.vt_status,
            max_pages=args.max_pages,
            max_skills=args.max_skills,
            delay=args.delay,
            timeout=args.timeout,
            dry_run=args.dry_run,
        )
        return

    interval_seconds = max(1, int(args.interval_minutes) * 60)
    while True:
        try:
            run_once(
                out_root=args.out_root,
                vt_status=args.vt_status,
                max_pages=args.max_pages,
                max_skills=args.max_skills,
                delay=args.delay,
                timeout=args.timeout,
                dry_run=args.dry_run,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[WARN] 本轮执行异常: {e}")

        print(f"[INFO] 休眠 {interval_seconds} 秒后继续...")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    main()
