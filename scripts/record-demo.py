#!/usr/bin/env python3
"""Record the README demo from a real DataShelf browser session."""

from __future__ import annotations

import io
import re
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PIL import Image
from playwright.sync_api import Page, sync_playwright


ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = ROOT / "assets"
PASSWORD = "demo-password123"
TOKEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def reserve_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_service(base_url: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"DataShelf exited with status {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", int(base_url.rsplit(":", 1)[1])), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("DataShelf did not become available")


def capture(frames: list[Image.Image], page: Page) -> None:
    image = Image.open(io.BytesIO(page.screenshot())).convert("RGB")
    frames.append(image.resize((960, 540), Image.Resampling.LANCZOS))


def main() -> None:
    data_root = Path(tempfile.mkdtemp(prefix="datashelf-demo-"))
    try:
        app_dir = data_root / "agent-result"
        app_dir.mkdir()
        share_expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat().replace("+00:00", "Z")
        (app_dir / "report.html").write_text(
            """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #102a43; color: #f0f4f8; font: 18px/1.6 system-ui, sans-serif; }
  main { width: min(680px, calc(100vw - 64px)); padding: 44px; border: 1px solid #486581; border-radius: 24px; background: #243b53; box-shadow: 0 18px 50px #06152580; }
  .eyebrow { color: #8fe3cf; letter-spacing: .12em; text-transform: uppercase; font-size: 12px; }
  code { color: #b3ecff; }
</style>
<main>
  <div class="eyebrow">Agent-generated HTML</div>
  <h1>固定链接仍然有效</h1>
  <p>这是一页由 Agent 生成并放入本地资料目录的自包含 HTML。</p>
  <p>DataShelf 将它通过受控的固定分享链接提供访问。</p>
  <p><code>/_s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/</code></p>
</main>
""",
            encoding="utf-8",
        )
        (app_dir / ".env").write_text(
            "\n".join(
                [
                    "title='Agent HTML demo'",
                    f"password='plain:{PASSWORD}'",
                    "SHARE_ENABLED='true'",
                    "SHARE_DOC_ENABLED='true'",
                    "SHARE_DOC_SCOPE='file'",
                    "SHARE_DOC_PATH='report.html'",
                    f"SHARE_DOC_TOKEN='{TOKEN}'",
                    f"SHARE_DOC_EXPIRES_AT='{share_expires_at}'",
                    f"SHARE_DOC_PASSWORD='plain:{PASSWORD}'",
                    "SHARE_DOC_ALLOW_DOWNLOAD='false'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        port = reserve_port()
        base_url = f"http://127.0.0.1:{port}"
        process = subprocess.Popen(
            ["go", "run", ".", "-dir", str(data_root), "-host", "127.0.0.1", "-port", str(port)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            wait_for_service(base_url, process)
            frames: list[Image.Image] = []
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1280, "height": 720}, device_scale_factor=1)
                page.goto(f"{base_url}/agent-result/", wait_until="networkidle")
                capture(frames, page)

                page.get_by_label("密码").fill(PASSWORD)
                page.get_by_role("button", name="进入资料").click()
                page.wait_for_url(f"{base_url}/agent-result/")
                page.wait_for_load_state("networkidle")
                capture(frames, page)

                env_path = app_dir / ".env"
                env_text = env_path.read_text(encoding="utf-8")
                password_hash = re.search(r"^password='(hash:[^']+)'$", env_text, re.MULTILINE)
                if password_hash is None:
                    raise RuntimeError("DataShelf did not migrate the demo password")
                env_path.write_text(
                    env_text.replace(f"SHARE_DOC_PASSWORD='plain:{PASSWORD}'", f"SHARE_DOC_PASSWORD='{password_hash.group(1)}'"),
                    encoding="utf-8",
                )
                page.reload(wait_until="networkidle")
                page.get_by_role("button", name="预览源码").click()
                page.locator("#preview-share-status").wait_for(state="visible")
                capture(frames, page)

                with page.expect_popup() as popup_info:
                    page.get_by_role("link", name="打开分享").click()
                share_page = popup_info.value
                share_page.wait_for_load_state("networkidle")
                if f"/_s/{TOKEN}/" not in share_page.url:
                    raise RuntimeError(f"unexpected share URL: {share_page.url}")
                capture(frames, share_page)

                share_page.get_by_label("访问密码").fill(PASSWORD)
                share_page.get_by_role("button", name="打开分享").click()
                share_page.wait_for_url(re.compile(r"/_s/[^/]+/_html$"))
                share_page.wait_for_load_state("networkidle")
                share_page.frame_locator("iframe").get_by_text("固定链接仍然有效").wait_for()
                capture(frames, share_page)
                browser.close()

            ASSET_DIR.mkdir(exist_ok=True)
            output = ASSET_DIR / "demo.gif"
            frames[0].save(
                output,
                save_all=True,
                append_images=frames[1:],
                duration=[1800, 1800, 2200, 1800, 2600],
                loop=0,
                optimize=False,
            )
            print(f"wrote {output} ({output.stat().st_size} bytes)")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    finally:
        shutil.rmtree(data_root, ignore_errors=True)


if __name__ == "__main__":
    main()
