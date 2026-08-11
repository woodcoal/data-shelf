const { test, expect } = require("@playwright/test");
const { mkdtemp, mkdir, rm, writeFile } = require("node:fs/promises");
const { once } = require("node:events");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const repositoryRoot = path.resolve(__dirname, "../..");
let dataRoot;
let baseURL;
let service;

function reservePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const { port } = listener.address();
      listener.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function requestStatus(url) {
  return new Promise((resolve, reject) => {
    const request = http.get(url, (response) => {
      response.resume();
      resolve(response.statusCode);
    });
    request.once("error", reject);
  });
}

async function waitForService() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      if (await requestStatus(baseURL + "/")) {
        return;
      }
    } catch (_) {
      // The Go process may still be compiling; try again before the deadline.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("DataShelf test service did not become available");
}

async function signIn(page) {
  await page.goto(baseURL + "/docs/");
  await page.getByLabel("密码").fill("浏览器断言密码123");
  await page.getByRole("button", { name: "进入资料" }).click();
  await expect(page).toHaveURL(baseURL + "/docs/");
}

test.beforeAll(async () => {
  dataRoot = await mkdtemp(path.join(os.tmpdir(), "datashelf-ui-"));
  const docs = path.join(dataRoot, "docs");
  await mkdir(docs);
  await writeFile(path.join(docs, ".env"), "title='浏览器断言资料'\npassword='plain:浏览器断言密码123'\n");
  await writeFile(path.join(docs, "page.html"), "<!doctype html><h1>受控 HTML</h1>");
  const port = await reservePort();
  baseURL = "http://127.0.0.1:" + port;
  service = spawn("go", ["run", ".", "-dir", dataRoot, "-host", "127.0.0.1", "-port", String(port)], {
    cwd: repositoryRoot,
    stdio: "ignore",
  });
  await waitForService();
});

test.afterAll(async () => {
  if (service && !service.killed) {
    service.kill("SIGTERM");
    await once(service, "exit");
  }
  await rm(dataRoot, { recursive: true, force: true });
});

for (const viewport of [
  { name: "桌面 1440px", width: 1440, height: 1000 },
  { name: "移动 390px", width: 390, height: 844 },
]) {
  test("密码页操作在" + viewport.name + "共用水平中心", async ({ page }) => {
    await page.setViewportSize(viewport);
    await page.goto(baseURL + "/docs/");
    const [submit, back] = await Promise.all([
      page.getByRole("button", { name: "进入资料" }).boundingBox(),
      page.getByRole("link", { name: "返回资料架" }).boundingBox(),
    ]);
    expect(submit).not.toBeNull();
    expect(back).not.toBeNull();
    expect(Math.abs(submit.x + submit.width / 2 - (back.x + back.width / 2))).toBeLessThanOrEqual(0.5);
    expect(submit.x).toBeGreaterThanOrEqual(0);
    expect(submit.x + submit.width).toBeLessThanOrEqual(viewport.width);
    expect(back.x).toBeGreaterThanOrEqual(0);
    expect(back.x + back.width).toBeLessThanOrEqual(viewport.width);
  });
}

test("HTML 文件名进入受控视图，源码按钮保留弹窗预览", async ({ page }) => {
  await signIn(page);
  const htmlLink = page.getByRole("link", { name: "page.html" });
  await expect(htmlLink).not.toHaveAttribute("data-preview-kind");
  await htmlLink.click();
  await expect(page).toHaveURL(baseURL + "/docs/_html/page.html");
  await expect(page.locator("iframe")).toHaveAttribute("src", "/docs/_html-content/page.html");

  await page.goto(baseURL + "/docs/");
  await page.getByRole("button", { name: "预览源码" }).click();
  await expect(page.locator("#preview-dialog")).toHaveAttribute("open", "");
  await expect(page.locator("#preview-kind-label")).toHaveText("HTML 源码预览");
});
