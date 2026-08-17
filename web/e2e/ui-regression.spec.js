const { test, expect } = require("@playwright/test");
const { mkdtemp, mkdir, readFile, rm, utimes, writeFile } = require("node:fs/promises");
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
  const shareExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  await writeFile(path.join(docs, ".env"), "title='浏览器断言资料'\npassword='plain:浏览器断言密码123'\nSHARE_ENABLED='true'\nSHARE_DOC_ENABLED='true'\nSHARE_DOC_SCOPE='file'\nSHARE_DOC_PATH='page.html'\nSHARE_DOC_TOKEN='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'\nSHARE_DOC_EXPIRES_AT='" + shareExpiresAt + "'\nSHARE_DOC_PASSWORD='plain:浏览器断言密码123'\nSHARE_DOC_ALLOW_DOWNLOAD='true'\nSHARE_FOLDER_ENABLED='true'\nSHARE_FOLDER_SCOPE='directory'\nSHARE_FOLDER_PATH='目录项'\nSHARE_FOLDER_TOKEN='BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBQ'\nSHARE_FOLDER_EXPIRES_AT='" + shareExpiresAt + "'\nSHARE_FOLDER_PASSWORD='plain:浏览器断言密码123'\nSHARE_FOLDER_ALLOW_DOWNLOAD='false'\nSHARE_CURRENT_ENABLED='true'\nSHARE_CURRENT_SCOPE='directory'\nSHARE_CURRENT_PATH='.'\nSHARE_CURRENT_TOKEN='CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCQ'\nSHARE_CURRENT_EXPIRES_AT='" + shareExpiresAt + "'\nSHARE_CURRENT_PASSWORD='plain:浏览器断言密码123'\nSHARE_CURRENT_ALLOW_DOWNLOAD='true'\n");
  await writeFile(path.join(docs, "page.html"), "<!doctype html><h1>受控 HTML</h1>");
  await mkdir(path.join(docs, "目录项"));
  await writeFile(path.join(docs, "alpha.bin"), Buffer.alloc(2));
  await writeFile(path.join(docs, "zeta.bin"), Buffer.alloc(2048));
  await writeFile(path.join(docs, "README"), "无扩展名");
  await writeFile(path.join(docs, "photo.JPG"), "大写扩展名");
  await writeFile(path.join(docs, "photo.jpg"), "小写扩展名");
  await writeFile(path.join(docs, "notes.md"), "Markdown");
  await utimes(path.join(docs, "alpha.bin"), new Date("2026-01-01T00:00:00Z"), new Date("2026-01-01T00:00:00Z"));
  await utimes(path.join(docs, "zeta.bin"), new Date("2040-03-01T00:00:00Z"), new Date("2040-03-01T00:00:00Z"));
  await Promise.all(Array.from({ length: 36 }, (_, index) => writeFile(path.join(docs, "scroll-" + String(index).padStart(2, "0") + ".txt"), "滚动测试")));
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

test("可用分享链接复制后会向辅助技术宣布结果", async ({ page }) => {
  await signIn(page);
  const configPath = path.join(dataRoot, "docs", ".env");
  const config = await readFile(configPath, "utf8");
  const passwordHash = config.match(/^password='(hash:[^']+)'$/m);
  expect(passwordHash).not.toBeNull();
  await writeFile(configPath, config.replace("SHARE_DOC_PASSWORD='plain:浏览器断言密码123'", "SHARE_DOC_PASSWORD='" + passwordHash[1] + "'"));
  await page.reload();
  await page.getByRole("button", { name: "预览源码" }).click();
  await expect(page.getByRole("button", { name: "复制链接" })).toBeVisible();
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: () => Promise.resolve() },
  }));
  await page.getByRole("button", { name: "复制链接" }).click();
  await expect(page.getByRole("status")).toHaveText("分享链接已复制。");
});

test("当前目录可创建分享，并保留权限和有效期提示", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "分享当前目录" }).click();
  const dialog = page.locator("#share-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(dialog.getByRole("heading", { name: "创建当前目录分享" })).toBeVisible();
  await expect(dialog.getByText("将分享当前目录及其内容。")).toBeVisible();
  await expect(dialog.getByText("请确认下载权限和有效期，再创建。")).toBeVisible();
  await dialog.getByLabel("访问密码").fill("当前目录分享密码123");
  const request = page.waitForRequest((candidate) => candidate.url() === baseURL + "/docs/_shares" && candidate.method() === "POST");
  const response = page.waitForResponse((candidate) => candidate.url() === baseURL + "/docs/_shares" && candidate.status() === 201);
  await dialog.getByRole("button", { name: "创建链接" }).click();
  expect(JSON.parse((await request).postData())).toMatchObject({ scope: "directory", path: ".", allow_download: true });
  await response;
  await expect(dialog.getByText("分享链接已创建。")).toBeVisible();
  await expect(dialog.getByLabel("分享链接")).toHaveValue(/\/_s\//);
});

test("已授权目录可统一管理文件、文件夹和当前目录分享", async ({ page }) => {
  await signIn(page);
  await page.getByRole("button", { name: "管理分享" }).click();
  const dialog = page.locator("#share-management-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(dialog.getByText("文件 · page.html")).toBeVisible();
  await expect(dialog.getByText("文件夹 · 目录项")).toBeVisible();
  await expect(dialog.getByText("当前目录分享").first()).toBeVisible();
  await expect(dialog.getByText("密码：需要验证").first()).toBeVisible();
  await expect(dialog.getByText("下载：允许").first()).toBeVisible();
  await expect(dialog.getByText("下载：禁止")).toBeVisible();
  await expect(dialog.getByRole("link", { name: "查看" }).first()).toHaveAttribute("href", /\/_s\//);
  await page.evaluate(() => Object.defineProperty(navigator, "clipboard", {
    configurable: true,
    value: { writeText: () => Promise.resolve() },
  }));
  await dialog.getByRole("button", { name: "复制链接" }).first().click();
  await expect(dialog.getByRole("status")).toHaveText("分享链接已复制。");
  page.once("dialog", (confirmation) => confirmation.accept());
  const fileShare = dialog.locator(".share-management-item", { hasText: "文件 · page.html" });
  await fileShare.getByRole("button", { name: "删除" }).click();
  await expect(dialog.getByText("文件 · page.html")).toHaveCount(0);
  await expect(dialog.getByText("文件夹 · 目录项")).toBeVisible();
  await expect.poll(() => readFile(path.join(dataRoot, "docs", ".env"), "utf8")).not.toContain("SHARE_DOC_TOKEN");
});

test("键盘提供跳到主要内容入口", async ({ page }) => {
  await page.goto(baseURL + "/");
  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "跳到主要内容" });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#content")).toBeFocused();
});

test("目录表头可稳定排序，并在长页提供滚动导航", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 700 });
  await signIn(page);
  const nameSort = page.getByRole("button", { name: "名称" });
  await expect(nameSort).toHaveAttribute("aria-sort", "none");
  await nameSort.click();
  await expect(nameSort).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator(".entry-link").first()).toHaveText("alpha.bin");
  await nameSort.click();
  await expect(nameSort).toHaveAttribute("aria-sort", "descending");
  expect(await page.locator(".entry-link").allTextContents()).toEqual(expect.arrayContaining(["zeta.bin", "alpha.bin"]));
  expect(await page.locator(".entry-link").evaluateAll((links) => links.findIndex((link) => link.textContent === "zeta.bin") < links.findIndex((link) => link.textContent === "alpha.bin"))).toBe(true);

  const typeSort = page.getByRole("button", { name: "类型" });
  await typeSort.click();
  await expect(typeSort).toHaveAttribute("aria-sort", "ascending");
  const typeOrder = await page.locator(".entry-link").allTextContents();
  expect(typeOrder.indexOf("目录项")).toBeLessThan(typeOrder.indexOf("README"));
  expect(typeOrder.indexOf("README")).toBeLessThan(typeOrder.indexOf("notes.md"));
  expect(typeOrder.indexOf("photo.JPG")).toBeLessThan(typeOrder.indexOf("photo.jpg"));
  await typeSort.click();
  await expect(typeSort).toHaveAttribute("aria-sort", "descending");
  const descendingTypeOrder = await page.locator(".entry-link").allTextContents();
  expect(descendingTypeOrder.indexOf("photo.jpg")).toBeLessThan(descendingTypeOrder.indexOf("photo.JPG"));
  expect(descendingTypeOrder.indexOf("README")).toBeLessThan(descendingTypeOrder.indexOf("目录项"));

  const sizeSort = page.getByRole("button", { name: "大小" });
  await sizeSort.click();
  await expect(sizeSort).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator(".entry-link").first()).toHaveText("alpha.bin");

  const modifiedSort = page.getByRole("button", { name: "修改时间" });
  await modifiedSort.click();
  await expect(modifiedSort).toHaveAttribute("aria-sort", "ascending");
  await expect(page.locator(".entry-link").first()).toHaveText("alpha.bin");
  await modifiedSort.click();
  await expect(modifiedSort).toHaveAttribute("aria-sort", "descending");
  await expect(page.locator(".entry-link").first()).toHaveText("zeta.bin");

  const bottom = page.getByRole("button", { name: "前往底部" });
  await expect(bottom).toBeVisible();
  const header = page.locator(".directory-heading-row");
  const initialHeader = await header.boundingBox();
  expect(initialHeader).not.toBeNull();
  await bottom.click();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
  const fixedHeader = await header.boundingBox();
  expect(fixedHeader).not.toBeNull();
  expect(fixedHeader.y).toBeGreaterThanOrEqual(0);
  expect(fixedHeader.y).toBeLessThanOrEqual(initialHeader.y);
  const top = page.getByRole("button", { name: "返回顶部" });
  await expect(top).toBeVisible();
  await top.click();
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
});

test("移动端保留四项排序，并支持键盘操作", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  const nameSort = page.getByRole("button", { name: "名称" });
  const typeSort = page.getByRole("button", { name: "类型" });
  const sizeSort = page.getByRole("button", { name: "大小" });
  const modifiedSort = page.getByRole("button", { name: "修改时间" });
  await expect(nameSort).toBeVisible();
  await expect(typeSort).toBeVisible();
  await expect(sizeSort).toBeVisible();
  await expect(modifiedSort).toBeVisible();
  const alphaRow = page.locator(".entry", { has: page.getByRole("link", { name: "alpha.bin" }) });
  const alphaSize = alphaRow.locator(".entry-size");
  await expect(alphaSize).toBeVisible();
  const [sizeHeaderBox, sizeValueBox] = await Promise.all([sizeSort.boundingBox(), alphaSize.boundingBox()]);
  expect(sizeHeaderBox).not.toBeNull();
  expect(sizeValueBox).not.toBeNull();
  expect(Math.abs(sizeHeaderBox.x - sizeValueBox.x)).toBeLessThanOrEqual(1);
  await sizeSort.focus();
  await page.keyboard.press("Enter");
  await expect(sizeSort).toHaveAttribute("aria-sort", "ascending");
  await page.keyboard.press("Space");
  await expect(sizeSort).toHaveAttribute("aria-sort", "descending");
  await modifiedSort.focus();
  await page.keyboard.press("Enter");
  await expect(modifiedSort).toHaveAttribute("aria-sort", "ascending");
});
