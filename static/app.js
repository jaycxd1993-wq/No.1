"use strict";
const $ = (id) => document.getElementById(id);
let mode = "login", accessToken = null, expiresAt = 0;
let refreshPromise = null, pending = 0;

function notice(message, error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
}

function clearSession() {
  accessToken = null; expiresAt = 0;
  $("session-badge").textContent = "未登录";
  $("profile-email").textContent = "登录后，这里会显示你的邮箱。";
  $("identity-status").textContent = "等待登录";
  $("expiry").textContent = "—";
}

function acceptSession(data) {
  // Access tokens live only in this page's memory, never in local/session storage.
  accessToken = data.access_token;
  expiresAt = Date.now() + data.expires_in * 1000;
  $("session-badge").textContent = "已登录";
  $("expiry").textContent = new Date(expiresAt).toLocaleTimeString("zh-CN");
  if (data.user) showUser(data.user);
}

function showUser(user) {
  $("profile-email").textContent = user.email;
  $("identity-status").textContent = "已通过服务器验证";
}

async function request(path, body, authenticated = false) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authenticated && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, {method: body === undefined ? "GET" : "POST",
    headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: "same-origin"});
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.error || "请求失败，请重试。");
    error.status = response.status;
    throw error;
  }
  return data;
}

async function renew() {
  // Share one in-flight refresh so this page does not consume the same token twice.
  if (!refreshPromise) {
    refreshPromise = request("/api/auth/refresh", {}).then((data) => {
      acceptSession(data);
      return data;
    }).catch((error) => {
      if (error.status === 401) clearSession();
      throw error;
    }).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

async function loadProfile() {
  if (!accessToken || Date.now() >= expiresAt) await renew();
  try {
    showUser((await request("/api/me", undefined, true)).user);
  } catch (error) {
    if (error.status !== 401) throw error;
    await renew();
    showUser((await request("/api/me", undefined, true)).user);
  }
}

async function run(action) {
  pending += 1;
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  try { await action(); }
  catch (error) { notice(error.status ? error.message : "无法连接服务，请确认本机服务已启动。", true); }
  finally {
    pending -= 1;
    if (!pending) document.querySelectorAll("button").forEach((button) => { button.disabled = false; });
  }
}

function setMode(value) {
  mode = value;
  $("login-mode").setAttribute("aria-pressed", String(mode === "login"));
  $("register-mode").setAttribute("aria-pressed", String(mode === "register"));
  $("form-title").textContent = mode === "login" ? "欢迎回来" : "创建你的账号";
  $("form-description").textContent = mode === "login" ? "还没有账号？切换到注册即可创建。" : "注册成功后，使用相同邮箱和密码登录。";
  $("password").autocomplete = mode === "login" ? "current-password" : "new-password";
  $("submit").textContent = mode === "login" ? "登录" : "创建账号";
}

$("login-mode").onclick = () => setMode("login");
$("register-mode").onclick = () => setMode("register");
$("auth-form").onsubmit = (event) => {
  event.preventDefault();
  run(async () => {
    const data = await request(`/api/auth/${mode}`, {email: $("email").value, password: $("password").value});
    $("password").value = "";
    if (mode === "register") {
      setMode("login"); notice("注册成功，请输入密码登录。");
    } else {
      acceptSession(data); notice("登录成功。现在可以查看个人资料。");
    }
  });
};
$("me").onclick = () => run(async () => { await loadProfile(); notice("个人资料已从服务器读取。"); });
$("refresh").onclick = () => run(async () => { await renew(); await loadProfile(); notice("登录已续期，旧令牌已失效。"); });
$("logout").onclick = () => run(async () => {
  await request("/api/auth/logout", {});
  clearSession(); notice("已退出。服务器上的会话已撤销。");
});

run(async () => {
  try { await renew(); await loadProfile(); notice("已恢复登录。"); }
  catch (error) {
    if (error.status === 401) { clearSession(); notice("可以先注册一个账号。"); }
    else throw error;
  }
});
