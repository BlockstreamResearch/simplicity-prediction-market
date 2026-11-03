import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { fetchAdmin } from "../src/admin-api";

const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");

afterEach(() => {
  mock.restore();
  if (originalWindow) {
    Object.defineProperty(globalThis, "window", originalWindow);
  } else {
    Reflect.deleteProperty(globalThis, "window");
  }
});

function browser(href = "https://market.example.test/?desk=1#admin") {
  const assign = mock((_url: string) => undefined);
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: { location: { href, assign } },
  });
  return assign;
}

function authRedirect() {
  const response = new Response(null);
  Object.defineProperty(response, "type", { value: "opaqueredirect" });
  return response;
}

test("admin requests preserve bodies, headers, and cancellation without following redirects", async () => {
  const assign = browser();
  const response = Response.json({ token: "fixture-token" });
  const fetch = spyOn(globalThis, "fetch").mockResolvedValue(response);
  const signal = new AbortController().signal;
  const init: RequestInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ login: "operator", password: "fixture-password" }),
    signal,
    redirect: "follow",
  };
  expect(
    await fetchAdmin("https://market.example.test/api/admin/login", init),
  ).toBe(response);
  expect(fetch).toHaveBeenCalledWith(
    "https://market.example.test/api/admin/login",
    { ...init, redirect: "manual" },
  );
  expect(assign).not.toHaveBeenCalled();
});

test("gateway redirects start browser sign-in and preserve the current page without replaying the request", async () => {
  const assign = browser();
  const fetch = spyOn(globalThis, "fetch").mockResolvedValue(authRedirect());
  await expect(
    fetchAdmin("/api/admin/predictions", {
      method: "POST",
      body: JSON.stringify({ title: "Fixture market" }),
    }),
  ).rejects.toThrow("Retry the admin action after signing in");
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(assign).toHaveBeenCalledTimes(1);
  const signIn = new URL(assign.mock.calls[0][0]);
  expect(signIn.origin).toBe("https://market.example.test");
  expect(signIn.pathname).toBe("/oauth2/start");
  expect(signIn.searchParams.get("rd")).toBe(
    "https://market.example.test/?desk=1#admin",
  );
});

test("operator authentication errors are returned without starting gateway sign-in", async () => {
  const assign = browser();
  const response = Response.json(
    { error: "invalid login or password" },
    { status: 401 },
  );
  spyOn(globalThis, "fetch").mockResolvedValue(response);
  expect(
    await fetchAdmin("https://market.example.test/api/admin/login"),
  ).toBe(response);
  expect(assign).not.toHaveBeenCalled();
});

test("network and cancellation errors propagate without starting sign-in", async () => {
  const assign = browser();
  const fetch = spyOn(globalThis, "fetch");
  for (const error of [
    new TypeError("Network unavailable"),
    new DOMException("Aborted", "AbortError"),
  ]) {
    fetch.mockRejectedValueOnce(error);
    await expect(
      fetchAdmin("https://market.example.test/api/admin/escrow"),
    ).rejects.toBe(error);
  }
  expect(assign).not.toHaveBeenCalled();
});

test("a separate API origin still works without an SSO gateway", async () => {
  const assign = browser();
  const response = Response.json({ token: "fixture-token" });
  spyOn(globalThis, "fetch").mockResolvedValue(response);
  expect(
    await fetchAdmin("https://api.example.test/api/admin/login"),
  ).toBe(response);
  expect(assign).not.toHaveBeenCalled();
});

test("cross-origin SSO reports the required proxy configuration instead of creating a redirect loop", async () => {
  const assign = browser();
  spyOn(globalThis, "fetch").mockResolvedValue(authRedirect());
  await expect(
    fetchAdmin("https://api.example.test/api/admin/login"),
  ).rejects.toThrow("same-origin API proxy. Leave VITE_SERVER_API unset");
  expect(assign).not.toHaveBeenCalled();
});
