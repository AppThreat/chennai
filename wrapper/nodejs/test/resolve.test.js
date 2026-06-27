import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { resolveChennaiProvider, getLinuxLibc } from "../packages/chennai/resolve.js";

describe("resolveChennaiProvider", () => {
  it("resolves darwin arm64 to native", () => {
    const r = resolveChennaiProvider({ platform: "darwin", arch: "arm64" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-darwin-arm64");
    assert.equal(r.kind, "native");
  });

  it("resolves darwin x64 to jar fallback", () => {
    const r = resolveChennaiProvider({ platform: "darwin", arch: "x64" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-darwin-amd64");
    assert.equal(r.kind, "jar");
  });

  it("resolves linux x64 glibc to native", () => {
    const r = resolveChennaiProvider({ platform: "linux", arch: "x64", libc: "glibc" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-linux-amd64");
    assert.equal(r.kind, "native");
  });

  it("resolves linux x64 musl to native musl", () => {
    const r = resolveChennaiProvider({ platform: "linux", arch: "x64", libc: "musl" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-linux-amd64-musl");
    assert.equal(r.kind, "native");
  });

  it("resolves linux arm64 glibc to native", () => {
    const r = resolveChennaiProvider({ platform: "linux", arch: "arm64", libc: "glibc" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-linux-arm64");
    assert.equal(r.kind, "native");
  });

  it("resolves linux arm64 musl to jar fallback", () => {
    const r = resolveChennaiProvider({ platform: "linux", arch: "arm64", libc: "musl" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-linux-arm64-musl");
    assert.equal(r.kind, "jar");
  });

  it("resolves win32 x64 to native", () => {
    const r = resolveChennaiProvider({ platform: "win32", arch: "x64" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-windows-amd64");
    assert.equal(r.kind, "native");
  });

  it("resolves win32 arm64 to jar fallback", () => {
    const r = resolveChennaiProvider({ platform: "win32", arch: "arm64" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-win32-arm64");
    assert.equal(r.kind, "jar");
  });

  it("resolves unknown platform to jar fallback", () => {
    const r = resolveChennaiProvider({ platform: "freebsd", arch: "x64" });
    assert.equal(r.preferredPkg, "@appthreat/chennai-jar");
    assert.equal(r.kind, "jar");
  });
});
