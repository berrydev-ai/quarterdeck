import { createHash, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Duplex } from "node:stream";

import { getQuarterdeckRuntimeHost, getQuarterdeckRuntimeOrigin, getQuarterdeckRuntimePort } from "../core";

const VITE_DEV_PORT = 4173;
const PREFLIGHT_MAX_AGE_SECONDS = "600";
const ALLOWED_METHODS = ["GET", "POST", "OPTIONS"].join(", ");
const ALLOWED_HEADERS = ["Authorization", "Content-Type", "X-Quarterdeck-Client-Id", "X-Quarterdeck-Project-Id"].join(
	", ",
);

export type CorsDecision =
	| { kind: "allow"; origin: string | null }
	| { kind: "preflight"; origin: string }
	| { kind: "reject"; origin: string };

export interface CorsGateInput {
	method: string | undefined;
	originHeader: string | undefined;
	allowedOrigins: ReadonlySet<string>;
}

export type HostDecision = { kind: "allow" } | { kind: "reject"; host: string | null };

export interface HostGateInput {
	hostHeader: string | undefined;
	allowedHosts: ReadonlySet<string>;
}

export type AccessAuthDecision = { kind: "allow" } | { kind: "reject" };

export interface AccessAuthInput {
	authorizationHeader: string | undefined;
	cookieHeader: string | undefined;
	password: string | null;
	username: string;
}

interface AccessCredentials {
	password: string | null;
	username: string;
}

function isDevelopmentMode(): boolean {
	return process.env.NODE_ENV === "development";
}

function normalizeHeaderValue(value: string | undefined): string | null {
	const trimmed = value?.trim();
	return trimmed ? trimmed : null;
}

function addHttpOrigin(origins: Set<string>, host: string, port: number): void {
	origins.add(`http://${host}:${port}`);
}

function addHostHeader(hosts: Set<string>, host: string, port: number): void {
	hosts.add(`${host}:${port}`.toLowerCase());
}

function addExternalHostHeader(hosts: Set<string>, host: string): void {
	hosts.add(host.toLowerCase());
}

function readOptionalPort(value: string | undefined): number | null {
	const normalized = value?.trim();
	if (!normalized || !/^\d+$/.test(normalized)) {
		return null;
	}
	const parsed = Number.parseInt(normalized, 10);
	return Number.isFinite(parsed) && parsed > 0 && parsed <= 65535 ? parsed : null;
}

function getDevelopmentWebUiPorts(): number[] {
	const ports = new Set<number>([VITE_DEV_PORT]);
	for (const rawPort of [process.env.QUARTERDECK_WEB_UI_PORT, process.env.QUARTERDECK_E2E_WEB_PORT]) {
		const parsed = readOptionalPort(rawPort);
		if (parsed !== null) {
			ports.add(parsed);
		}
	}
	return [...ports];
}

function parseAllowedHostEntry(value: string): { host: string; origins: string[] } | null {
	if (value.startsWith("http://") || value.startsWith("https://")) {
		try {
			const url = new URL(value);
			if (!url.host) {
				return null;
			}
			return { host: url.host.toLowerCase(), origins: [url.origin] };
		} catch {
			return null;
		}
	}

	if (value.includes("/") || value.includes("@")) {
		return null;
	}

	try {
		const url = new URL(`https://${value}`);
		if (!url.hostname || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
			return null;
		}
		return {
			host: url.host.toLowerCase(),
			origins: [`http://${url.host.toLowerCase()}`, `https://${url.host.toLowerCase()}`],
		};
	} catch {
		return null;
	}
}

function parseExternalHostAllowlist(): Array<{ host: string; origins: string[] }> {
	const raw = process.env.QUARTERDECK_ALLOWED_HOSTS?.trim();
	if (!raw) {
		return [];
	}

	const entries: Array<{ host: string; origins: string[] }> = [];
	for (const part of raw.split(",")) {
		const value = part.trim();
		if (!value) {
			continue;
		}

		const parsed = parseAllowedHostEntry(value);
		if (parsed !== null) {
			entries.push(parsed);
		}
	}
	return entries;
}

export function getAllowedRuntimeOrigins(): ReadonlySet<string> {
	const port = getQuarterdeckRuntimePort();
	const runtimeHost = getQuarterdeckRuntimeHost().toLowerCase();
	const allowed = new Set<string>([getQuarterdeckRuntimeOrigin()]);

	addHttpOrigin(allowed, runtimeHost, port);
	addHttpOrigin(allowed, "127.0.0.1", port);
	addHttpOrigin(allowed, "localhost", port);
	addHttpOrigin(allowed, "[::1]", port);

	if (isDevelopmentMode()) {
		for (const webUiPort of getDevelopmentWebUiPorts()) {
			addHttpOrigin(allowed, "127.0.0.1", webUiPort);
			addHttpOrigin(allowed, "localhost", webUiPort);
			addHttpOrigin(allowed, "[::1]", webUiPort);
		}
	}

	for (const entry of parseExternalHostAllowlist()) {
		for (const origin of entry.origins) {
			allowed.add(origin);
		}
	}

	return allowed;
}

export function getAllowedHostHeaders(): ReadonlySet<string> {
	const port = getQuarterdeckRuntimePort();
	const runtimeHost = getQuarterdeckRuntimeHost().toLowerCase();
	const allowed = new Set<string>();

	addHostHeader(allowed, runtimeHost, port);
	addHostHeader(allowed, "127.0.0.1", port);
	addHostHeader(allowed, "localhost", port);
	addHostHeader(allowed, "[::1]", port);

	for (const entry of parseExternalHostAllowlist()) {
		addExternalHostHeader(allowed, entry.host);
	}

	return allowed;
}

export function evaluateCors(input: CorsGateInput): CorsDecision {
	const origin = normalizeHeaderValue(input.originHeader);
	if (origin === null) {
		return { kind: "allow", origin: null };
	}

	if (!input.allowedOrigins.has(origin)) {
		return { kind: "reject", origin };
	}

	if (input.method === "OPTIONS") {
		return { kind: "preflight", origin };
	}

	return { kind: "allow", origin };
}

export function evaluateHost(input: HostGateInput): HostDecision {
	const host = normalizeHeaderValue(input.hostHeader);
	if (host === null) {
		return { kind: "reject", host: null };
	}

	if (!input.allowedHosts.has(host.toLowerCase())) {
		return { kind: "reject", host };
	}

	return { kind: "allow" };
}

function getAccessPassword(): string | null {
	const value = process.env.QUARTERDECK_ACCESS_PASSWORD?.trim();
	return value ? value : null;
}

function getAccessUsername(): string {
	return process.env.QUARTERDECK_ACCESS_USERNAME?.trim() || "quarterdeck";
}

function getAccessCredentials(): AccessCredentials {
	return {
		password: getAccessPassword(),
		username: getAccessUsername(),
	};
}

function timingSafeStringEqual(a: string, b: string): boolean {
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	return left.length === right.length && timingSafeEqual(left, right);
}

function buildAccessToken(username: string, password: string): string {
	return createHash("sha256").update(`${username}:${password}`).digest("hex");
}

function readAccessCookie(cookieHeader: string | undefined): string | null {
	const header = normalizeHeaderValue(cookieHeader);
	if (header === null) {
		return null;
	}
	for (const part of header.split(";")) {
		const [rawName, ...rawValueParts] = part.trim().split("=");
		if (rawName === "quarterdeck_access") {
			const value = rawValueParts.join("=").trim();
			return value ? value : null;
		}
	}
	return null;
}

export function evaluateAccessAuth(input: AccessAuthInput): AccessAuthDecision {
	if (input.password === null) {
		return { kind: "allow" };
	}

	const accessToken = buildAccessToken(input.username, input.password);
	const cookieToken = readAccessCookie(input.cookieHeader);
	if (cookieToken !== null && timingSafeStringEqual(cookieToken, accessToken)) {
		return { kind: "allow" };
	}

	const header = normalizeHeaderValue(input.authorizationHeader);
	if (header === null || !header.toLowerCase().startsWith("basic ")) {
		return { kind: "reject" };
	}

	const encodedCredentials = header.slice(6).trim();
	let decodedCredentials: string;
	try {
		decodedCredentials = Buffer.from(encodedCredentials, "base64").toString("utf8");
	} catch {
		return { kind: "reject" };
	}

	const separatorIndex = decodedCredentials.indexOf(":");
	if (separatorIndex < 0) {
		return { kind: "reject" };
	}

	const username = decodedCredentials.slice(0, separatorIndex);
	const password = decodedCredentials.slice(separatorIndex + 1);
	if (!timingSafeStringEqual(username, input.username) || !timingSafeStringEqual(password, input.password)) {
		return { kind: "reject" };
	}

	return { kind: "allow" };
}

function buildAccessCookie(username: string, password: string, secure: boolean): string {
	const token = buildAccessToken(username, password);
	const secureAttribute = secure ? "; Secure" : "";
	return `quarterdeck_access=${token}; Path=/; HttpOnly; SameSite=Lax${secureAttribute}`;
}

function applyAllowedOriginHeaders(res: ServerResponse, origin: string): void {
	res.setHeader("Access-Control-Allow-Origin", origin);
	res.setHeader("Access-Control-Allow-Credentials", "true");
	res.setHeader("Vary", "Origin");
}

function rejectHttpRequest(res: ServerResponse, message: string): { end: true } {
	res.writeHead(403, {
		"Cache-Control": "no-store",
		"Content-Type": "application/json; charset=utf-8",
	});
	res.end(JSON.stringify({ error: message }));
	return { end: true };
}

function rejectUnauthorizedHttpRequest(res: ServerResponse): { end: true } {
	res.writeHead(401, {
		"Cache-Control": "no-store",
		"Content-Type": "application/json; charset=utf-8",
		"WWW-Authenticate": 'Basic realm="Quarterdeck", charset="UTF-8"',
	});
	res.end(JSON.stringify({ error: "Authentication required." }));
	return { end: true };
}

function rejectSocketUpgrade(socket: Duplex): { end: true } {
	socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
	socket.destroy();
	return { end: true };
}

function rejectUnauthorizedSocketUpgrade(socket: Duplex): { end: true } {
	socket.write(
		'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Quarterdeck", charset="UTF-8"\r\nConnection: close\r\n\r\n',
	);
	socket.destroy();
	return { end: true };
}

function getHeaderValue(value: string | string[] | undefined): string | undefined {
	return Array.isArray(value) ? value[0] : value;
}

function isAccessCookieSecureRequest(req: IncomingMessage): boolean {
	const forwardedProto = getHeaderValue(req.headers["x-forwarded-proto"])?.toLowerCase();
	if (
		forwardedProto
			?.split(",")
			.map((value) => value.trim())
			.includes("https")
	) {
		return true;
	}
	return process.env.QUARTERDECK_ACCESS_COOKIE_SECURE === "true";
}

export function handleHttpRequest(req: IncomingMessage, res: ServerResponse): { end: boolean } {
	const hostDecision = evaluateHost({
		hostHeader: req.headers.host,
		allowedHosts: getAllowedHostHeaders(),
	});
	if (hostDecision.kind === "reject") {
		return rejectHttpRequest(res, "Host not allowed.");
	}

	const corsDecision = evaluateCors({
		method: req.method,
		originHeader: req.headers.origin,
		allowedOrigins: getAllowedRuntimeOrigins(),
	});
	switch (corsDecision.kind) {
		case "allow": {
			if (corsDecision.origin !== null) {
				applyAllowedOriginHeaders(res, corsDecision.origin);
			}
			const accessCredentials = getAccessCredentials();
			const authDecision = evaluateAccessAuth({
				authorizationHeader: getHeaderValue(req.headers.authorization),
				cookieHeader: getHeaderValue(req.headers.cookie),
				password: accessCredentials.password,
				username: accessCredentials.username,
			});
			if (authDecision.kind === "reject") {
				return rejectUnauthorizedHttpRequest(res);
			}
			if (accessCredentials.password !== null) {
				res.setHeader(
					"Set-Cookie",
					buildAccessCookie(
						accessCredentials.username,
						accessCredentials.password,
						isAccessCookieSecureRequest(req),
					),
				);
			}
			return { end: false };
		}
		case "preflight": {
			applyAllowedOriginHeaders(res, corsDecision.origin);
			res.setHeader("Access-Control-Allow-Methods", ALLOWED_METHODS);
			res.setHeader("Access-Control-Allow-Headers", ALLOWED_HEADERS);
			res.setHeader("Access-Control-Max-Age", PREFLIGHT_MAX_AGE_SECONDS);
			res.writeHead(204);
			res.end();
			return { end: true };
		}
		case "reject": {
			return rejectHttpRequest(res, "Origin not allowed.");
		}
	}
}

export function handleSocketUpgrade(request: IncomingMessage, socket: Duplex): { end: boolean } {
	const hostDecision = evaluateHost({
		hostHeader: request.headers.host,
		allowedHosts: getAllowedHostHeaders(),
	});
	if (hostDecision.kind === "reject") {
		return rejectSocketUpgrade(socket);
	}

	const corsDecision = evaluateCors({
		method: request.method,
		originHeader: request.headers.origin,
		allowedOrigins: getAllowedRuntimeOrigins(),
	});
	if (corsDecision.kind === "reject") {
		return rejectSocketUpgrade(socket);
	}

	const authDecision = evaluateAccessAuth({
		authorizationHeader: getHeaderValue(request.headers.authorization),
		cookieHeader: getHeaderValue(request.headers.cookie),
		password: getAccessPassword(),
		username: getAccessUsername(),
	});
	if (authDecision.kind === "reject") {
		return rejectUnauthorizedSocketUpgrade(socket);
	}

	return { end: false };
}
