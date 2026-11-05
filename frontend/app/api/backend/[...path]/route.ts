import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.PRIVGUARD_BACKEND_URL || "http://127.0.0.1:8000";
const API_KEY = process.env.PRIVGUARD_API_KEY || "pg_live_test_api_key_valid_99999";

const ALLOWED_ROUTE_PREFIXES = new Set([
  "dashboard",
  "threats",
  "agents",
  "tasks",
  "capabilities",
  "approvals",
  "audit",
  "privacy",
  "chat",
  "tools",
  "memory",
  "mcp",
]);

async function proxyRequest(request: NextRequest, { params }: { params: { path: string[] } }) {
  if (!API_KEY) {
    return NextResponse.json(
      { error: { code: "BFF_CONFIGURATION_ERROR", message: "Backend API key is not configured." } },
      { status: 500 }
    );
  }

  const segments = params.path || [];

  // Reject path traversal and normalization bypass attempts
  if (segments.some((seg) => seg.includes("..") || seg.includes("/") || seg.includes("\\"))) {
    return NextResponse.json(
      { error: { code: "PATH_TRAVERSAL_DETECTED", message: "Invalid route segment path." } },
      { status: 400 }
    );
  }

  const rootPrefix = segments[0];
  if (!rootPrefix || !ALLOWED_ROUTE_PREFIXES.has(rootPrefix)) {
    return NextResponse.json(
      { error: { code: "ROUTE_NOT_PERMITTED", message: `Route prefix '${rootPrefix}' is not allowed.` } },
      { status: 403 }
    );
  }

  const path = segments.join("/");
  const searchParams = request.nextUrl.searchParams.toString();
  const targetUrl = `${BACKEND_URL}/v1/${path}${searchParams ? `?${searchParams}` : ""}`;

  const headers = new Headers();
  headers.set("X-API-Key", API_KEY);
  headers.set("Content-Type", "application/json");
  const incomingUserId = request.headers.get("X-User-ID");
  if (incomingUserId) {
    headers.set("X-User-ID", incomingUserId);
  }

  const method = request.method;
  let body: string | undefined = undefined;
  if (method !== "GET" && method !== "HEAD") {
    try {
      body = await request.text();
    } catch {
      body = undefined;
    }
  }

  try {
    const backendResponse = await fetch(targetUrl, {
      method,
      headers,
      body: body || undefined,
      cache: "no-store",
    });

    const responseBody = await backendResponse.text();
    return new NextResponse(responseBody, {
      status: backendResponse.status,
      headers: {
        "Content-Type": backendResponse.headers.get("Content-Type") || "application/json",
      },
    });
  } catch (error: any) {
    return NextResponse.json(
      {
        error: {
          code: "BACKEND_PROXY_ERROR",
          message: "Failed to connect to PRIVGUARD backend gateway.",
          details: error.message,
        },
      },
      { status: 502 }
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;

