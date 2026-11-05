import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.PRIVGUARD_BACKEND_URL || "http://127.0.0.1:8000";
const API_KEY = process.env.PRIVGUARD_API_KEY || "pg_live_test_api_key_valid_99999";
const MAX_BODY_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

// Explicit prefix allowlist with allowed HTTP methods
const ROUTE_POLICY: Record<string, string[]> = {
  dashboard: ["GET"],
  threats: ["GET"],
  agents: ["GET", "POST"],
  tasks: ["GET", "POST"],
  capabilities: ["GET", "POST", "DELETE"],
  approvals: ["GET", "POST"],
  audit: ["GET"],
  privacy: ["POST"],
  chat: ["POST"],
  tools: ["GET", "POST"],
  memory: ["GET", "POST", "DELETE"],
  mcp: ["GET", "POST", "DELETE"],
  organizations: ["GET", "POST", "DELETE"],
  scim: ["GET", "POST", "PATCH", "DELETE"],
  keys: ["GET", "POST"],
  secrets: ["GET", "POST"],
  incidents: ["GET", "POST"],
  monitoring: ["GET", "POST"],
};

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
]);

async function proxyRequest(request: NextRequest, { params }: { params: { path: string[] } }) {
  if (!API_KEY) {
    return NextResponse.json(
      { error: { code: "BFF_CONFIGURATION_ERROR", message: "Backend API key is not configured." } },
      { status: 500 }
    );
  }

  const segments = params.path || [];

  // 1. Strict traversal and encoded normalization rejection
  for (const seg of segments) {
    const lower = seg.toLowerCase();
    if (
      lower.includes("..") ||
      lower.includes("/") ||
      lower.includes("\\") ||
      lower.includes("%2e") ||
      lower.includes("%2f") ||
      lower.includes("%5c")
    ) {
      return NextResponse.json(
        { error: { code: "PATH_TRAVERSAL_DETECTED", message: "Invalid route segment path." } },
        { status: 400 }
      );
    }
  }

  const rootPrefix = segments[0];
  if (!rootPrefix || !(rootPrefix in ROUTE_POLICY)) {
    return NextResponse.json(
      { error: { code: "ROUTE_NOT_PERMITTED", message: `Route prefix '${rootPrefix}' is not allowed.` } },
      { status: 403 }
    );
  }

  // 2. HTTP Method validation per route policy
  const method = request.method.toUpperCase();
  const allowedMethods = ROUTE_POLICY[rootPrefix] || [];
  if (!allowedMethods.includes(method)) {
    return NextResponse.json(
      { error: { code: "METHOD_NOT_ALLOWED", message: `Method '${method}' is not permitted for route '${rootPrefix}'.` } },
      { status: 405 }
    );
  }

  const path = segments.join("/");
  const searchParams = request.nextUrl.searchParams.toString();
  const targetUrl = `${BACKEND_URL}/v1/${path}${searchParams ? `?${searchParams}` : ""}`;

  // 3. Assemble upstream headers while stripping hop-by-hop headers
  const headers = new Headers();
  headers.set("X-API-Key", API_KEY);
  headers.set("Content-Type", "application/json");

  // Pass through authorized identity and tenant context headers
  const incomingUserId = request.headers.get("X-User-ID");
  if (incomingUserId) headers.set("X-User-ID", incomingUserId);
  const incomingTenantId = request.headers.get("X-Tenant-ID");
  if (incomingTenantId) headers.set("X-Tenant-ID", incomingTenantId);
  const incomingWorkspaceId = request.headers.get("X-Workspace-ID");
  if (incomingWorkspaceId) headers.set("X-Workspace-ID", incomingWorkspaceId);

  // 4. Request body processing with size validation
  let body: string | undefined = undefined;
  if (method !== "GET" && method !== "HEAD") {
    try {
      body = await request.text();
      if (body && body.length > MAX_BODY_SIZE_BYTES) {
        return NextResponse.json(
          { error: { code: "PAYLOAD_TOO_LARGE", message: "Request payload exceeds 10 MB limit." } },
          { status: 413 }
        );
      }
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
    const responseHeaders = new Headers();

    // Preserve content-type while discarding hop-by-hop headers
    const contentType = backendResponse.headers.get("Content-Type");
    if (contentType) responseHeaders.set("Content-Type", contentType);

    return new NextResponse(responseBody, {
      status: backendResponse.status,
      headers: responseHeaders,
    });
  } catch (error: any) {
    // Mask internal networking details from client
    return NextResponse.json(
      {
        error: {
          code: "BACKEND_UNAVAILABLE",
          message: "The security enforcement gateway is currently unavailable.",
        },
      },
      { status: 502 }
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
