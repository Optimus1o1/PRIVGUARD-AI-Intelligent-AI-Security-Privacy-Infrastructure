import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.PRIVGUARD_BACKEND_URL || "http://127.0.0.1:8000";
const API_KEY = process.env.PRIVGUARD_API_KEY || "pg_live_test_api_key_valid_99999";

async function proxyRequest(request: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join("/");
  const searchParams = request.nextUrl.searchParams.toString();
  const targetUrl = `${BACKEND_URL}/v1/${path}${searchParams ? `?${searchParams}` : ""}`;

  const headers = new Headers();
  headers.set("X-API-Key", API_KEY);
  headers.set("Content-Type", "application/json");

  const method = request.method;
  let body = undefined;
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
