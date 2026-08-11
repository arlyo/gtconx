// relay/server.js

const express = require("express");
const path = require("path");
const http = require("http");
const crypto = require("crypto");
const WebSocket = require("ws");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 10000;

const REQUEST_TIMEOUT_MS = Number(
  process.env.REQUEST_TIMEOUT_MS || 10000
);

const MAX_REQUEST_BODY_BYTES = Number(
  process.env.MAX_REQUEST_BODY_BYTES || 1024 * 1024
);

const HEARTBEAT_INTERVAL_MS = Number(
  process.env.HEARTBEAT_INTERVAL_MS || 30000
);

const TUNNEL_AGENT_SECRET = process.env.TUNNEL_AGENT_SECRET;
const TUNNEL_ADMIN_SECRET = process.env.TUNNEL_ADMIN_SECRET;

if (!TUNNEL_AGENT_SECRET) {
  console.error(
    "Missing required environment variable: TUNNEL_AGENT_SECRET"
  );
  process.exit(1);
}

if (!TUNNEL_ADMIN_SECRET) {
  console.error(
    "Missing required environment variable: TUNNEL_ADMIN_SECRET"
  );
  process.exit(1);
}

if (
  !Number.isFinite(REQUEST_TIMEOUT_MS) ||
  REQUEST_TIMEOUT_MS < 1000
) {
  console.error(
    "REQUEST_TIMEOUT_MS must be a number of at least 1000 milliseconds."
  );
  process.exit(1);
}

if (
  !Number.isFinite(MAX_REQUEST_BODY_BYTES) ||
  MAX_REQUEST_BODY_BYTES < 1
) {
  console.error(
    "MAX_REQUEST_BODY_BYTES must be a positive number."
  );
  process.exit(1);
}

if (
  !Number.isFinite(HEARTBEAT_INTERVAL_MS) ||
  HEARTBEAT_INTERVAL_MS < 5000
) {
  console.error(
    "HEARTBEAT_INTERVAL_MS must be a number of at least 5000 milliseconds."
  );
  process.exit(1);
}

// Capture all incoming request bodies as raw bytes.
//
// This preserves JSON, text, forms, and other non-streaming bodies
// exactly as received so they can be forwarded through the tunnel.
app.use(
  express.raw({
    type: () => true,
    limit: MAX_REQUEST_BODY_BYTES,
  })
);

// Authenticated agents registered by agent ID.
const agents = new Map();

// In-memory tenant slug → agent ID routing table.
//
// These initial routes are preserved across relay startup, but routes
// added through the Admin API exist only until the relay restarts.
// Persistent storage can be added in a later version.
const tenantRoutes = new Map();

// Public HTTP requests waiting for an agent response.
const pendingRequests = new Map();

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const REQUEST_HEADERS_TO_REMOVE = new Set([
  ...HOP_BY_HOP_HEADERS,
  "content-length",
  "host",
]);

const RESPONSE_HEADERS_TO_REMOVE = new Set([
  ...HOP_BY_HOP_HEADERS,
  "content-length",
]);

function secretsMatch(receivedSecret, expectedSecret) {
  if (
    typeof receivedSecret !== "string" ||
    typeof expectedSecret !== "string"
  ) {
    return false;
  }

  const receivedBuffer = Buffer.from(receivedSecret);
  const expectedBuffer = Buffer.from(expectedSecret);

  if (receivedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    receivedBuffer,
    expectedBuffer
  );
}

function isValidAgentId(agentId) {
  return (
    typeof agentId === "string" &&
    /^[a-zA-Z0-9_-]{1,64}$/.test(agentId)
  );
}

function isValidTenantSlug(tenantSlug) {
  return (
    typeof tenantSlug === "string" &&
    /^(?:[a-z0-9]|[a-z0-9][a-z0-9-]{0,62}[a-z0-9])$/.test(
      tenantSlug
    )
  );
}

function getConnectedAgent(agentId) {
  const agent = agents.get(agentId);

  if (
    !agent ||
    !agent.socket ||
    agent.socket.readyState !== WebSocket.OPEN ||
    agent.socket.isAuthenticated !== true ||
    agent.socket.isAlive !== true
  ) {
    return null;
  }

  return agent;
}

function getConnectedAgents() {
  const connectedAgents = [];

  for (const [agentId, agent] of agents.entries()) {
    if (!getConnectedAgent(agentId)) {
      continue;
    }

    connectedAgents.push({
      agentId,
      connectedAt: agent.connectedAt,
      lastSeen: agent.lastSeen,
      lastPongAt: agent.lastPongAt,
      heartbeatAlive: agent.socket.isAlive === true,
    });
  }

  return connectedAgents;
}

function getTenantRoutes() {
  const routes = [];

  for (const [tenantSlug, agentId] of tenantRoutes.entries()) {
    routes.push({
      tenantSlug,
      agentId,
      agentConnected: getConnectedAgent(agentId) !== null,
    });
  }

  routes.sort((firstRoute, secondRoute) =>
    firstRoute.tenantSlug.localeCompare(secondRoute.tenantSlug)
  );

  return routes;
}

// Returns the first currently connected authenticated agent.
function getDefaultConnectedAgent() {
  for (const [agentId] of agents.entries()) {
    const agent = getConnectedAgent(agentId);

    if (agent) {
      return agent;
    }
  }

  return null;
}

function sanitizeRequestHeaders(headers) {
  const sanitizedHeaders = {};

  for (const [name, value] of Object.entries(headers || {})) {
    const normalizedName = name.toLowerCase();

    if (
      REQUEST_HEADERS_TO_REMOVE.has(normalizedName) ||
      value === undefined
    ) {
      continue;
    }

    sanitizedHeaders[normalizedName] = value;
  }

  return sanitizedHeaders;
}

function applyResponseHeaders(res, headers) {
  if (!headers || typeof headers !== "object") {
    return;
  }

  for (const [name, value] of Object.entries(headers)) {
    const normalizedName = name.toLowerCase();

    if (
      RESPONSE_HEADERS_TO_REMOVE.has(normalizedName) ||
      value === undefined ||
      value === null
    ) {
      continue;
    }

    try {
      res.setHeader(name, value);
    } catch (error) {
      console.warn(
        `Could not set response header "${name}": ${error.message}`
      );
    }
  }
}

function getRequestBodyBase64(req) {
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    return null;
  }

  return req.body.toString("base64");
}

function parseJsonRequestBody(req) {
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
    return null;
  }

  return JSON.parse(req.body.toString("utf8"));
}

function requireAdminAuthentication(req, res, next) {
  const receivedSecret = req.get("x-gtconx-admin-secret");

  if (
    !secretsMatch(receivedSecret, TUNNEL_ADMIN_SECRET)
  ) {
    return res.status(401).json({
      ok: false,
      error: "Invalid or missing admin credentials.",
    });
  }

  return next();
}

function failPendingRequestsForAgent(agentId, errorMessage) {
  for (const [requestId, pending] of pendingRequests.entries()) {
    if (pending.agentId !== agentId) {
      continue;
    }

    clearTimeout(pending.timeout);

    if (!pending.res.headersSent) {
      pending.res.status(503).json({
        ok: false,
        error: errorMessage,
      });
    }

    pendingRequests.delete(requestId);
  }
}

function removeRegisteredAgent(socket, errorMessage) {
  if (!socket.agentId) {
    return;
  }

  const registeredAgent = agents.get(socket.agentId);

  // Do not remove a newer socket that replaced this connection.
  if (!registeredAgent || registeredAgent.socket !== socket) {
    return;
  }

  agents.delete(socket.agentId);

  failPendingRequestsForAgent(
    socket.agentId,
    errorMessage ||
      `The authenticated agent "${socket.agentId}" disconnected.`
  );
}

function updateAgentActivity(socket, activityType) {
  if (!socket.agentId) {
    return;
  }

  const agent = agents.get(socket.agentId);

  if (!agent || agent.socket !== socket) {
    return;
  }

  const now = new Date().toISOString();

  agent.lastSeen = now;

  if (activityType === "pong") {
    agent.lastPongAt = now;
  }
}

function forwardRequestToAgent(
  agent,
  req,
  res,
  routeContext = {}
) {
  const requestId = crypto.randomUUID();

  const timeout = setTimeout(() => {
    pendingRequests.delete(requestId);

    if (!res.headersSent) {
      res.status(504).json({
        ok: false,
        error: "The local application did not respond in time.",
      });
    }
  }, REQUEST_TIMEOUT_MS);

  pendingRequests.set(requestId, {
    agentId: agent.agentId,
    tenantSlug: routeContext.tenantSlug || null,
    res,
    timeout,
  });

  const tunnelMessage = {
    type: "tunnel-request",
    requestId,
    method: req.method,
    path: req.url || "/",
    headers: sanitizeRequestHeaders(req.headers),
    bodyBase64: getRequestBodyBase64(req),
    tenantSlug: routeContext.tenantSlug || null,
  };

  try {
    agent.socket.send(JSON.stringify(tunnelMessage));
  } catch (error) {
    clearTimeout(timeout);
    pendingRequests.delete(requestId);

    if (!res.headersSent) {
      res.status(502).json({
        ok: false,
        error: "The relay could not send the request to the agent.",
        details: error.message,
      });
    }
  }
}



app.get("/health", (req, res) => {
  const connectedAgents = getConnectedAgents();
  const firstAgent = connectedAgents[0] || null;

  res.json({
    ok: true,
    service: "gtconx-relay",

    // Kept temporarily for compatibility with older health checks.
    agentConnected: connectedAgents.length > 0,
    authenticatedAgentId: firstAgent
      ? firstAgent.agentId
      : null,

    connectedAgentCount: connectedAgents.length,
    connectedAgents,

    routing: {
      dynamicAgentRoute: "/t/:agentId",
      tenantRoute: "/tenant/:tenantSlug",
    },

    tenants: {
      configuredTenantCount: tenantRoutes.size,
    },

    adminApi: {
      enabled: true,
      authenticated: true,
      routesEndpoint: "/admin/routes",
      persistence: "memory",
    },

    httpForwarding: {
      requestHeaders: true,
      queryStrings: true,
      requestBodies: true,
      responseHeaders: true,
      binarySafeBodies: true,
      maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
    },

    heartbeat: {
      enabled: true,
      intervalMs: HEARTBEAT_INTERVAL_MS,
      staleSocketAction: "terminate",
    },
  });
});

// Protect every /admin endpoint with the separate admin secret.
app.use("/admin", requireAdminAuthentication);

// List all configured tenant routes.
app.get("/admin/routes", (req, res) => {
  const routes = getTenantRoutes();

  res.json({
    ok: true,
    routeCount: routes.length,
    routes,
  });
});

// Add or replace a tenant route.
app.post("/admin/routes", (req, res) => {
  let body;

  try {
    body = parseJsonRequestBody(req);
  } catch (error) {
    return res.status(400).json({
      ok: false,
      error: "The request body must contain valid JSON.",
    });
  }

  if (!body || typeof body !== "object") {
    return res.status(400).json({
      ok: false,
      error: "A JSON request body is required.",
    });
  }

  const tenantSlug =
    typeof body.tenantSlug === "string"
      ? body.tenantSlug.trim()
      : typeof body.tenant === "string"
        ? body.tenant.trim()
        : "";

  const agentId =
    typeof body.agentId === "string"
      ? body.agentId.trim()
      : "";

  if (!isValidTenantSlug(tenantSlug)) {
    return res.status(400).json({
      ok: false,
      error:
        "tenantSlug must contain only lowercase letters, numbers, and hyphens.",
    });
  }

  if (!isValidAgentId(agentId)) {
    return res.status(400).json({
      ok: false,
      error:
        "agentId must contain only letters, numbers, underscores, and hyphens.",
    });
  }

  const previousAgentId = tenantRoutes.get(tenantSlug) || null;
  const created = previousAgentId === null;

  tenantRoutes.set(tenantSlug, agentId);

  console.log(
    `${
      created ? "Created" : "Updated"
    } tenant route: ${tenantSlug} -> ${agentId}`
  );

  return res.status(created ? 201 : 200).json({
    ok: true,
    created,
    route: {
      tenantSlug,
      agentId,
      agentConnected: getConnectedAgent(agentId) !== null,
    },
    previousAgentId,
  });
});

// Delete a tenant route.
app.delete("/admin/routes/:tenantSlug", (req, res) => {
  const tenantSlug = req.params.tenantSlug;

  if (!isValidTenantSlug(tenantSlug)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid tenant slug.",
    });
  }

  const previousAgentId = tenantRoutes.get(tenantSlug);

  if (!previousAgentId) {
    return res.status(404).json({
      ok: false,
      error: `No route exists for tenant "${tenantSlug}".`,
    });
  }

  tenantRoutes.delete(tenantSlug);

  console.log(
    `Deleted tenant route: ${tenantSlug} -> ${previousAgentId}`
  );

  return res.json({
    ok: true,
    deleted: {
      tenantSlug,
      agentId: previousAgentId,
    },
  });
});

// Dynamic route by agent ID.
app.use("/t/:agentId", (req, res) => {
  const agentId = req.params.agentId;

  if (!isValidAgentId(agentId)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid agent ID.",
    });
  }

  const agent = getConnectedAgent(agentId);

  if (!agent) {
    return res.status(503).json({
      ok: false,
      error: `The authenticated agent "${agentId}" is not connected.`,
    });
  }

  return forwardRequestToAgent(agent, req, res);
});

// Tenant-aware public route.
//
// Examples:
// /tenant/example
// /tenant/example/api/echo
app.use("/tenant/:tenantSlug", (req, res) => {
  const tenantSlug = req.params.tenantSlug;

  if (!isValidTenantSlug(tenantSlug)) {
    return res.status(400).json({
      ok: false,
      error: "Invalid tenant slug.",
    });
  }

  const agentId = tenantRoutes.get(tenantSlug);

  if (!agentId) {
    return res.status(404).json({
      ok: false,
      error: `No GTConX Tunnel route is configured for tenant "${tenantSlug}".`,
    });
  }

  const agent = getConnectedAgent(agentId);

  if (!agent) {
    return res.status(503).json({
      ok: false,
      error: `Tenant "${tenantSlug}" is assigned to agent "${agentId}", but that agent is not connected.`,
    });
  }

  return forwardRequestToAgent(agent, req, res, {
    tenantSlug,
  });
});

// Dedicated GTConX public route.
// All otherwise-unmatched HTTP traffic is forwarded to gtconx-web.
app.use((req, res) => {
  const agent = getConnectedAgent("gtconx-web");

  if (!agent) {
    return res.status(503).json({
      ok: false,
      error: 'The GTConX web agent "gtconx-web" is not connected.',
    });
  }

  return forwardRequestToAgent(agent, req, res);
});

wss.on("connection", (socket) => {
  console.log(
    "WebSocket client connected. Waiting for authentication."
  );

  socket.isAuthenticated = false;
  socket.agentId = null;
  socket.isAlive = true;

  socket.on("pong", () => {
    socket.isAlive = true;
    updateAgentActivity(socket, "pong");
  });

  socket.send(
    JSON.stringify({
      type: "welcome",
      message:
        "Connected to GTConX Relay. Authentication required.",
    })
  );

  socket.on("message", (rawMessage) => {
    try {
      const message = JSON.parse(rawMessage.toString());

      if (!socket.isAuthenticated) {
        if (message.type !== "authenticate") {
          socket.send(
            JSON.stringify({
              type: "auth-failed",
              message: "Authentication is required.",
            })
          );

          socket.close(1008, "Authentication required");
          return;
        }

        const agentId =
          typeof message.agentId === "string"
            ? message.agentId.trim()
            : "";

        if (
          !isValidAgentId(agentId) ||
          !secretsMatch(
            message.secret,
            TUNNEL_AGENT_SECRET
          )
        ) {
          console.warn(
            `Agent authentication failed${
              agentId ? ` for: ${agentId}` : ""
            }.`
          );

          socket.send(
            JSON.stringify({
              type: "auth-failed",
              message: "Invalid agent credentials.",
            })
          );

          socket.close(1008, "Invalid agent credentials");
          return;
        }

        const existingAgent = agents.get(agentId);

        if (
          existingAgent &&
          existingAgent.socket &&
          existingAgent.socket !== socket &&
          (existingAgent.socket.readyState === WebSocket.OPEN ||
            existingAgent.socket.readyState === WebSocket.CONNECTING)
        ) {
          existingAgent.socket.close(
            1012,
            "Replaced by a new connection using the same agent ID"
          );
        }

        const now = new Date().toISOString();

        socket.isAuthenticated = true;
        socket.agentId = agentId;
        socket.isAlive = true;

        agents.set(agentId, {
          agentId,
          socket,
          connectedAt: now,
          lastSeen: now,
          lastPongAt: null,
        });

        console.log(
          `Agent authenticated and registered: ${agentId}`
        );

        socket.send(
          JSON.stringify({
            type: "auth-success",
            agentId,
            message: "Agent authentication successful.",
          })
        );

        return;
      }

      const registeredAgent = getConnectedAgent(
        socket.agentId
      );

      // Ignore messages from a socket that was replaced.
      if (
        !registeredAgent ||
        registeredAgent.socket !== socket
      ) {
        return;
      }

      updateAgentActivity(socket, "message");

      if (message.type === "agent-ready") {
        console.log(
          `Agent ready: ${socket.agentId} — ${
            message.message || ""
          }`
        );
        return;
      }

      if (message.type === "tunnel-response") {
        const pending = pendingRequests.get(
          message.requestId
        );

        if (!pending) {
          return;
        }

        // Prevent one agent from answering another agent's request.
        if (pending.agentId !== socket.agentId) {
          console.warn(
            `Agent ${socket.agentId} attempted to answer a request assigned to ${pending.agentId}.`
          );
          return;
        }

        clearTimeout(pending.timeout);
        pendingRequests.delete(message.requestId);

        applyResponseHeaders(
          pending.res,
          message.headers
        );

        // Compatibility with older agent responses.
        if (
          message.contentType &&
          !pending.res.hasHeader("Content-Type")
        ) {
          pending.res.setHeader(
            "Content-Type",
            message.contentType
          );
        }

        const statusCode =
          Number.isInteger(message.statusCode) &&
          message.statusCode >= 100 &&
          message.statusCode <= 599
            ? message.statusCode
            : 200;

        if (typeof message.bodyBase64 === "string") {
          const responseBody = Buffer.from(
            message.bodyBase64,
            "base64"
          );

          pending.res
            .status(statusCode)
            .send(responseBody);

          return;
        }

        // Compatibility with the old string body format.
        pending.res
          .status(statusCode)
          .send(message.body ?? "");

        return;
      }

      console.warn(
        `Unsupported message type from ${socket.agentId}: ${message.type}`
      );
    } catch (error) {
      console.error(
        "Invalid WebSocket message:",
        error.message
      );
    }
  });

  socket.on("close", (code, reasonBuffer) => {
    const reason = reasonBuffer.toString();

    if (socket.isAuthenticated) {
      console.log(
        `Authenticated agent disconnected: ${
          socket.agentId
        } (code ${code}${reason ? `, ${reason}` : ""})`
      );
    } else {
      console.log(
        `Unauthenticated WebSocket client disconnected (code ${code}${
          reason ? `, ${reason}` : ""
        })`
      );
    }

    removeRegisteredAgent(
      socket,
      socket.agentId
        ? `The authenticated agent "${socket.agentId}" disconnected.`
        : undefined
    );
  });

  socket.on("error", (error) => {
    console.error(
      `WebSocket error${
        socket.agentId ? ` for ${socket.agentId}` : ""
      }: ${error.message}`
    );
  });
});

// WebSocket protocol-level heartbeat.
//
// Each interval:
// 1. Sockets that answered the previous ping remain alive.
// 2. Sockets that did not answer are terminated.
// 3. Live sockets receive another ping.
const heartbeatTimer = setInterval(() => {
  for (const socket of wss.clients) {
    if (socket.readyState !== WebSocket.OPEN) {
      continue;
    }

    if (socket.isAlive === false) {
      const label =
        socket.agentId || "unauthenticated client";

      console.warn(
        `Heartbeat timeout for ${label}. Terminating stale WebSocket.`
      );

      removeRegisteredAgent(
        socket,
        socket.agentId
          ? `The authenticated agent "${socket.agentId}" stopped responding to heartbeat checks.`
          : undefined
      );

      socket.terminate();
      continue;
    }

    socket.isAlive = false;

    try {
      socket.ping();
    } catch (error) {
      console.error(
        `Could not send heartbeat ping${
          socket.agentId ? ` to ${socket.agentId}` : ""
        }: ${error.message}`
      );
    }
  }
}, HEARTBEAT_INTERVAL_MS);

heartbeatTimer.unref();

// Friendly JSON error for request bodies over the configured limit.
app.use((error, req, res, next) => {
  if (error?.type === "entity.too.large") {
    return res.status(413).json({
      ok: false,
      error: "The request body is too large for this tunnel.",
      maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
    });
  }

  return next(error);
});

server.on("close", () => {
  clearInterval(heartbeatTimer);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `GTConX Relay running on port ${PORT}`
  );

  console.log(
    `Heartbeat monitoring enabled every ${HEARTBEAT_INTERVAL_MS} ms`
  );

  console.log(
    `Configured tenant routes: ${tenantRoutes.size}`
  );

  console.log(
    "Protected route management API enabled at /admin/routes"
  );
});