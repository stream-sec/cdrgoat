require("isomorphic-fetch");
const { Client } = require("@microsoft/microsoft-graph-client");

async function getClientCredentialToken(tenantId, clientId, clientSecret) {
  const url = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;

  const body = new URLSearchParams({
    client_id: clientId,
    client_secret: clientSecret,
    grant_type: "client_credentials",
    scope: "https://graph.microsoft.com/.default"
  });

  const resp = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Token request failed (${resp.status}): ${text}`);
  }

  return resp.json();
}

module.exports = async function (context, req) {
  try {
    const tenantId = process.env.GRAPH_TENANT_ID;
    const clientId = process.env.GRAPH_CLIENT_ID;
    const clientSecret = process.env.GRAPH_CLIENT_SECRET;

    if (!tenantId || !clientId || !clientSecret) {
      context.res = {
        status: 500,
        body: { error: "Missing GRAPH_TENANT_ID / GRAPH_CLIENT_ID / GRAPH_CLIENT_SECRET app settings" }
      };
      return;
    }

    const tok = await getClientCredentialToken(tenantId, clientId, clientSecret);

    const graph = Client.init({
      authProvider: (done) => done(null, tok.access_token)
    });

    const result = await graph
      .api("/users")
      .select("id,displayName,userPrincipalName,accountEnabled")
      .top(50)
      .get();

    context.res = {
      status: 200,
      headers: { "content-type": "application/json" },
      body: {
        scenario: process.env.LAB_SCENARIO || "graph_user_enumeration",
        count: result.value?.length ?? 0,
        users: result.value ?? []
      }
    };
  } catch (e) {
    context.log.error(e);
    context.res = {
      status: 500,
      body: { error: e.message || "Unknown error" }
    };
  }
};