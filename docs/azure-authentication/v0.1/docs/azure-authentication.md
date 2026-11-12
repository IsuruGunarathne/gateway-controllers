---
title: "Overview"
---
# Azure Authentication

## Overview

The **Azure Authentication** policy authenticates requests to Azure-hosted backends with a
short-lived [Microsoft Entra ID](https://learn.microsoft.com/entra/identity-platform/) access
token instead of a static API key. Before a request is forwarded upstream, the policy obtains a
token for the gateway's own Azure identity and sets it in a request header, by default
`Authorization: Bearer <token>`.

With `authenticationType: workload-identity`, the gateway uses
[AKS Workload Identity](https://learn.microsoft.com/azure/aks/workload-identity-overview): the
Kubernetes service account token projected into the gateway pod is exchanged for an access token
of the user-assigned managed identity federated with that service account. No key, secret or
certificate is configured on the API, and nothing needs rotating by hand.

With `authenticationType: managed-identity`, the gateway gets the token from the
[Azure Instance Metadata Service](https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service)
(IMDS) of the VM, VM scale set or AKS node it runs on, for a
[managed identity](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview)
assigned to that host. Use it when the gateway runs on Azure compute without Workload Identity,
for example on Azure VMs.

Use it for Azure AI Foundry, Azure OpenAI and other Azure services that accept Entra ID tokens,
typically as the upstream authentication of an LLM provider.

## Features

- Secretless upstream authentication with AKS Workload Identity (user-assigned managed identity),
  or with the managed identity of the VM, VM scale set or AKS node through IMDS
- Works with any Entra ID–protected resource through a configurable `scope`
- One cached token per identity and scope, shared by every route and API that uses it
- Background refresh before expiry, so requests don't wait for a new token
- Retries transient failures (network errors, 429, 5xx, and IMDS's 404 and 410), honouring
  `Retry-After`
- Picks up the rotated service account token automatically
- Sovereign clouds through the `AZURE_AUTHORITY_HOST` environment variable
- Keeps any authentication context set by an earlier inbound auth policy

## Configuration

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `authenticationType` | string | Yes | | How the token is obtained: `workload-identity` (AKS Workload Identity) or `managed-identity` (IMDS). |
| `scope` | string | No | `https://ai.azure.com/.default` | Scope of the access token: the target resource followed by `/.default`. See [Choosing the scope](#choosing-the-scope). |
| `clientId` | string | No | `AZURE_CLIENT_ID` (`workload-identity`) | Application (client) ID of the managed identity, as a GUID. With `workload-identity`, overrides the environment variable. With `managed-identity`, selects a user-assigned identity of the host; leave it unset for the system-assigned identity. |
| `tenantId` | string | No | `AZURE_TENANT_ID` | Microsoft Entra tenant ID (GUID) or domain name. Overrides the environment variable. `workload-identity` only: setting it with `managed-identity` makes the policy fail to initialize. |
| `headerName` | string | No | `Authorization` | Request header the token is set in. |
| `valuePrefix` | string | No | `Bearer` | Prefix placed before the token, separated by a space. An empty string sends the token alone. Control characters are not allowed. |
| `tokenRequestTimeout` | string | No | `10s` | Maximum time to obtain a token, including retries: whole seconds from `1s` to `30s`, or milliseconds from `1ms` to `30000ms`. |

There are no system (`config.toml`) parameters.

### Environment Variables (Gateway Runtime)

With `workload-identity`, the identity is read from the environment the AKS Workload Identity
webhook injects into the gateway runtime pod. `managed-identity` reads none of these four
variables.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Unless `tenantId` is set | Tenant of the managed identity. |
| `AZURE_CLIENT_ID` | Unless `clientId` is set | Client ID of the managed identity. |
| `AZURE_FEDERATED_TOKEN_FILE` | Yes | Path of the projected service account token. Read on every token request, so rotation is picked up. |
| `AZURE_AUTHORITY_HOST` | No | Entra ID host, `https://login.microsoftonline.com/` by default. Set by the webhook for sovereign clouds. Must use `https`. |
| `AZURE_IMDS_TOKEN_ENDPOINT` | No | `managed-identity` only. Replaces the IMDS token endpoint, `http://169.254.169.254/metadata/identity/oauth2/token`, to test against a stand-in IMDS. Must be an `https` URL. Leave it unset in production. |

The token file path and the authority host are deliberately never policy parameters. If both
could be set on an API, whoever writes that API could make the gateway send any file it can read
to a host of their choosing.

If `AZURE_FEDERATED_TOKEN_FILE` is missing, or neither the parameter nor the environment variable
supplies a client or tenant ID, the policy fails to initialize: the routes using it return
`500` and the gateway runtime logs the reason. Other routes are not affected. With
`managed-identity`, the policy also fails to initialize when `tenantId` is set or
`AZURE_IMDS_TOKEN_ENDPOINT` is not an `https` URL.

Parameters are checked against the policy definition when an API is created, and an invalid
value is rejected with `400`. Parameters given in an LLM provider's `upstream.auth.policyParams`
are not checked when the provider is created; an invalid value there also makes the provider's
routes return `500`, with the reason in the gateway runtime log.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: azure-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/azure-authentication@v0
```

## Workload Identity Prerequisites

The gateway must run on AKS with Workload Identity set up for the gateway runtime's service
account. This is Azure and Kubernetes configuration, not something the policy creates.

1. Enable the OIDC issuer and Workload Identity on the cluster, and note the issuer URL:

   ```bash
   az aks update -g <resource-group> -n <cluster> --enable-oidc-issuer --enable-workload-identity
   export AKS_OIDC_ISSUER="$(az aks show -g <resource-group> -n <cluster> \
     --query oidcIssuerProfile.issuerUrl -o tsv)"
   ```

2. Create a user-assigned managed identity:

   ```bash
   az identity create -g <resource-group> -n gateway-identity
   export CLIENT_ID="$(az identity show -g <resource-group> -n gateway-identity --query clientId -o tsv)"
   ```

3. Federate the identity with the gateway's service account. The subject is
   `system:serviceaccount:<namespace>:<service-account>`:

   ```bash
   az identity federated-credential create --name gateway-runtime \
     --identity-name gateway-identity -g <resource-group> \
     --issuer "$AKS_OIDC_ISSUER" \
     --subject system:serviceaccount:<namespace>:<service-account> \
     --audience api://AzureADTokenExchange
   ```

4. Grant the identity a data-plane role on the target resource, for example
   `Cognitive Services OpenAI User` on an Azure OpenAI resource, or the role your Azure AI Foundry
   resource or project requires:

   ```bash
   az role assignment create --role "<role>" --scope <resource-id> \
     --assignee-object-id "$(az identity show -g <resource-group> -n gateway-identity --query principalId -o tsv)" \
     --assignee-principal-type ServicePrincipal
   ```

5. Annotate the service account with the client ID and label the gateway runtime pods. With the
   gateway Helm chart:

   ```yaml
   serviceAccount:
     annotations:
       azure.workload.identity/client-id: <CLIENT_ID>
   gateway:
     gatewayRuntime:
       deployment:
         podLabels:
           azure.workload.identity/use: "true"
   ```

   The chart's service account is named after the release unless `serviceAccount.name` is set;
   the federated credential's subject must match it.

The gateway also needs outbound HTTPS access to `login.microsoftonline.com` (or your cloud's
authority host).

### Choosing the scope

The scope names the resource the token is for, followed by `/.default`.

| Backend | Scope |
|---------|-------|
| Azure AI Foundry (`*.services.ai.azure.com`) | `https://ai.azure.com/.default` (default) |
| Azure OpenAI (`*.openai.azure.com`) | `https://cognitiveservices.azure.com/.default` |
| Azure AI Content Safety and other Azure AI services | `https://cognitiveservices.azure.com/.default` |

A token issued for the wrong scope is rejected by the backend with `401`, which the gateway passes
through to the client unchanged.

## Managed Identity (IMDS) Prerequisites

With `managed-identity`, the gateway must run on an Azure VM, VM scale set or AKS node that has
the managed identity assigned. This is Azure configuration, not something the policy creates.

1. Assign a user-assigned identity to the host, or leave out `--identities` to enable its
   system-assigned identity:

   ```bash
   # A VM
   az vm identity assign -g <resource-group> -n <vm> --identities <identity-resource-id>

   # A VM scale set; then apply the change to the existing instances
   az vmss identity assign -g <resource-group> -n <vmss> --identities <identity-resource-id>
   az vmss update-instances -g <resource-group> -n <vmss> --instance-ids '*'
   ```

2. Grant the identity a data-plane role on the target resource, as in step 4 of the Workload
   Identity prerequisites.

3. Set `clientId` to the identity's client ID to use a user-assigned identity. Without
   `clientId`, IMDS uses the host's system-assigned identity; a host without one uses its only
   user-assigned identity, and IMDS rejects the request if the host has several.

The gateway must reach `169.254.169.254` directly. Requests to IMDS never go through
`HTTP_PROXY` or `HTTPS_PROXY`, and host firewalls and Kubernetes network policies must allow them.

On AKS, prefer Workload Identity. Any pod that can reach IMDS can get tokens for the node's
identities, so an identity assigned to a node pool is shared by every workload on it. Clusters
with IMDS restriction enabled block pods from reaching IMDS, so `managed-identity` doesn't work
there.

## How It Works

1. **Request header phase**: the policy only sets a header, so it never buffers the request body.
2. The policy asks its token cache for a token. There is one cache per identity, scope and
   timeout, shared by every route and API that uses the same combination.
   - A fresh token is returned straight away.
   - A token that is due for refresh (Entra ID's `refresh_in` hint, or 5 minutes before expiry)
     is still returned, and one background refresh starts. If that refresh fails, the current
     token stays in use and the next attempt is made 30 seconds later.
   - With no token, or less than a minute of validity left, the request waits for a new token.
     Concurrent requests share one token request.
3. A token request reads `AZURE_FEDERATED_TOKEN_FILE` and sends an OAuth 2.0 client credentials
   request with that token as a client assertion to
   `{authority}/{tenant}/oauth2/v2.0/token`. Network errors, `429` and `5xx` are retried up to
   twice with backoff, honouring `Retry-After`, all within `tokenRequestTimeout`. Other errors are
   not retried, and redirects are never followed.

   With `managed-identity`, a token request is one `GET` to
   `http://169.254.169.254/metadata/identity/oauth2/token` with `api-version=2018-02-01`, the
   scope's resource (the scope without `/.default`), `client_id` when `clientId` is set, and the
   `Metadata: true` header. Network errors, `404`, `410`, `429` and `5xx` are retried up to four
   times with backoff, honouring `Retry-After`, all within `tokenRequestTimeout`. Other errors are
   not retried, redirects are never followed, and no proxy is used.
4. The token is set in `headerName` (`Authorization: Bearer <token>` by default) and the request
   is forwarded upstream.
5. If no token can be obtained, the request is short-circuited with `502 Bad Gateway`: it is the
   gateway's own upstream credential that failed, not the client's.

## Reference Scenarios

### Example 1: Azure AI Foundry LLM Provider

Requires a gateway release newer than 1.2.0, which supports `upstream.auth.type: other`.

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: foundry-provider
spec:
  displayName: Azure AI Foundry Provider
  version: v1.0
  template: azureai-foundry
  upstream:
    url: https://<resource>.services.ai.azure.com
    auth:
      type: other
      policyName: azure-authentication
      policyVersion: v0
      policyParams:
        authenticationType: workload-identity
```

### Example 2: Azure OpenAI as a REST API

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: RestApi
metadata:
  name: azure-openai-chat-v1.0
spec:
  displayName: Azure-OpenAI-Chat
  version: v1.0
  context: /aoai/$version
  upstream:
    main:
      url: https://<resource>.openai.azure.com
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
        scope: https://cognitiveservices.azure.com/.default
  operations:
    - method: POST
      path: /openai/deployments/{deployment}/chat/completions
```

### Example 3: A Second Identity for One API

A gateway can use more than one managed identity, as long as each identity has a federated
credential that trusts the gateway's service account.

```yaml
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
        clientId: 99999999-8888-7777-6666-555555555555
```

### Example 4: Inbound API Key, Outbound Entra ID Token

Clients authenticate to the gateway with its own API key; `api-key-auth` removes that key before
the request is forwarded, and `azure-authentication` adds the Entra ID token.

```yaml
  policies:
    - name: api-key-auth
      version: v1
      params:
        key: X-API-Key
        in: header
    - name: azure-authentication
      version: v0
      params:
        authenticationType: workload-identity
```

### Example 5: Managed Identity on an Azure VM

The gateway runs on an Azure VM with a user-assigned identity that has access to the Azure OpenAI
resource.

```yaml
  policies:
    - name: azure-authentication
      version: v0
      params:
        authenticationType: managed-identity
        clientId: 99999999-8888-7777-6666-555555555555
        scope: https://cognitiveservices.azure.com/.default
```

## Error Responses

All error responses are returned as JSON with `Content-Type: application/json`.

| Scenario | Status | Message |
|----------|--------|---------|
| A token could not be obtained from Microsoft Entra ID or IMDS (token file unreadable, endpoint unreachable, request rejected, invalid response or timeout) | 502 | `failed to authenticate request to upstream Azure service` |

**Example error body:**

```json
{
  "error": "Bad Gateway",
  "message": "failed to authenticate request to upstream Azure service"
}
```

The gateway runtime logs the full reason, including Entra ID's error code, `AADSTS` codes and
correlation ID, which Microsoft support asks for, or IMDS's error code and description. The access
token and the service account token are never logged.

## Fault reporting

Every rejection this policy makes is reported to the gateway as a **fault**: a stable code and
type alongside the response. A gateway that supports fault policies uses it for the analytics
event and hands it to the API's fault policies (for example `log-message`). A gateway without
fault policy support ignores it.

| When | Status | Code | Type |
|------|--------|------|------|
| No access token could be obtained from Microsoft Entra ID or the Azure Instance Metadata Service | `502` | `960000` | `mediation` |

The fault's `Description` carries a short internal reason, for example
`Microsoft Entra ID rejected the token request (invalid_client)`, or with `managed-identity`
`the Azure Instance Metadata Service rejected the token request (invalid_request)`. It is passed
to fault policies and analytics only, never to the client.

## Security Considerations

- **Least privilege**: grant the managed identity only the data-plane role the backend needs, on
  the specific resource rather than the subscription.
- **Federate narrowly**: the federated credential's subject should name the gateway runtime's own
  namespace and service account, so no other workload can use the identity.
- **Identity overrides**: `clientId` lets an API choose any identity federated with the gateway's
  service account. Federate only identities that every API on the gateway may use.
- **No stored secret**: nothing is stored in the API definition, and the projected token is short
  lived and rotated by Kubernetes.
- **HTTPS only**: the authority host must use `https`, and token requests never follow redirects.
  With `managed-identity`, plain HTTP goes only to the link-local IMDS address; an
  `AZURE_IMDS_TOKEN_ENDPOINT` override must use `https`.
- **Managed identity on shared hosts**: with `managed-identity`, every process that can reach the
  host's IMDS can get tokens for the same identity, including every pod on an AKS node. Use it on
  hosts dedicated to the gateway, and prefer Workload Identity on AKS.

## Limitations

- Managed identity through the App Service, Azure Functions, Container Apps, Azure Arc and Service
  Fabric endpoints is not supported, nor are client secrets.
- IMDS answers `410` while it updates, which can take about 70 seconds. A request that needs a
  new token during that time fails with `502` once `tokenRequestTimeout` passes; the next request
  tries again.
- The AKS identity bindings proxy and Entra ID regional endpoints are not used.
- A token rejected by the backend is not discarded early; it is replaced on the normal refresh
  schedule.

## Gateway Module Reference

```yaml
- name: azure-authentication
  gomodule: github.com/wso2/gateway-controllers/policies/azure-authentication@v0
```
