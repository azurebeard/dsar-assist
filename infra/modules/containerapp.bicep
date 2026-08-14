// The container app itself.
//
// The properties that matter are `secrets: []`, `allowInsecure: false`, and a
// replica count pinned to exactly one. Each is asserted by a test, because
// each replaces a guarantee that used to live somewhere else.

param suffix string
param location string
param tags object
param containerImage string
param appClientId string
param tenantId string
param allowedIpRanges array
param environmentId string
param identityId string
param identityClientId string
param auditBlobUrl string

var appName = 'ca-${suffix}'

// An empty `allowedIpRanges` means the human deploying chose an internet-facing
// endpoint. That is a legitimate answer — the parameter has no default so it
// has to be given — and it produces no restrictions rather than a rule that
// blocks everything.
var ipRestrictions = [for (range, i) in allowedIpRanges: {
  name: 'allow-${i}'
  description: 'Permitted operator network'
  ipAddressRange: range
  action: 'Allow'
}]

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  tags: tags
  identity: {
    // User-assigned only. A system-assigned identity would be created and
    // destroyed with the app, and the federated credential names its principal
    // id — so a redeploy would silently break client authentication in a way
    // that surfaces as AADSTS70021 hours later.
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    managedEnvironmentId: environmentId
    configuration: {
      // THE central assertion. There is no secret in this deployment: the
      // client assertion is minted at runtime by the managed identity, and the
      // storage account allows no shared key. `az containerapp show --query
      // properties.configuration.secrets` returning [] is the check.
      secrets: []
      ingress: {
        external: true
        targetPort: 8765
        transport: 'auto'
        // No plaintext. The redirect URI is https and a __Host- cookie
        // requires Secure, so a plaintext listener could only ever serve a
        // broken sign-in — while looking like it worked.
        allowInsecure: false
        ipSecurityRestrictions: ipRestrictions
        stickySessions: { affinity: 'none' }
      }
      registries: []
      activeRevisionsMode: 'Single'
    }
    template: {
      containers: [
        {
          name: 'dsar'
          image: containerImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'DSAR_MODE', value: 'hosted' }
            { name: 'DSAR_CLIENT_ID', value: appClientId }
            { name: 'DSAR_TENANT_ID', value: tenantId }
            { name: 'DSAR_UAMI_CLIENT_ID', value: identityClientId }
            { name: 'DSAR_AUDIT_BLOB_URL', value: auditBlobUrl }
            { name: 'DSAR_BASE_URL', value: 'https://${appName}.${environmentDomain}' }
            { name: 'DSAR_PORT', value: '8765' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/healthz', port: 8765 }
              initialDelaySeconds: 5
              periodSeconds: 30
            }
          ]
        }
      ]
      scale: {
        // Exactly one, and it is not a cost decision.
        //
        // Sessions are in-process, so a second replica would serve an operator
        // a request the replica holding their session never saw. And the audit
        // chain's head is process state: two writers would each believe they
        // held it, and the trail would fork into two chains that both verify
        // and neither of which is the record.
        //
        // The consequence, documented rather than discovered: a revision update
        // signs every operator out. The UI detects the lost session and
        // re-runs sign-in, usually invisibly against a live Entra session.
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

// The ingress FQDN is only known after the environment exists, and the app's
// own `DSAR_BASE_URL` has to match it exactly — a redirect URI derived from a
// Host header is an attacker-controlled redirect URI, which is why the
// application refuses to derive one.
var environmentDomain = reference(environmentId, '2024-03-01').defaultDomain

output appUrl string = 'https://${app.properties.configuration.ingress.fqdn}'
output appName string = appName
