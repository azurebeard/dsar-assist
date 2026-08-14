// Log Analytics, the Container Apps environment, the managed identity, and the
// storage account holding the audit trail.

param suffix string
param location string
param tags object
param storageAccountName string
param auditImmutabilityDays int

var auditContainerName = 'audit'

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    // The audit trail tees to stderr, which Container Apps ships here
    // automatically. That is the only defence against someone with the
    // data-plane role truncating the blob — the hash chain makes truncation
    // *detectable* only if a copy of a later head exists somewhere.
    //
    // ⚠️ It is NOT "a different trust domain", which an earlier version of this
    // comment claimed (WS10 SEC-M-03). It is a different data plane in the
    // same subscription and the same resource group: one management-plane
    // actor can delete both. And 90 days against the trail's 2555 means the
    // second copy expires first — raising it is a real cost decision, not a
    // template default, so it is named here rather than quietly changed.
    retentionInDays: 90
    features: { enableLogAccessUsingOnlyResourcePermissions: true }
  }
}

// Dedicated to this application. With a federated credential there is no
// secret, but anyone who can run code as this identity can mint the assertion
// — so it is exactly as sensitive as a client secret would have been, and it
// is not shared with anything else.
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-${suffix}'
  location: location
  tags: tags
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-${suffix}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
    zoneRedundant: false
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: { name: 'Standard_ZRS' }
  kind: 'StorageV2'
  properties: {
    // No account key, so no SAS. The audit sink authenticates with an Entra
    // token from the managed identity — the same reasoning the application
    // makes about client secrets, applied to storage.
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      // Container Apps egress is not a fixed address without a NAT gateway, so
      // a network ACL here would break the writer. The control is the absence
      // of a shared key plus a data-plane role scoped to one container.
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
    encryption: {
      services: {
        blob: { enabled: true, keyType: 'Account' }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 30 }
    containerDeleteRetentionPolicy: { enabled: true, days: 30 }
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: auditContainerName
  properties: {
    publicAccess: 'None'
  }
}

// WORM. `allowProtectedAppendWrites` is the whole point: it permits appends to
// an append blob while forbidding modification or deletion of what is already
// there, which is exactly the shape of a hash-chained trail.
//
// ⚠️ `state: Unlocked` is deliberate and is a stated limitation. An unlocked
// policy can be shortened or removed by someone with the management-plane
// role, so this is tamper-*evident* rather than tamper-proof until it is
// locked. Locking is irreversible — the retention period can then only be
// extended, never reduced, for the life of the account — so it is a decision
// for a human at go-live, not a default in a template.
resource immutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  parent: auditContainer
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: auditImmutabilityDays
    allowProtectedAppendWrites: true
  }
}

// Storage Blob Data Contributor, scoped to the CONTAINER and not the account.
// Contributor rather than Appender because the sink also reads the trail back
// to resume the chain and to verify it. Scoping to the container is what keeps
// that from being a general data-plane grant.
var storageBlobDataContributor = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

resource auditRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: auditContainer
  name: guid(auditContainer.id, identity.id, storageBlobDataContributor)
  properties: {
    roleDefinitionId: storageBlobDataContributor
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// CanNotDelete on the two resources that hold the evidence. The immutability
// policy is a DATA-plane control: it stops the blob being modified or deleted,
// and does nothing about one management-plane `DELETE` of the account beneath
// it (WS10 SEC-M-03). A lock is not a strong control — anyone who can remove
// it can then delete — but it converts an accident, and a single mis-scoped
// script, into a deliberate two-step act.
resource storageLock 'Microsoft.Authorization/locks@2020-05-01' = {
  scope: storage
  name: 'dsar-audit-cannotdelete'
  properties: {
    level: 'CanNotDelete'
    notes: 'Holds the DSAR audit trail under a time-based immutability policy. Deleting the account destroys evidence the policy exists to preserve.'
  }
}

resource logsLock 'Microsoft.Authorization/locks@2020-05-01' = {
  scope: logs
  name: 'dsar-logs-cannotdelete'
  properties: {
    level: 'CanNotDelete'
    notes: 'Holds the stderr copy of the audit trail and the sign-in join data.'
  }
}

// Who read, wrote or deleted a blob — including the audit trail itself. Absent
// until WS10 SEC-M-03: the trail recorded what operators did in the
// application and nothing recorded access to the trail.
//
// ⚠️ This lands in the SAME workspace, which is in the same resource group and
// under the same locks. It is better than nothing and it is not the
// independent copy the threat model wants; a workspace in another subscription
// is the honest version and is a decision rather than a template default.
resource blobAudit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: blobService
  name: 'dsar-blob-access'
  properties: {
    workspaceId: logs.id
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
  }
}

output environmentId string = environment.id
output identityId string = identity.id
output identityClientId string = identity.properties.clientId
output identityPrincipalId string = identity.properties.principalId
output auditContainerUrl string = '${storage.properties.primaryEndpoints.blob}${auditContainerName}'
