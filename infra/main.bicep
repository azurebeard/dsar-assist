// DSAR Assist — hosted mode. Subscription scope.
//
// Deploys the resource group and everything in it. Entra objects are NOT here:
// the Microsoft.Graph Bicep extension is still preview, so the app
// registration, its app roles, the app management policy and the federated
// identity credential live in `infra/entra/provision.sh`, which takes the
// managed identity's principal id from this deployment's output. Revisit when
// that extension reaches GA.
//
//   az deployment sub create \
//     --location uksouth \
//     --template-file infra/main.bicep \
//     --parameters appClientId=<hosted app registration id> \
//                  allowedIpRanges='["203.0.113.0/24"]'
//
// CAF naming throughout: <type>-<workload>-<env>-<region>-<instance>.

targetScope = 'subscription'

@description('Deployment environment. Part of every resource name.')
@allowed(['dev', 'prod'])
param environment string = 'prod'

@description('Azure region. UK South for a UK data subject access tool.')
param location string = 'uksouth'

@description('Instance number, so a second deployment does not collide.')
param instance string = '01'

@description('Application (client) ID of the hosted Entra app registration. Not a secret — it identifies a registration, it does not authorise anything.')
param appClientId string

@description('Tenant ID. Pins the authority; never /common.')
param tenantId string = subscription().tenantId

@description('Container image, BY DIGEST. A tag can be repointed upstream with no change here, and reproducibility is this project is reason for existing.')
param containerImage string = 'ghcr.io/azurebeard/dsar-assist@sha256:0000000000000000000000000000000000000000000000000000000000000000'

@description('CIDR ranges permitted to reach the ingress. DELIBERATELY NO DEFAULT: deployment fails until a human decides whether this endpoint is internet-facing. An empty array is a valid, explicit answer meaning "open to the internet".')
param allowedIpRanges array

@description('Days the audit trail is held immutable. Cannot be shortened once set; it can only be extended or locked.')
@minValue(1)
param auditImmutabilityDays int = 2555 // seven years

var workload = 'dsar'
var suffix = '${workload}-${environment}-uks-${instance}'
var resourceGroupName = 'rg-${suffix}'
// Storage account names allow no hyphens and cap at 24 characters.
var storageAccountName = 'st${workload}${environment}uks${instance}'

var tags = {
  workload: 'DSAR Assist'
  environment: environment
  dataClassification: 'audit-metadata-only'
  // Stated in the tags because the question "does this hold personal data"
  // gets asked of an inventory, not of a design document.
  contents: 'no-item-content'
}

resource rg 'Microsoft.Resources/resourceGroups@2024-11-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module platform 'modules/platform.bicep' = {
  name: 'platform'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    storageAccountName: storageAccountName
    auditImmutabilityDays: auditImmutabilityDays
  }
}

module app 'modules/containerapp.bicep' = {
  name: 'containerapp'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    containerImage: containerImage
    appClientId: appClientId
    tenantId: tenantId
    allowedIpRanges: allowedIpRanges
    environmentId: platform.outputs.environmentId
    identityId: platform.outputs.identityId
    identityClientId: platform.outputs.identityClientId
    auditBlobUrl: platform.outputs.auditContainerUrl
  }
}

@description('Feed this to infra/entra/provision.sh hosted — it is the FIC subject, and it is CASE-SENSITIVE.')
output identityPrincipalId string = platform.outputs.identityPrincipalId

@description('DSAR_UAMI_CLIENT_ID for the container.')
output identityClientId string = platform.outputs.identityClientId

@description('Register this exact URI as a redirect URI on the hosted app registration.')
output redirectUri string = '${app.outputs.appUrl}/auth/callback'

output appUrl string = app.outputs.appUrl
output auditContainerUrl string = platform.outputs.auditContainerUrl
