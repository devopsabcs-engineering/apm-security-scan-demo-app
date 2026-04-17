@description('Name prefix for storage resources (used with uniqueString for global uniqueness)')
param namePrefix string = 'stapmscan'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Principal ID for Storage Blob Data Reader RBAC assignment')
param readerPrincipalId string = ''

@description('Principal type for the RBAC assignment')
@allowed(['User', 'Group', 'ServicePrincipal'])
param readerPrincipalType string = 'ServicePrincipal'

var storageAccountName = '${namePrefix}${uniqueString(resourceGroup().id)}'
var containerName = 'apm-security-results'

var storageBlobDataReaderRoleId = '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  tags: {
    Application: 'apm-security-scanner'
    Department: 'Engineering'
    Project: 'APMSecurity'
    ManagedBy: 'Bicep'
  }
  properties: {
    isHnsEnabled: true
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

resource blobDataReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(readerPrincipalId)) {
  name: guid(storageAccount.id, readerPrincipalId, storageBlobDataReaderRoleId)
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageBlobDataReaderRoleId)
    principalId: readerPrincipalId
    principalType: readerPrincipalType
  }
}

output storageAccountName string = storageAccount.name
output containerName string = containerName
output storageAccountId string = storageAccount.id
output dfsEndpoint string = 'https://${storageAccount.name}.dfs.core.windows.net'
