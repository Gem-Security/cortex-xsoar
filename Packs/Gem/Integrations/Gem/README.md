Use Gem alerts as a trigger for Cortex XSOAR’s custom playbooks, to automate response to specific TTPs.
This integration was integrated and tested with version xx of Gem.

## Configure Gem on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gem.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Incident type |  | False |
    | API Endpoint | The API endpoint to use for connection \(US or EU\) | True |
    | Service Account ID | The Service Account ID to use for connection | True |
    | Service Account Secret | The Service Account Secret to use for connection | True |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Maximum number of alerts per fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gem-list-threats

***
List all threats detected in Gem.

#### Base Command

`gem-list-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of alert to fetch. Default is 50. | Optional | 
| time_start | The start time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| time_end | The end time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| ordering | The ordering of the items. Possible values are: -timeframe_start, timeframe_state, -mitre_technique, mitre_technique, -severity, severity, -assignee, assignee, -is_resolved, is_resolved. Default is -timeframe_start. | Optional | 
| status | The status of the threats to return. Possible values are: open, resolved, in_progress. | Optional | 
| ttp_id | The TTP ID of the threats to return. | Optional | 
| title | The title of the threats to return. | Optional | 
| severity | The severity of the threats to return. Possible values are: low, medium, high. | Optional | 
| cloud_provider | The provider of the threats to return. Possible values are: aws, azure, gcp, okta, huawei. | Optional | 
| entity_type | The entity type of the threats to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.ThreatsList.accounts.account_status | String |  | 
| Gem.ThreatsList.accounts.cloud_provider | String |  | 
| Gem.ThreatsList.accounts.display_name | String |  | 
| Gem.ThreatsList.accounts.hierarchy_path.id | String |  | 
| Gem.ThreatsList.accounts.hierarchy_path.name | String |  | 
| Gem.ThreatsList.accounts.id | Number |  | 
| Gem.ThreatsList.accounts.identifier | String |  | 
| Gem.ThreatsList.accounts.organization_name | String |  | 
| Gem.ThreatsList.alert_source | String |  | 
| Gem.ThreatsList.alerts.accounts.account_status | String |  | 
| Gem.ThreatsList.alerts.accounts.cloud_provider | String |  | 
| Gem.ThreatsList.alerts.accounts.display_name | String |  | 
| Gem.ThreatsList.alerts.accounts.id | Number |  | 
| Gem.ThreatsList.alerts.accounts.identifier | String |  | 
| Gem.ThreatsList.alerts.accounts.organization_name | String |  | 
| Gem.ThreatsList.alerts.alert_source | String |  | 
| Gem.ThreatsList.alerts.datetime | Date |  | 
| Gem.ThreatsList.alerts.description | String |  | 
| Gem.ThreatsList.alerts.entities.activity_by_provider | Unknown |  | 
| Gem.ThreatsList.alerts.entities.cloud_provider | String |  | 
| Gem.ThreatsList.alerts.entities.id | String |  | 
| Gem.ThreatsList.alerts.entities.is_main_entity | Boolean |  | 
| Gem.ThreatsList.alerts.entities.is_secondary_entity | Boolean |  | 
| Gem.ThreatsList.alerts.entities.resource_id | Unknown |  | 
| Gem.ThreatsList.alerts.entities.type | String |  | 
| Gem.ThreatsList.alerts.id | String |  | 
| Gem.ThreatsList.alerts.main_alert_id | String |  | 
| Gem.ThreatsList.alerts.mitre_techniques.id | String |  | 
| Gem.ThreatsList.alerts.mitre_techniques.technique_name | String |  | 
| Gem.ThreatsList.alerts.organization_id | String |  | 
| Gem.ThreatsList.alerts.severity | Number |  | 
| Gem.ThreatsList.alerts.severity_text | String |  | 
| Gem.ThreatsList.alerts.status | String |  | 
| Gem.ThreatsList.alerts.title | String |  | 
| Gem.ThreatsList.alerts.ttp_id | String |  | 
| Gem.ThreatsList.assignees | Unknown |  | 
| Gem.ThreatsList.category | String |  | 
| Gem.ThreatsList.datetime | Date |  | 
| Gem.ThreatsList.description | String |  | 
| Gem.ThreatsList.entities.activity_by_provider | Unknown |  | 
| Gem.ThreatsList.entities.cloud_provider | String |  | 
| Gem.ThreatsList.entities.id | String |  | 
| Gem.ThreatsList.entities.is_main_entity | Boolean |  | 
| Gem.ThreatsList.entities.is_secondary_entity | Boolean |  | 
| Gem.ThreatsList.entities.resource_id | Unknown |  | 
| Gem.ThreatsList.entities.type | String |  | 
| Gem.ThreatsList.id | String |  | 
| Gem.ThreatsList.main_alert_id | String |  | 
| Gem.ThreatsList.mitre_techniques.id | String |  | 
| Gem.ThreatsList.mitre_techniques.technique_name | String |  | 
| Gem.ThreatsList.organization_id | String |  | 
| Gem.ThreatsList.severity_text | String |  | 
| Gem.ThreatsList.status | String |  | 
| Gem.ThreatsList.title | String |  | 
| Gem.ThreatsList.ttp_id | String |  | 

### gem-get-threat-details

***
Get details about a specific threat.

#### Base Command

`gem-get-threat-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Threat.accounts.account_status | String |  | 
| Gem.Threat.accounts.cloud_provider | String |  | 
| Gem.Threat.accounts.display_name | String |  | 
| Gem.Threat.accounts.hierarchy_path.id | String |  | 
| Gem.Threat.accounts.hierarchy_path.name | String |  | 
| Gem.Threat.accounts.id | Number |  | 
| Gem.Threat.accounts.identifier | String |  | 
| Gem.Threat.accounts.organization_name | String |  | 
| Gem.Threat.alert_source | String |  | 
| Gem.Threat.alerts.accounts.account_status | String |  | 
| Gem.Threat.alerts.accounts.cloud_provider | String |  | 
| Gem.Threat.alerts.accounts.display_name | String |  | 
| Gem.Threat.alerts.accounts.id | Number |  | 
| Gem.Threat.alerts.accounts.identifier | String |  | 
| Gem.Threat.alerts.accounts.organization_name | String |  | 
| Gem.Threat.alerts.alert_source | String |  | 
| Gem.Threat.alerts.datetime | Date |  | 
| Gem.Threat.alerts.description | String |  | 
| Gem.Threat.alerts.entities.activity_by_provider | Unknown |  | 
| Gem.Threat.alerts.entities.cloud_provider | String |  | 
| Gem.Threat.alerts.entities.id | String |  | 
| Gem.Threat.alerts.entities.is_main_entity | Boolean |  | 
| Gem.Threat.alerts.entities.is_secondary_entity | Boolean |  | 
| Gem.Threat.alerts.entities.resource_id | Unknown |  | 
| Gem.Threat.alerts.entities.type | String |  | 
| Gem.Threat.alerts.id | String |  | 
| Gem.Threat.alerts.main_alert_id | String |  | 
| Gem.Threat.alerts.mitre_techniques.id | String |  | 
| Gem.Threat.alerts.mitre_techniques.technique_name | String |  | 
| Gem.Threat.alerts.organization_id | String |  | 
| Gem.Threat.alerts.severity | Number |  | 
| Gem.Threat.alerts.severity_text | String |  | 
| Gem.Threat.alerts.status | String |  | 
| Gem.Threat.alerts.title | String |  | 
| Gem.Threat.alerts.ttp_id | String |  | 
| Gem.Threat.assignees | Unknown |  | 
| Gem.Threat.category | String |  | 
| Gem.Threat.datetime | Date |  | 
| Gem.Threat.description | String |  | 
| Gem.Threat.entities.activity_by_provider | Unknown |  | 
| Gem.Threat.entities.cloud_provider | String |  | 
| Gem.Threat.entities.id | String |  | 
| Gem.Threat.entities.is_main_entity | Boolean |  | 
| Gem.Threat.entities.is_secondary_entity | Boolean |  | 
| Gem.Threat.entities.resource_id | Unknown |  | 
| Gem.Threat.entities.type | String |  | 
| Gem.Threat.id | String |  | 
| Gem.Threat.main_alert_id | String |  | 
| Gem.Threat.mitre_techniques.id | String |  | 
| Gem.Threat.mitre_techniques.technique_name | String |  | 
| Gem.Threat.organization_id | String |  | 
| Gem.Threat.severity_text | String |  | 
| Gem.Threat.status | String |  | 
| Gem.Threat.title | String |  | 
| Gem.Threat.ttp_id | String |  | 

### gem-get-alert-details

***
Get details about a specific alert.

#### Base Command

`gem-get-alert-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Alert.alert_context.account_db_id | String |  | 
| Gem.Alert.alert_context.alert_id | String |  | 
| Gem.Alert.alert_context.alert_source | String |  | 
| Gem.Alert.alert_context.alert_source_id | String |  | 
| Gem.Alert.alert_context.alert_source_url | String |  | 
| Gem.Alert.alert_context.cloud_provider | String |  | 
| Gem.Alert.alert_context.created_at | Date |  | 
| Gem.Alert.alert_context.description | String |  | 
| Gem.Alert.alert_context.description_template | String |  | 
| Gem.Alert.alert_context.general_cloud_provider | String |  | 
| Gem.Alert.alert_context.mitre_techniques.id | String |  | 
| Gem.Alert.alert_context.mitre_techniques.technique_name | String |  | 
| Gem.Alert.alert_context.resolved | Boolean |  | 
| Gem.Alert.alert_context.severity | Number |  | 
| Gem.Alert.alert_context.status | String |  | 
| Gem.Alert.alert_context.timeframe_end | Date |  | 
| Gem.Alert.alert_context.timeframe_start | Date |  | 
| Gem.Alert.alert_context.title | String |  | 
| Gem.Alert.alert_context.ttp_id | String |  | 
| Gem.Alert.triage_configuration.analysis | String |  | 
| Gem.Alert.triage_configuration.entities.activity_by_provider | String |  | 
| Gem.Alert.triage_configuration.entities.cloud_provider | String |  | 
| Gem.Alert.triage_configuration.entities.id | String |  | 
| Gem.Alert.triage_configuration.entities.is_main_entity | Boolean |  | 
| Gem.Alert.triage_configuration.entities.is_secondary_entity | Boolean |  | 
| Gem.Alert.triage_configuration.entities.resource_id | String |  | 
| Gem.Alert.triage_configuration.entities.type | String |  | 
| Gem.Alert.triage_configuration.event_groups.description | String |  | 
| Gem.Alert.triage_configuration.event_groups.end_time | Date |  | 
| Gem.Alert.triage_configuration.event_groups.error_code | String |  | 
| Gem.Alert.triage_configuration.event_groups.event_name | String |  | 
| Gem.Alert.triage_configuration.event_groups.event_type | String |  | 
| Gem.Alert.triage_configuration.event_groups.events | String |  | 
| Gem.Alert.triage_configuration.event_groups.start_time | Date |  | 
| Gem.Alert.triage_configuration.event_groups.time_indicator_text | String |  | 
| Gem.Alert.triage_configuration.event_groups.timeline_item_type | String |  | 
| Gem.Alert.triage_configuration.event_groups.title | String |  | 
| Gem.Alert.triage_configuration.event_groups.type | String |  | 
| Gem.Alert.triage_configuration.resolve_params.include_data_events | Boolean |  | 
| Gem.Alert.triage_configuration.resolve_params.timeframe_lookup_window_hours | Number |  | 
| Gem.Alert.triage_configuration.state | String |  | 

### gem-list-inventory-resources

***
List inventory resources in Gem.

#### Base Command

`gem-list-inventory-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The number of items to return. Default is 50. | Optional | 
| include_deleted | Include deleted resources in the response. | Optional | 
| region | The region of the resources to return. | Optional | 
| resource_type | The type of the resources to return. | Optional | 
| search | The search query to use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.InventoryItems.account.account_status | String |  | 
| Gem.InventoryItems.account.cloud_provider | String |  | 
| Gem.InventoryItems.account.display_name | String |  | 
| Gem.InventoryItems.account.hierarchy_path | String |  | 
| Gem.InventoryItems.account.id | Number |  | 
| Gem.InventoryItems.account.identifier | String |  | 
| Gem.InventoryItems.account.organization_name | String |  | 
| Gem.InventoryItems.account.tenant | String |  | 
| Gem.InventoryItems.categories | String |  | 
| Gem.InventoryItems.created_at | Date |  | 
| Gem.InventoryItems.deleted | Boolean |  | 
| Gem.InventoryItems.external_url | String |  | 
| Gem.InventoryItems.identifiers.name | String |  | 
| Gem.InventoryItems.identifiers.value | String |  | 
| Gem.InventoryItems.region | String |  | 
| Gem.InventoryItems.resource_id | String |  | 
| Gem.InventoryItems.resource_type | String |  | 
| Gem.InventoryItems.tags | Unknown |  | 

### gem-get-resource-details

***
Get details about a specific resource.

#### Base Command

`gem-get-resource-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.InventoryItem.account.account_status | String |  | 
| Gem.InventoryItem.account.cloud_provider | String |  | 
| Gem.InventoryItem.account.display_name | String |  | 
| Gem.InventoryItem.account.hierarchy_path | Unknown |  | 
| Gem.InventoryItem.account.id | Number |  | 
| Gem.InventoryItem.account.identifier | String |  | 
| Gem.InventoryItem.account.organization_name | String |  | 
| Gem.InventoryItem.account.tenant | String |  | 
| Gem.InventoryItem.categories | String |  | 
| Gem.InventoryItem.created_at | Date |  | 
| Gem.InventoryItem.deleted | Boolean |  | 
| Gem.InventoryItem.external_url | String |  | 
| Gem.InventoryItem.identifiers.name | String |  | 
| Gem.InventoryItem.identifiers.value | String |  | 
| Gem.InventoryItem.region | String |  | 
| Gem.InventoryItem.resource_id | String |  | 
| Gem.InventoryItem.resource_type | String |  | 

### gem-list-ips-by-entity

***
List all source IP addresses used by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-ips-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.IP.AS_NAME | String |  | 
| Gem.IP.AS_NUMBER | String |  | 
| Gem.IP.CITY | String |  | 
| Gem.IP.COUNTRY_CODE | String |  | 
| Gem.IP.COUNTRY_NAME | String |  | 
| Gem.IP.COUNT_SOURCEIP | String |  | 
| Gem.IP.IP_TYPE | String |  | 
| Gem.IP.IS_PRIVATE | String |  | 
| Gem.IP.LATITUDE | String |  | 
| Gem.IP.LONGITUDE | String |  | 
| Gem.IP.PROVIDER | String |  | 
| Gem.IP.SOURCEIPADDRESS | String |  | 

### gem-list-services-by-entity

***
List all services accessed by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-services-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.By.Services.COUNT_SERVICE | String |  | 
| Gem.Entity.By.Services.SERVICE | String |  | 

### gem-list-events-by-entity

***
List all events performed by an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-events-by-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.By.Events.EVENTNAME | String |  | 
| Gem.Entity.By.Events.EVENTNAME_COUNT | String |  | 

### gem-list-accessing-entities

***
List all entities that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Accessing.USER_COUNT | String |  | 
| Gem.Entity.Accessing.USER_ID | String |  | 

### gem-list-using-entities

***
List all entities that used an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-using-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Using.ENTITY_COUNT | String |  | 
| Gem.Entity.Using.ENTITY_ID | String |  | 

### gem-list-events-on-entity

***
List all events performed on an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-events-on-entity`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.On.Events.EVENTNAME | String |  | 
| Gem.Entity.On.Events.EVENTNAME_COUNT | String |  | 

### gem-list-accessing-ips

***
List all source IP addresses that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-ips`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_id | Gem ID of the entity. This will usually be the ARN or CSP ID. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| entity_type | Type of the entity. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Gem.Entity.Accessing.IPs.AS_NAME | String |  | 
| Gem.Entity.Accessing.IPs.AS_NUMBER | String |  | 
| Gem.Entity.Accessing.IPs.CITY | String |  | 
| Gem.Entity.Accessing.IPs.COUNTRY_CODE | String |  | 
| Gem.Entity.Accessing.IPs.COUNTRY_NAME | String |  | 
| Gem.Entity.Accessing.IPs.COUNT_SOURCEIP | String |  | 
| Gem.Entity.Accessing.IPs.IP_TYPE | String |  | 
| Gem.Entity.Accessing.IPs.IS_PRIVATE | String |  | 
| Gem.Entity.Accessing.IPs.LATITUDE | String |  | 
| Gem.Entity.Accessing.IPs.LONGITUDE | String |  | 
| Gem.Entity.Accessing.IPs.PROVIDER | String |  | 
| Gem.Entity.Accessing.IPs.SOURCEIPADDRESS | String |  | 

### gem-update-threat-status

***
Set a threat's status to open, in progress or resolved.

#### Base Command

`gem-update-threat-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to update. | Required | 
| status | The new status of the threat (open, in_progress, resolved). Possible values are: open, in_progress, resolved. | Required | 
| verdict | The verdict of the threat. Possible values are: malicious, security_test, planned_action, not_malicious, inconclusive. | Optional | 
| reason | The reason for resolving the threat. | Optional | 

#### Context Output

There is no context output for this command.
### gem-run-action

***
Run an action on an entity.

#### Base Command

`gem-run-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action | The action to run. | Required | 
| entity_id | The ID of the entity to run the action on. | Required | 
| entity_type | The type of the entity to run the action on. | Required | 
| alert_id | The ID of the alert to run the action on. | Required | 
| resource_id | The ID of the resource to run the action on. | Required | 

#### Context Output

There is no context output for this command.
### gem-add-timeline-event

***
Add a timeline event to a threat.

#### Base Command

`gem-add-timeline-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to add the timeline event to. | Required | 
| comment | The comment to add to the timeline event. | Required | 

#### Context Output

There is no context output for this command.
