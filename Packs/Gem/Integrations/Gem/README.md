[Enter a comprehensive, yet concise, description of what the integration does, what use cases it is designed for, etc.]
This integration was integrated and tested with version xx of Gem.

## Configure Gem on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Gem.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Endpoint | The API endpoint to use for connection \(US or EU\) | True |
    | Service Account ID | The Service Account ID to use for connection | True |
    | Service Account Secret | The Service Account Secret to use for connection | True |
    | Sync incidents 30 days back |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gem-list-threats

***
List all threats detected in Gem

#### Base Command

`gem-list-threats`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number to return. Default is 1. | Required | 
| page_size | The number of items to return per page. Default is 10. | Required | 
| ordering | The ordering of the items. Possible values are: -timeframe_start, timeframe_state, -mitre_technique, mitre_technique, -severity, severity, -assignee, assignee, -is_resolved, is_resolved. Default is -timeframe_start. | Optional | 
| status | The status of the threats to return. Possible values are: open, resolved, in_progress. | Optional | 
| ttp_id | The TTP ID of the threats to return. | Optional | 
| title | The title of the threats to return. | Optional | 
| severity | The severity of the threats to return. Possible values are: low, medium, high. | Optional | 
| cloud_provider | The provider of the threats to return. Possible values are: aws, azure, gcp, okta, huawei. | Optional | 
| entity_type | The entity type of the threats to return. | Optional | 
| time_start | The start time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| time_end | The end time of the threats to return in ISO format. Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

There is no context output for this command.

### gem-get-threat-details

***
Get details about a specific threat

#### Base Command

`gem-get-threat-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| threat_id | The ID of the threat to get details for. | Required | 

#### Context Output

There is no context output for this command.

### gem-list-inventory-resources

***
List inventory resources in Gem

#### Base Command

`gem-list-inventory-resources`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cursor | The cursor to use for pagination. | Optional | 
| page_size | The number of items to return per page. Default is 10. | Required | 
| include_deleted | Include deleted resources in the response. | Optional | 
| region | The region of the resources to return. | Optional | 
| resource_type | The type of the resources to return. | Optional | 
| search | The search query to use. | Optional | 
| total | Whether to include the total count of resources in the response. | Optional | 

#### Context Output

There is no context output for this command.

### gem-get-resource-details

***
Get details about a specific resource

#### Base Command

`gem-get-resource-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | The ID of the resource to get details for. | Required | 

#### Context Output

There is no context output for this command.

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

There is no context output for this command.

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

There is no context output for this command.

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

There is no context output for this command.

### gem-list-accessing-entities

***
List all entities that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Gem ID of the resource. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| resource_type | Type of the resource. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

There is no context output for this command.

### gem-list-using-entities

***
List all entities that used an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-using-entities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Gem ID of the resource. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| resource_type | Type of the resource. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

There is no context output for this command.

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

There is no context output for this command.

### gem-list-accessing-ips

***
List all source IP addresses that accessed an entity in a specific timeframe. The results are sorted by activity volume.

#### Base Command

`gem-list-accessing-ips`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_id | Gem ID of the resource. This property is also available for every resource in the Inventory screen. Example: arn:aws:ec2:us-east-1:112233445566:instance/i-1234567890abcdefg. | Required | 
| resource_type | Type of the resource. See documentation for the full options list. | Required | 
| read_only | Show read-only events. | Optional | 
| start_time | Timeframe start (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 
| end_time | Timeframe end (ISO format). Examples: 2023-01-01, 2023-01-01T01:01:01Z, 2023-01-01T01:01:01+00:00. | Required | 

#### Context Output

There is no context output for this command.

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
| verdict | The verdict of the threat. Possible values are: malicious, security_test, planned_action, not_malicious, inconclusive. | Required | 
| reason | The reason for resolving the threat. | Optional | 

#### Context Output

There is no context output for this command.
