import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
import jwt

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
PAGE_SIZE = 5
OK_CODES = (200, 201, 202)

# ENDPOINTS
TOKEN_URL = 'https://login.gem.security/oauth/token'
THREATS_ENDPOINT = '/threats'
THREAT_ENDPOINT = '/threats/{id}'
INVENTORY_ENDPOINT = '/inventory'
INVENTORY_ITEM_ENDPOINT = '/inventory/{id}'
BREAKDOWN_ENDPOINT = '../triage/investigation/timeline/breakdown'
EVENTS_ENDPOINT = '../triage/investigation/entity/events'

UPDATE_THREAT_ENDPOINT = '../detection/threats/{id}/update_threat_status_v2'


''' CLIENT CLASS '''


class GemClient(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, ok_codes=OK_CODES)
        self._client_id = client_id
        self._client_secret = client_secret
        try:
            self._auth_token = self._get_token()
        except Exception as e:
            raise DemistoException(f'Failed to get token. Error: {str(e)}')

    def _get_token(self):
        ctx = get_integration_context()

        if not ctx or not ctx.get('auth_token'):
            # No token in integration context, probably first run
            auth_token = self._generate_token()
        else:
            # Token exists, check if it's expired and generate a new one if needed
            auth_token = ctx.get('auth_token')
            decoded_jwt = jwt.decode(auth_token, options={"verify_signature": False})

            token_expiration = datetime.fromtimestamp(decoded_jwt['exp'])

            if token_expiration < datetime.now():
                auth_token = self._generate_token()

        return auth_token

    def http_request(self, method: str, url_suffix='', full_url=None, headers=None, json_data=None, params=None, auth=True):
        if auth:
            headers = headers or {}
            headers['Authorization'] = f'Bearer {self._auth_token}'
        try:
            return super()._http_request(
                method=method,
                url_suffix=url_suffix,
                full_url=full_url,
                headers=headers,
                json_data=json_data,
                params=params,
                raise_on_status=True
            )
        except DemistoException as e:
            demisto.error(f"Failed to execute {method} request to {url_suffix}. Error: {str(e)}")
            raise Exception(f"Failed to execute {method} request to {url_suffix}. Error: {str(e)}")

    def _generate_token(self) -> str:
        """Generate an access token using the client id and secret
        :return: valid token
        """

        data = {
            'client_id': self._client_id,
            'client_secret': self._client_secret,
            'grant_type': 'client_credentials',
            "audience": "https://backend.gem.security"
        }

        headers = {
            'Content-Type': 'application/json'
        }

        token_res = self.http_request(
            method='POST',
            full_url=TOKEN_URL,
            headers=headers,
            json_data=data,
            auth=False
        )

        set_integration_context((get_integration_context() or {}).update({'auth_token': token_res.get('access_token')}))

        return token_res.get('access_token')

    def get_resource_details(self, resource_id: str) -> dict:
        """ Get inventory item details
        :param resource_id: id of the item to get
        :return: inventory item
        """
        return self.http_request(
            method='GET',
            url_suffix=INVENTORY_ITEM_ENDPOINT.format(id=resource_id)
        )

    def get_threat_details(self, threat_id: str):
        """ Get threat details
        :param threat_id: id of the threat to get
        :return: threat details
        """
        response = self.http_request(
            method='GET',
            url_suffix=THREAT_ENDPOINT.format(id=threat_id)
        )

        return response

    def list_threats(self, limit, time_start=None, time_end=None, ordering=None, status=None, ttp_id=None,
                     title=None, severity=None, entity_type=None, cloud_provider=None) -> list[dict]:
        """ List threats
        :param time_start: time of first threat
        :param time_end: time of last threat
        :param limit: amount of threats
        :param ordering: how to order threats
        :param status: filter of threat status
        :param ttp_id: filter of threat ttp
        :param title: filter of threat title
        :param severity: filter of threat severity
        :param entity_type: filter of threat entity type
        :param cloud_provider: filter of threat cloud provider

        :return: threat list
        """

        results = []
        results_fetched = 0
        for p in range(1, int(limit / PAGE_SIZE) + 2):
            if limit == results_fetched:
                break
            if limit - results_fetched < PAGE_SIZE:
                demisto.debug(f"Fetching page #{p} page_size {limit - results_fetched}")
                params = {'start_time': time_start, 'end_time': time_end, 'page': p, 'page_size': limit - results_fetched,
                          'ordering': ordering,
                          'status': status, 'ttp_id': ttp_id, 'title': title, 'severity': severity, 'entity_type': entity_type,
                          'provider': cloud_provider}
                response = self.http_request(
                    method='GET',
                    url_suffix=THREATS_ENDPOINT,
                    params={k: v for k, v in params.items() if v is not None}

                )
                results_fetched = limit

            else:
                demisto.debug(f"Fetching page #{p} page_size {PAGE_SIZE}")
                params = {'start_time': time_start, 'end_time': time_end, 'page': p, 'page_size': PAGE_SIZE, 'ordering': ordering,
                          'status': status, 'ttp_id': ttp_id, 'title': title, 'severity': severity, 'entity_type': entity_type,
                          'provider': cloud_provider}
                response = self.http_request(
                    method='GET',
                    url_suffix=THREATS_ENDPOINT,
                    params={k: v for k, v in params.items() if v is not None}

                )
                if len(response['results']) < PAGE_SIZE:
                    demisto.debug(f"Fetched {len(response['results'])}")
                    results_fetched += len(response['results'])
                    results.extend(response['results'])
                    break

                results_fetched += PAGE_SIZE

            results.extend(response['results'])

        demisto.debug(f"Fetched {len(results)} threats")

        return results

    def list_inventory_resources(self, limit, include_deleted=None, region=None, resource_type=None,
                                 search=None) -> list[dict]:
        results = []
        results_fetched = 0
        params = {'page_size': limit if limit < PAGE_SIZE else PAGE_SIZE, 'include_deleted': include_deleted, 'region': region,
                  'resource_type': resource_type, 'search': search}
        response = self.http_request(
            method='GET',
            url_suffix=INVENTORY_ENDPOINT,
            params={k: v for k, v in params.items() if v is not None}

        )
        results_fetched += len(response['results'])
        results.extend(response['results'])

        while response['next'] != "" and results_fetched < limit:
            page_size = limit - results_fetched if limit - results_fetched < PAGE_SIZE else PAGE_SIZE
            demisto.debug(f"Fetching page #{response['next']} page_size {page_size}")
            params = {'cursor': response['next'], 'page_size': page_size, 'include_deleted': include_deleted, 'region': region,
                      'resource_type': resource_type, 'search': search}
            response = self.http_request(
                method='GET',
                url_suffix=INVENTORY_ENDPOINT,
                params={k: v for k, v in params.items() if v is not None}

            )
            results_fetched += len(response['results'])
            results.extend(response['results'])

        demisto.debug(f"Fetched {len(results)} inventory resources")

        return results

    def _breakdown(self, breakdown_by, entity_id=None, entity_type=None, read_only=None, start_time=None, end_time=None) -> dict:
        params = {'breakdown_by': breakdown_by, 'entity_id': entity_id, 'entity_type': entity_type, 'read_only': read_only,
                  'start_time': start_time, 'end_time': end_time}
        response = self.http_request(
            method='GET',
            url_suffix=BREAKDOWN_ENDPOINT,
            params={k: v for k, v in params.items() if v is not None}
        )

        return response['table']

    def list_ips_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                           end_time=None) -> dict:
        return self._breakdown(breakdown_by='source_ip', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_services_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                                end_time=None) -> dict:
        return self._breakdown(breakdown_by='service', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_events_by_entity(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                              end_time=None) -> dict:
        return self._breakdown(breakdown_by='entity_event_out', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_accessing_entities(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                                end_time=None) -> dict:
        return self._breakdown(breakdown_by='user_in', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_using_entities(self, entity_id=None, entity_type=None, read_only=None, start_time=None,
                            end_time=None) -> dict:
        return self._breakdown(breakdown_by='using_entities', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_events_on_entity(self, entity_id=None, entity_type=None, start_time=None, end_time=None, read_only=None) -> dict:
        return self._breakdown(breakdown_by='entity_event_in', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def list_accessing_ips(self, entity_id=None, entity_type=None, start_time=None, end_time=None, read_only=None) -> dict:
        return self._breakdown(breakdown_by='ip_access', entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                               start_time=start_time, end_time=end_time)

    def update_threat_status(self, threat_id: str, status: Optional[str], verdict: Optional[str], reason: Optional[str] = None):
        json_data = {"resolved_metadata": {'verdict': verdict, 'reason': reason}, 'status': status}
        response = self.http_request(
            method='PATCH',
            url_suffix=UPDATE_THREAT_ENDPOINT.format(id=threat_id),
            json_data=json_data
        )

        return response


''' HELPER FUNCTIONS '''


def init_client(params: dict) -> GemClient:
    """
    Initializes a new Client object
    """
    return GemClient(
        base_url=params['api_endpoint'],
        verify=True,
        proxy=params.get('proxy', False),
        client_id=params['client_id'],
        client_secret=params['client_secret']
    )


''' COMMAND FUNCTIONS '''


def fetch_threats(client: GemClient, maxincidents=None, firstfetch=None, severity=None, start_time=None, category=None,
                  accounts=None, status=None, assignee=None, mitre_technique_id=None, threat_source=None, entity_type=None,
                  ttp_id=None, provider=None) -> None:
    pass


def test_module(params: dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication.
    Return "ok" if test passed, anything else will fail the test.

    Args:
        params (Dict): Integration parameters

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        init_client(params)
    except Exception:
        raise DemistoException('Authentication failed')

    return 'ok'


def get_resource_details(client: GemClient, args: dict[str, Any]) -> CommandResults:
    resource_id = args.get('resource_id')
    if not resource_id:
        raise DemistoException('Resource ID is a required parameter.')

    result = client.get_resource_details(resource_id)

    return CommandResults(
        readable_output=tableToMarkdown('Inventory Item', result),
        outputs_prefix='Gem.InventoryItem',
        outputs_key_field='resource_id',
        outputs=result
    )


def get_threat_details(client: GemClient, args: dict[str, Any]) -> CommandResults:
    threat_id = args.get('threat_id')

    if not threat_id:
        raise DemistoException('Threat ID is a required parameter.')
    result = client.get_threat_details(threat_id=threat_id)

    return CommandResults(
        readable_output=tableToMarkdown('Threat', result),
        outputs_prefix='Gem.Threat',
        outputs_key_field='id',
        outputs=result
    )


def list_inventory_resources(client: GemClient, args: dict[str, Any]) -> CommandResults:
    limit = arg_to_number(args.get("limit")) or PAGE_SIZE
    include_deleted = args.get('include_deleted')
    region = args.get('region')
    resource_type = args.get('resource_type')
    search = args.get('search')

    result = client.list_inventory_resources(limit, include_deleted=include_deleted,
                                             region=region, resource_type=resource_type, search=search)

    return CommandResults(
        readable_output=tableToMarkdown('Inventory Items', result),
        outputs_prefix='Gem.InventoryItems',
        outputs_key_field='id',
        outputs=result
    )


def list_threats(client: GemClient, args: dict[str, Any]) -> CommandResults:
    time_start = args.get('time_start')
    time_end = args.get('time_end')
    limit = arg_to_number(args.get("limit")) or PAGE_SIZE
    ordering = args.get('ordering')
    status = args.get('status')
    ttp_id = args.get('ttp_id')
    title = args.get('title')
    severity = args.get('severity')
    entity_type = args.get('entity_type')
    cloud_provider = args.get('cloud_provider')

    if not time_start:
        raise DemistoException('Start time is a required parameter.')

    if not time_end:
        raise DemistoException('End time is a required parameter.')

    result = client.list_threats(time_start=time_start, time_end=time_end, limit=limit,
                                 ordering=ordering, status=status, ttp_id=ttp_id, title=title, severity=severity,
                                 entity_type=entity_type, cloud_provider=cloud_provider)

    demisto.debug(f"Got {len(result)} Threats")
    return CommandResults(
        readable_output=tableToMarkdown('Threats', result),
        outputs_prefix='Gem.ThreatsList',
        outputs_key_field='id',
        outputs=result
    )


def _breakdown_validate_params(client: GemClient, args: dict[str, Any]) -> tuple[Any, Any, Any | None, Any, Any]:
    entity_id = args.get('entity_id')
    entity_type = args.get('entity_type')
    read_only = args.get('read_only')
    start_time = args.get('start_time')
    end_time = args.get('end_time')

    if not entity_id:
        raise DemistoException('Entity ID is a required parameter.')

    if not entity_type:
        raise DemistoException('Entity Type is a required parameter.')

    if not start_time:
        raise DemistoException('Start time is a required parameter.')

    if not end_time:
        raise DemistoException('End time is a required parameter.')

    return entity_id, entity_type, read_only, start_time, end_time


def _parse_breakdown_result(result: dict) -> tuple[list[str], list[list[str]], list[dict]]:
    new_t = []

    for r in result['rows']:
        new_t.append(r['row'])

    return result['headers'], new_t, new_t


def list_ips_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_ips_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                       start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('IPs', rows, headers=headers),
        outputs_prefix='Gem.IP',
        outputs_key_field='SOURCEIPADDRESS',
        outputs=outputs
    )


def list_services_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_services_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                            start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Services', rows, headers=headers),
        outputs_prefix='Gem.Entity.By.Services',
        outputs_key_field='SERVICE',
        outputs=outputs
    )


def list_events_by_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_events_by_entity(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                          start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Events by Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.By.Events',
        outputs_key_field='EVENTNAME',
        outputs=outputs
    )


def list_accessing_entities(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_accessing_entities(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                            start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Accessing Entities', rows, headers=headers),
        outputs_prefix='Gem.Entity.Accessing',
        outputs_key_field='',
        outputs=outputs
    )


def list_using_entities(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_using_entities(entity_id=entity_id, entity_type=entity_type, read_only=read_only,
                                        start_time=start_time, end_time=end_time)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Using Entities', rows, headers=headers),
        outputs_prefix='Gem.Entity.Using',
        outputs_key_field='ENTITY_ID',
        outputs=outputs
    )


def list_events_on_entity(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_events_on_entity(entity_id=entity_id, entity_type=entity_type,
                                          start_time=start_time, end_time=end_time, read_only=read_only)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('Events on Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.On.Events',
        outputs_key_field='EVENTNAME',
        outputs=outputs
    )


def list_accessing_ips(client: GemClient, args: dict[str, Any]) -> CommandResults:

    entity_id, entity_type, read_only, start_time, end_time = _breakdown_validate_params(client, args)

    result = client.list_accessing_ips(entity_id=entity_id, entity_type=entity_type,
                                       start_time=start_time, end_time=end_time, read_only=read_only)
    headers, rows, outputs = _parse_breakdown_result(result)

    return CommandResults(
        readable_output=tableToMarkdown('IPs Accessing Entity', rows, headers=headers),
        outputs_prefix='Gem.Entity.Accessing.IPs',
        outputs_key_field='AS_NAME',
        outputs=outputs
    )


def update_threat_status(client: GemClient, args: dict[str, Any]):
    threat_id = args.get('threat_id')
    status = args.get('status')
    verdict = args.get('verdict')
    reason = args.get('reason')

    if not threat_id:
        raise DemistoException('Threat ID is a required parameter.')
    client.update_threat_status(threat_id=threat_id, status=status, verdict=verdict, reason=reason)


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    # TODO: Implement fetch_incidents, use fetch_back param to determine if to fetch 30 days back
    # Whether to fetch incident 30 days back on initial fetch
    params.get('fetch_back', False)

    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            # This is the call made when pressing the integration Test button
            return_results(test_module(params))

        client = init_client(params)

        if command == 'gem-list-threats':
            return_results(list_threats(client, args))
        elif command == 'gem-get-threat-details':
            return_results(get_threat_details(client, args))
        elif command == 'gem-list-inventory-resources':
            return_results(list_inventory_resources(client, args))
        elif command == 'gem-get-resource-details':
            return_results(get_resource_details(client, args))
        elif command == 'gem-list-ips-by-entity':
            return_results(list_ips_by_entity(client, args))
        elif command == 'gem-list-services-by-entity':
            return_results(list_services_by_entity(client, args))
        elif command == 'gem-list-events-by-entity':
            return_results(list_events_by_entity(client, args))
        elif command == 'gem-list-accessing-entities':
            return_results(list_accessing_entities(client, args))
        elif command == 'gem-list-using-entities':
            return_results(list_using_entities(client, args))
        elif command == 'gem-list-events-on-entity':
            return_results(list_events_on_entity(client, args))
        elif command == 'gem-list-accessing-ips':
            return_results(list_accessing_ips(client, args))
        elif command == 'gem-update-threat-status':
            return_results(update_threat_status(client, args))
        elif command == 'fetch-incidents':
            fetch_threats(client)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
