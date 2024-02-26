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

# ENDPOINTS
TOKEN_URL = 'https://login.gem.security/oauth/token'
THREATS_ENDPOINT = '/threats'
THREAT_ENDPOINT = '/threats/{id}'
INVENTORY_ENDPOINT = '/inventory'
INVENTORY_ITEM_ENDPOINT = '/inventory/{id}'


''' CLIENT CLASS '''


class GemClient(BaseClient):
    def __init__(self, base_url: str, verify: bool, proxy: bool, client_id: str, client_secret: str):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
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
        return super()._http_request(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            json_data=json_data,
            params=params
        )

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

    def get_alert_list(self, limit=None, severity=None) -> list[dict]:
        """For developing walkthrough purposes, this is a dummy response.
           For real API calls, see the specific_api_endpoint_call_example method.

        Args:
            limit (int): The number of items to generate.
            severity (str) : The severity value of the items returned.

        Returns:
            list[dict]: List of alerts data.
        """

        # TODO: Implement filtering

        response = self.http_request(
            method='GET',
            url_suffix=THREATS_ENDPOINT,
            params={'limit': limit, 'severity': severity}
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
        outputs_key_field='id',
        outputs=result
    )


def get_alert_list(client: GemClient, args: dict[str, Any]) -> CommandResults:
    limit = args.get('limit')
    severity = args.get('severity')

    if not limit:
        raise DemistoException('Limit is a required parameter.')

    if not limit.isdigit():
        raise DemistoException('Limit must be a number.')

    result = client.get_alert_list(limit, severity)

    return CommandResults(
        readable_output=tableToMarkdown('Alerts', result),
        outputs_prefix='Gem.Alert',
        outputs_key_field='id',
        outputs=result
    )


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

        if command == 'gem-get-resource-details':
            return_results(get_resource_details(client, args))
        elif command == 'gem-get-alert-list':
            return_results(get_alert_list(client, args))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
