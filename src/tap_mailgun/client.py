import datetime as dt
from typing import Dict, Generator, Optional
from urllib.parse import urljoin

import requests

import singer

ENDPOINTS = {
    'domains': 'domains',
    'events': '{domain_name}/events',
    'bounces_full': '{domain_name}/bounces',
    'bounces_single': '{domain_name}/bounces/{address}',
    'complaints_full': '{domain_name}/complaints',
    'complaints_single': '{domain_name}/complaints/{address}',
    'unsubscribes_full': '{domain_name}/unsubscribes',
    'unsubscribes_single': '{domain_name}/unsubscribes/{address}',
    'mailing_lists': 'lists/pages',
    'members': 'lists/{list_address}/members/pages'
}

logger = singer.get_logger()


class MailgunAPIError(Exception):
    pass


class MailgunClient:
    """
    Client to GET objects from the Mailgun API. Paginated responses are automatically handled.
    Supported objects:
    - Domains
    - Suppressions (Bounces, Complaints, Unsubscribes)
    - Events
    - Messages
    - Mailing Lists
    """

    def __init__(self, *, base_url: str, session: requests.Session, timeout: int = 10):
        """
        Initialize the API Client.
        Allows for changing the base url and also the session for different
        scenarios.
        """
        self.base_url = base_url
        self.session = session
        self.timeout = timeout

    @singer.utils.backoff(
        exceptions=requests.exceptions.RequestException,
        giveup=singer.utils.exception_is_4xx,
    )
    @singer.utils.ratelimit(10, 1)
    def _do_authenticated_request(
        self,
        url: str,
        *,
        stream: str,
        method: str = 'GET',
        params: Optional[dict] = None,
        **kwargs,
    ):
        params = params or {}

        try:
            with singer.metrics.http_request_timer(endpoint=stream):
                resp = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    params=params,
                    **kwargs,
                )
                if resp.status_code == 404:
                    logger.warning(
                        'GET %s [%s - %s]', url, resp.status_code, resp.content
                    )
                    return {}
                else:
                    resp.raise_for_status()
                    return resp.json()
        except requests.RequestException as exc:
            raise MailgunAPIError(
                'Request API raised an error:{}'.format(resp.content)
            ) from exc

    def get_domains(self) -> Generator[Dict, None, None]:
        entity = 'domains'
        url = urljoin(self.base_url, ENDPOINTS[entity])
        domains = self._do_authenticated_request(url, stream=entity)
        yield from domains['items']

    def get_mailing_lists(self) -> Generator[Dict, None, None]:
        entity = 'mailing_lists'
        url = urljoin(self.base_url, ENDPOINTS[entity])
        yield from self._auto_paginate(url=url, entity=entity)
    
    def get_all_members(
        self, *, list_address: str
    ) -> Generator[Dict, None, None]:
        entity = 'members'
        url = urljoin(self.base_url, ENDPOINTS['members']).format(
            list_address=list_address
        )
        yield from self._auto_paginate(url=url, entity=entity)

    def get_all_suppressions_of_type(
        self, *, domain_name: str, suppression_type: str
    ) -> Generator[Dict, None, None]:
        entity = suppression_type
        url = urljoin(self.base_url, ENDPOINTS[entity + '_full']).format(
            domain_name=domain_name
        )
        yield from self._auto_paginate(url=url, entity=entity)

    def get_events(
        self, *, domain_name: str, begin: dt.datetime, end: dt.datetime
    ) -> Generator[Dict, None, None]:
        entity = 'events'
        url = urljoin(self.base_url, ENDPOINTS[entity]).format(domain_name=domain_name)

        yield from self._auto_paginate(
            url=url, entity=entity, params={'begin': begin, 'end': end}
        )

    def _auto_paginate(
        self, *, url: str, entity: str, params: dict = None
    ) -> Generator[Dict, None, None]:
        params = params or {}
        while True:
            resp = self._do_authenticated_request(url, stream=entity, params=params)
            if not resp['items']:
                break
            yield from resp['items']
            url = resp['paging']['next']

    def get_single_suppression(
        self, *, domain_name: str, suppression_type: str, address: str
    ) -> dict:
        entity = suppression_type
        url = urljoin(self.base_url, ENDPOINTS[entity + '_single']).format(
            domain_name=domain_name, address=address
        )
        return self._do_authenticated_request(url, stream=entity)

    def get_message(self, *, storage_url: str) -> dict:
        entity = 'messages'
        return self._do_authenticated_request(storage_url, stream=entity)


def get_client(
    *, base_url: str, private_key: str, headers: dict, timeout: Optional[int] = None
) -> MailgunClient:
    """
    Sets up a Session with authorisation and headers, returns a MailgunClient object.
    """
    # Basic Auth.
    session = requests.Session()
    session.auth = ('api', private_key)
    session.headers.update(headers)
    return MailgunClient(base_url=base_url, session=session, timeout=timeout)
