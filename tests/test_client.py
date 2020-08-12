import datetime as dt

import pytest

from tap_mailgun.client import MailgunAPIError


def test_get_client(mailgun_client):
    """
    Ensure that the MailgunClient class is initiated with the correct values.
    """
    client = mailgun_client
    assert client.base_url == 'https://api.mailgun.net/v3/'
    assert client.session.auth == ('api', 'test_private_key')
    assert client.session.headers['User-Agent'] == 'test_user_agent'


@pytest.mark.parametrize('status_code', [401, 403, 500])
def test_do_authenticated_request_error(mailgun_client, requests_mock, status_code):
    """
    Ensure that an exception is raised when an error status code is returned with a request.
    """
    requests_mock.get(mailgun_client.base_url, status_code=status_code)
    with pytest.raises(MailgunAPIError):
        mailgun_client._do_authenticated_request(
            mailgun_client.base_url, stream='stream'
        )


def test_do_authenticated_request_404(mailgun_client, requests_mock):
    """
    Ensure that 404 status code does not raise an exception, 404s are allowed as objects can be deleted from Mailgun
    prior to being synced.
    """
    requests_mock.get(mailgun_client.base_url, status_code=404)
    response = mailgun_client._do_authenticated_request(
        mailgun_client.base_url, stream='stream'
    )
    assert response == {}


def test_auto_paginate(
    mailgun_client, requests_mock, mock_response_json, mock_empty_response_json
):
    """
    Ensure that the correct amount of items are yielded from the _auto_paginate method.
    """
    requests_mock.get(mailgun_client.base_url, json=mock_response_json)
    requests_mock.get(
        mock_response_json['paging']['next'], json=mock_empty_response_json
    )
    # list call is needed to consume the generator
    response = list(
        mailgun_client._auto_paginate(
            url='https://api.mailgun.net/v3/', entity='stream', params={'test': 'param'}
        )
    )

    assert len(mock_response_json['items']) == 3
    assert len(response) == 3


def test_get_message(mailgun_client, requests_mock):
    """
    Ensure that the correct method is called during get_message.
    """
    request_url = 'https://api.mailgun.net/v3/test_storage_url'
    mock = requests_mock.get(request_url, json=[])
    mailgun_client.get_message(storage_url=request_url)

    assert len(mock.request_history) == 1
    assert mock.request_history[0].url == request_url


def test_get_single_suppression(
    mailgun_client, requests_mock, mock_empty_response_json
):
    """
    Ensure that the correct method is called during get_single_suppression.
    """
    request_url = (
        'https://api.mailgun.net/v3/test_domain_name/unsubscribes/test@address.com'
    )
    mock = requests_mock.get(request_url, json=mock_empty_response_json)
    mailgun_client.get_single_suppression(
        domain_name='test_domain_name',
        suppression_type='unsubscribes',
        address='test@address.com',
    )

    assert len(mock.request_history) == 1
    assert mock.request_history[0].url == request_url


def test_get_events(mailgun_client, requests_mock, mock_empty_response_json):
    """
    Ensure that the correct method is called during get_events.
    """
    request_url = 'https://api.mailgun.net/v3/test_domain_name/events'
    mock = requests_mock.get(request_url, json=mock_empty_response_json)
    now = dt.datetime(2019, 12, 31, 0, 0, tzinfo=dt.timezone.utc)
    # list call is needed to consume the generator
    list(mailgun_client.get_events(domain_name='test_domain_name', begin=now, end=now))

    assert len(mock.request_history) == 1
    assert (
        mock.request_history[0].url
        == 'https://api.mailgun.net/v3/test_domain_name/events?begin=2019-12-31+00%3A00%3A00%2B00%3A00&end=2019-12-31'
        '+00%3A00%3A00%2B00%3A00'
    )


def test_get_all_suppressions_of_type(
    mailgun_client, requests_mock, mock_empty_response_json
):
    """
    Ensure that the correct method is called during get_all_suppressions_of_type.
    """
    request_url = 'https://api.mailgun.net/v3/test_domain_name/unsubscribes'
    mock = requests_mock.get(request_url, json=mock_empty_response_json)
    # list call is needed to consume the generator
    list(
        mailgun_client.get_all_suppressions_of_type(
            domain_name='test_domain_name', suppression_type='unsubscribes'
        )
    )

    assert len(mock.request_history) == 1
    assert mock.request_history[0].url == request_url


def test_get_domains(mailgun_client, requests_mock, mock_empty_response_json):
    """
    Ensure that the correct method is called during get_domains.
    """
    request_url = 'https://api.mailgun.net/v3/domains'
    mock = requests_mock.get(request_url, json=mock_empty_response_json)
    # list call is needed to consume the generator
    list(mailgun_client.get_domains())

    assert len(mock.request_history) == 1
    assert mock.request_history[0].url == request_url
