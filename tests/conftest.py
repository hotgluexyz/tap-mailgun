import pytest

from tap_mailgun.client import get_client


@pytest.fixture(name='mock_context')
def _mock_context(mocker):
    return mocker.patch('tap_mailgun.Context', autospec=True)


@pytest.fixture(name='mailgun_client')
def _mailgun_client():
    return get_client(
        base_url='https://api.mailgun.net/v3/',
        private_key='test_private_key',
        headers={'User-Agent': 'test_user_agent'},
    )


@pytest.fixture(name='mock_response_json')
def _mock_response_json():
    return {
        'items': [
            {
                'address': 'alice@example.com',
                'tag': '*',
                'created_at': 'Fri, 21 Oct 2011 11:02:55 GMT',
            },
            {
                'address': 'alice@example.com',
                'tag': '*',
                'created_at': 'Fri, 21 Oct 2011 11:02:55 GMT',
            },
            {
                'address': 'alice@example.com',
                'tag': '*',
                'created_at': 'Fri, 21 Oct 2011 11:02:55 GMT',
            },
        ],
        'paging': {
            'first': 'https://api.mailgun.net/v3/first',
            'next': 'https://api.mailgun.net/v3/next',
            'previous': 'https://api.mailgun.net/v3/previous',
            'last': 'https://api.mailgun.net/v3/last',
        },
    }


@pytest.fixture(name='mock_empty_response_json')
def _mock_empty_response_json():
    return {"items": []}


@pytest.fixture(name='mock_schema')
def _mock_schema():
    return {
        'type': 'object',
        'properties': {
            'address': {'type': 'string'},
            'created_at': {'type': 'string', 'format': 'date-time'},
            'code': {'type': ['null', 'string']},
            'domain_id': {'type': 'string'},
            'error': {'type': ['null', 'string']},
            'smtp_password': {'type': 'string'},
        },
        'required': ['address', 'created_at', 'domain_id'],
    }


@pytest.fixture(name='mock_catalog')
def _mock_catalog():
    return {
        'streams': [
            {
                'stream': 'test_stream',
                'tap_stream_id': 'test_stream',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'address': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'code': {'type': ['null', 'string']},
                        'domain_id': {'type': 'string'},
                        'error': {'type': ['null', 'string']},
                        'smtp_password': {'type': 'string'},
                    },
                    'required': ['address', 'created_at', 'domain_id'],
                },
                'metadata': [
                    {
                        'breadcrumb': (),
                        'metadata': {
                            'table-key-properties': [
                                'domain_id',
                                'address',
                                'created_at',
                            ],
                            'selected': True,
                        },
                    },
                    {
                        'breadcrumb': ('properties', 'address'),
                        'metadata': {'inclusion': 'automatic'},
                    },
                    {
                        'breadcrumb': ('properties', 'created_at'),
                        'metadata': {'inclusion': 'automatic'},
                    },
                    {
                        'breadcrumb': ('properties', 'code'),
                        'metadata': {
                            'inclusion': 'available',
                            'selected-by-default': True,
                        },
                    },
                    {
                        'breadcrumb': ('properties', 'domain_id'),
                        'metadata': {'inclusion': 'automatic'},
                    },
                    {
                        'breadcrumb': ('properties', 'error'),
                        'metadata': {
                            'inclusion': 'available',
                            'selected-by-default': True,
                        },
                    },
                    {
                        'breadcrumb': ('properties', 'smtp_password'),
                        'metadata': {'inclusion': 'available'},
                    },
                ],
                'key_properties': ['domain_id', 'address', 'created_at'],
            }
        ]
    }


@pytest.fixture(name='mock_state')
def _mock_state():
    return {'events': '2020-01-01T00:00:00.000000Z'}


@pytest.fixture(name='mock_config')
def _mock_config():
    return {'start_date': '2020-01-01T00:00:00.000000Z'}
