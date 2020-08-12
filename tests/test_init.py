import argparse
import datetime as dt
from unittest.mock import call

import pytest

from singer.catalog import Catalog

import tap_mailgun


def test_context_get_catalog_entry(mocker, mock_catalog):
    """
    Ensure that the expected catalog entry is returned in the expected format.
    """
    mocker.patch.dict('tap_mailgun.Context.catalog', mock_catalog)
    expected = mock_catalog['streams'][0]
    actual = tap_mailgun.Context.get_catalog_entry('test_stream')
    assert expected == actual


def test_context_is_selected(mocker, mock_catalog):
    """
    Ensure that the correct response is received if the stream is selected in the catalog.
    """
    mocker.patch.dict('tap_mailgun.Context.catalog', mock_catalog)
    expected = True
    actual = tap_mailgun.Context.is_selected('test_stream')
    assert expected == actual


def test_context_get_schema(mocker, mock_catalog, mock_schema):
    """
    Ensure that the expected schema is returned in the expected format.
    """
    mocker.patch.dict('tap_mailgun.Context.catalog', mock_catalog)
    expected = mock_schema
    actual = tap_mailgun.Context.get_schema('test_stream')
    assert expected == actual


def test_sync_events(mocker, mock_schema, mock_context):
    """
    Ensure that the expected methods are called based on the returned response from the events endpoint.
    """
    mock_context.is_selected.return_value = True
    mock_context.domains = {'domain_id': 'test_domain_name'}
    mock_context.get_schema.return_value = mock_schema
    mock_context.mailgun_client.get_events.return_value = [
        {
            'id': 'id1',
            'name': 'event1',
            'event': 'test_event',
            'timestamp': 1376325780.160809,
            'storage': {'url': 'test_storage_url'},
        },
        {
            'id': 'id2',
            'event': 'failed',
            'reason': 'bounce',
            'name': 'event2',
            'recipient': 'bounced@recipient.com',
            'timestamp': 1376325780.160809,
        },
        {
            'id': 'id3',
            'event': 'unsubscribed',
            'name': 'event3',
            'recipient': 'unsubscribed@recipient.com',
            'timestamp': 1376325780.160809,
        },
        {
            'id': 'id4',
            'event': 'complained',
            'name': 'event4',
            'recipient': 'complained@recipient.com',
            'timestamp': 1376325780.160809,
        },
    ]

    mocker.patch(
        'tap_mailgun._get_start',
        return_value=dt.datetime(2019, 12, 31, 23, 0, tzinfo=dt.timezone.utc),
    )
    mocker.patch(
        'tap_mailgun.singer.utils.now',
        return_value=dt.datetime(2013, 8, 12, 17, 43, tzinfo=dt.timezone.utc),
    )
    mock_transform = mocker.patch(
        'tap_mailgun._transform_and_write_record', autospec=True
    )
    mock_sync_single_suppression = mocker.patch(
        'tap_mailgun.sync_single_suppression', autospec=True
    )
    mocker.patch('tap_mailgun.singer.utils.update_state', autospec=True)

    tap_mailgun.sync_events()

    assert mock_transform.call_count == 4
    mock_context.messages.add.assert_called_once_with('test_storage_url')
    mock_sync_single_suppression.assert_has_calls(
        [
            call('bounces', 'bounced@recipient.com'),
            call('unsubscribes', 'unsubscribed@recipient.com'),
            call('complaints', 'complained@recipient.com'),
        ],
        any_order=False,
    )


def test_get_start_no_state(mock_context):
    """
    Ensure that the expected value is returned from the _get_start function when no state is present.
    """
    mock_context.config = {'start_date': '2019-01-01T00:00:00.000000Z'}
    expected = dt.datetime(2019, 1, 1, 0, 0, tzinfo=dt.timezone.utc)
    actual = tap_mailgun._get_start('events')

    assert expected == actual


def test_get_start_state(mock_state, mock_context):
    """
    Ensure that the expected value is returned from the _get_start function when a state is present.
    """
    mock_context.config = {'event_lookback': 1}
    mock_context.state = mock_state

    expected = dt.datetime(2019, 12, 31, 23, 0, tzinfo=dt.timezone.utc)
    actual = tap_mailgun._get_start('events')

    assert expected == actual


def test_get_streams_to_sync(mock_catalog, mock_context):
    """
    Ensure that the catalog is read properly and the expected selected streams are returned by _get_streams_to_sync.
    """
    mock_context.catalog = mock_catalog

    expected = frozenset(['test_stream'])
    actual = tap_mailgun._get_streams_to_sync()

    assert expected == actual


def test_populate_metadata(mocker, mock_schema):
    """
    Ensure that metadata is populated as expected...
    - Key properties are applied
    - Fields are selected by default with the exception of smtp_password.
    """
    mocker.patch.dict(
        'tap_mailgun.KEY_PROPERTIES',
        {'test_schema': ['domain_id', 'address', 'created_at']},
    )

    expected = {
        (): {
            'table-key-properties': ['domain_id', 'address', 'created_at'],
            'selected': True,
        },
        ('properties', 'address'): {'inclusion': 'automatic'},
        ('properties', 'created_at'): {'inclusion': 'automatic'},
        ('properties', 'code'): {'inclusion': 'available', 'selected-by-default': True},
        ('properties', 'domain_id'): {'inclusion': 'automatic'},
        ('properties', 'error'): {
            'inclusion': 'available',
            'selected-by-default': True,
        },
        ('properties', 'smtp_password'): {'inclusion': 'available'},
    }

    actual = tap_mailgun._populate_metadata(
        schema_name='test_schema', schema=mock_schema
    )

    assert expected == actual


def test_transform_and_write_record(capfd, mock_schema, mock_catalog, mock_context):
    """
    Ensure that stdout from the _transform_and_write_record fuction is expected.
    """
    stream = 'test_stream'
    record = {
        'address': 'test@email.com',
        'created_at': '2020-07-29T14:27:29.000000Z',
        'code': 'test_code',
        'domain_id': 'test_domain_id',
        'error': 'test_error',
    }
    mock_context.catalog = mock_catalog

    tap_mailgun._transform_and_write_record(record, mock_schema, stream)

    expected_stdout = (
        '{"type": "RECORD", "stream": "test_stream", "record": {"address": "test@email.com", '
        '"created_at": "2020-07-29T14:27:29.000000Z", "code": "test_code", "domain_id": '
        '"test_domain_id", "error": "test_error"}}\n'
    )
    actual_stdout = capfd.readouterr().out

    assert expected_stdout == actual_stdout


def test_validate_dependencies():
    """
    Ensure that an exception is raised if there is a dependency exception.
    """
    with pytest.raises(tap_mailgun.DependencyException) as excinfo:
        tap_mailgun._validate_dependencies(frozenset(['bounces']))

    assert 'domains stream is required for this tap to work' in str(excinfo.value)
    assert 'To extract bounces, you need to select the events' in str(excinfo.value)


def test_sync_domains(mocker, mock_schema, mock_context):
    """
    Ensure that the expected functions are called during sync_domains.
    """
    mock_context.get_schema.return_value = mock_schema
    mock_context.mailgun_client.get_domains.return_value = [
        {'id': 'id1', 'name': 'domain1', 'created_at': '2020-07-29T14:27:29.000000Z'},
        {'id': 'id2', 'name': 'domain2', 'created_at': '2020-07-29T14:27:29.000000Z'},
        {'id': 'id3', 'name': 'domain3', 'created_at': '2020-07-29T14:27:29.000000Z'},
        {'id': 'id4', 'name': 'domain4', 'created_at': '2020-07-29T14:27:29.000000Z'},
    ]
    mock_transform = mocker.patch(
        'tap_mailgun._transform_and_write_record', autospec=True
    )

    tap_mailgun.sync_domains()

    mock_context.get_schema.assert_called_once_with('domains')
    mock_context.mailgun_client.get_domains.assert_called_once()
    assert mock_transform.call_count == 4


def test_sync_single_suppression(mocker, mock_schema, mock_context):
    """
    Ensure that the expected functions are called with the correct parameters during sync_single_suppression.
    """
    test_suppression_type = 'bounces'
    test_address = 'test@email.com'
    mock_context.get_schema.return_value = mock_schema
    mock_context.current_domain_name = 'test_domain_name'
    mock_get_suppression = mocker.patch(
        'tap_mailgun.Context.mailgun_client.get_single_suppression',
        return_value={'bounce1': 'value', 'created_at': '2020-07-29T14:27:29.000000Z'},
    )
    mock_transform = mocker.patch(
        'tap_mailgun._transform_and_write_record', autospec=True
    )

    tap_mailgun.sync_single_suppression(test_suppression_type, test_address)

    mock_context.get_schema.assert_called_once_with(test_suppression_type)
    mock_get_suppression.assert_called_once_with(
        domain_name='test_domain_name',
        suppression_type=test_suppression_type,
        address=test_address,
    )
    mock_transform.assert_called_once()


def test_sync_all_suppressions_false(caplog, mock_context):
    """
    Ensure that the sync_all_suppressions function is skipped if config doesn't support it's action.
    """
    mock_context.config = {'full_suppression_sync': False}

    tap_mailgun.sync_all_suppressions('bounces')

    mock_context.get_schema.assert_not_called()

    assert 'full_suppression_sync is not enabled' in caplog.text


def test_sync_all_suppressions_true(mocker, mock_schema, mock_context):
    """
    Ensure that the sync_all_suppressions function is not skipped if config supports it's action.
    Ensure that the correct functions are called with their expected parameters and call_counts.
    """
    test_suppression_type = 'bounces'

    mock_context.config = {'full_suppression_sync': True}
    mock_context.get_schema.return_value = mock_schema
    mock_context.domains = {'domain_id': 'test_domain_name'}

    mock_get_suppressions = mocker.patch(
        'tap_mailgun.Context.mailgun_client.get_all_suppressions_of_type',
        return_value=[
            {'bounce1': 'value', 'created_at': '2020-07-29T14:27:29.000000Z'},
            {'bounce2': 'value', 'created_at': '2020-07-29T14:27:29.000000Z'},
            {'bounce3': 'value', 'created_at': '2020-07-29T14:27:29.000000Z'},
            {'bounce4': 'value', 'created_at': '2020-07-29T14:27:29.000000Z'},
        ],
    )
    mock_transform = mocker.patch(
        'tap_mailgun._transform_and_write_record', autospec=True
    )

    tap_mailgun.sync_all_suppressions(test_suppression_type)

    mock_context.get_schema.assert_called_once_with(test_suppression_type)
    mock_get_suppressions.assert_called_once_with(
        domain_name='test_domain_name', suppression_type=test_suppression_type
    )
    assert mock_transform.call_count == 4


@pytest.mark.parametrize('message_set', [{1, 2, 3}, {}, {1, 2, 3, 4, 5}])
def test_sync_messages(mocker, message_set, mock_context):
    """
    Ensure that the expected functions are called the correct amount of times during sync_messages.
    """
    mock_context.messages = message_set
    mock_transform = mocker.patch(
        'tap_mailgun._transform_and_write_record', autospec=True
    )

    tap_mailgun.sync_messages()

    assert mock_transform.call_count == len(message_set)
    assert mock_context.mailgun_client.get_message.call_count == len(message_set)


def test_do_discover(mocker, mock_schema, mock_catalog, capfd):
    """
    Ensure that the stdout and return value of do_discover is as expected.
    """
    mocker.patch('tap_mailgun._load_schemas', return_value={'test_stream': mock_schema})
    mocker.patch.dict(
        'tap_mailgun.KEY_PROPERTIES',
        {'test_stream': ['domain_id', 'address', 'created_at']},
    )

    return_value = tap_mailgun.do_discover()

    stdout = capfd.readouterr().out

    assert '"stream": "test_stream"' in stdout
    assert return_value == mock_catalog


def test_main_discover(mocker, mock_config, mock_context):
    """
    Ensure that the correct functions are called when tap is executed in discovery mode.
    """
    mocker.patch(
        'tap_mailgun.singer.utils.parse_args',
        return_value=argparse.Namespace(config=mock_config, discover=True, state=None),
    )
    mock_do_discover = mocker.patch('tap_mailgun.do_discover', autospec=True)

    tap_mailgun.main()

    mock_context.config.update.assert_called_once_with(mock_config)
    mock_context.state.update.assert_not_called()
    mock_do_discover.assert_called_once()


def test_main_no_state(mocker, mock_catalog, mock_config, mock_context):
    """
    Ensure that the correct functions are called when tap is executed with no state.
    """
    catalog = Catalog.from_dict(mock_catalog)

    mocker.patch(
        'tap_mailgun.singer.utils.parse_args',
        return_value=argparse.Namespace(
            catalog=catalog, config=mock_config, state=None, discover=None,
        ),
    )

    mock_get_client = mocker.patch('tap_mailgun.get_client', autospec=True)
    mock_do_sync = mocker.patch('tap_mailgun.do_sync', autospec=True)

    tap_mailgun.main()

    mock_context.config.update.assert_called_once_with(mock_config)
    mock_context.state.update.assert_not_called()
    mock_context.catalog.update.assert_called_once_with(catalog.to_dict())
    mock_get_client.assert_called_once()
    mock_do_sync.assert_called_once()
    mock_context.print_counts.assert_called_once()


def test_main_with_state(mocker, mock_config, mock_catalog, mock_state, mock_context):
    """
    Ensure that the correct functions are called when tap is executed with a state file.
    """
    catalog = Catalog.from_dict(mock_catalog)

    mocker.patch(
        'tap_mailgun.singer.utils.parse_args',
        return_value=argparse.Namespace(
            config=mock_config, state=mock_state, catalog=catalog, discover=False,
        ),
    )
    mock_get_client = mocker.patch('tap_mailgun.get_client', autospec=True)
    mock_do_sync = mocker.patch('tap_mailgun.do_sync', autospec=True)

    tap_mailgun.main()

    mock_context.config.update.assert_called_once_with(mock_config)
    mock_context.state.update.assert_called_once_with(mock_state)
    mock_context.catalog.update.assert_called_once_with(catalog.to_dict())
    mock_get_client.assert_called_once()
    mock_do_sync.assert_called_once()
    mock_context.print_counts.assert_called_once()


def test_do_sync(mocker, mock_state, mock_context):
    """
    Ensure that the correct functions are called when tap is executed in sync mode.
    """
    streams = frozenset(['complaints', 'unsubscribes', 'events', 'messages'])

    mock_context.get_schema.return_value = 'schema'
    mock_context.is_selected.return_value = True
    mock_context.state = mock_state

    mock__get_streams_to_sync = mocker.patch(
        'tap_mailgun._get_streams_to_sync', return_value=streams, autospec=True
    )
    mock__validate_dependencies = mocker.patch(
        'tap_mailgun._validate_dependencies', autospec=True
    )

    mocker.patch('tap_mailgun.singer.write_schema', autospec=True)

    mock_sync_domains = mocker.patch('tap_mailgun.sync_domains', autospec=True)
    mock_sync_all_suppressions = mocker.patch(
        'tap_mailgun.sync_all_suppressions', autospec=True
    )
    mock_sync_events = mocker.patch('tap_mailgun.sync_events', autospec=True)
    mock_sync_messages = mocker.patch('tap_mailgun.sync_messages', autospec=True)

    mock_singer_write_state = mocker.patch(
        'tap_mailgun.singer.write_state', autospec=True
    )

    tap_mailgun.do_sync()

    mock__get_streams_to_sync.assert_called_once()
    mock__validate_dependencies.assert_called_once_with(streams)

    mock_sync_domains.assert_called_once()
    mock_sync_all_suppressions.assert_has_calls(
        [call('bounces'), call('complaints'), call('unsubscribes')], any_order=False
    )

    mock_sync_events.assert_called_once()
    mock_sync_messages.assert_called_once()

    mock_singer_write_state.assert_called_once_with(mock_state)
