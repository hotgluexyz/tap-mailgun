#!/usr/bin/env python3
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Dict, FrozenSet, Optional

import singer
from singer import metadata

from .client import MailgunClient, get_client
from .const import DEFAULT_BASE_URL, DEPENDENCIES, KEY_PROPERTIES, REQUIRED_CONFIG_KEYS

logger = singer.get_logger()


class DependencyException(Exception):
    pass


class Context:
    config: dict = {
        'base_url': DEFAULT_BASE_URL,
        'full_suppression_sync': False,
        'event_lookback': 1,
    }
    state: dict = {}
    catalog: dict = {}
    stream_map: dict = {}
    counts: dict = {}
    # The parameters below relate only to Mailgun, not Singer.
    # Domains are stored here when discovered during sync_domains, to be used in other sync functions.
    domains: dict = {}
    # The current domain_id that API responses relate to, stored here to easily add to records.
    current_domain_id: str = None
    # The current domain_name being used to make in API requests.
    current_domain_name: str = None
    # Messages are stored here until ready to be synced in batch, after sync_events.
    messages: set = set()
    # Client used to access the Mailgun API.
    mailgun_client: Optional[MailgunClient] = None

    @classmethod
    def get_catalog_entry(cls, stream_name):
        if not cls.stream_map:
            cls.stream_map = {s['tap_stream_id']: s for s in cls.catalog['streams']}
        return cls.stream_map.get(stream_name)

    @classmethod
    def get_schema(cls, stream_name):
        stream = [
            s for s in cls.catalog['streams'] if s['tap_stream_id'] == stream_name
        ][0]
        return stream['schema']

    @classmethod
    def is_selected(cls, stream_name):
        stream = cls.get_catalog_entry(stream_name)
        stream_metadata = metadata.to_map(stream['metadata'])
        return metadata.get(stream_metadata, (), 'selected')

    @classmethod
    def print_counts(cls):
        # Separate loops for formatting.
        for stream_name, stream_count in Context.counts.items():
            with singer.metrics.record_counter(stream_name) as counter:
                counter.increment(stream_count)

        logger.info('------------------')
        for stream_name, stream_count in Context.counts.items():
            logger.info(
                '%s: %d records replicated', stream_name, stream_count,
            )
        logger.info('------------------')


def _get_abs_path(path: str) -> Path:
    p = Path(__file__).parent / path
    return p.resolve()


def _get_start(key: str) -> dt.datetime:
    if key in Context.state:
        # Subtract look-back from Config (default 1 hour) from State, in case of late arriving events.
        # https://documentation.mailgun.com/en/latest/api-events.html#event-polling
        start = singer.utils.strptime_to_utc(Context.state[key]) - dt.timedelta(
            hours=Context.config['event_lookback']
        )
    else:
        start = singer.utils.strptime_to_utc(Context.config['start_date'])

    return start


def _get_streams_to_sync() -> FrozenSet[str]:
    return frozenset(
        stream['tap_stream_id']
        for stream in Context.catalog['streams']
        if Context.is_selected(stream['tap_stream_id'])
    )


def _populate_metadata(schema_name: str, schema: Dict):
    mdata = metadata.new()
    mdata = metadata.write(
        mdata, (), 'table-key-properties', KEY_PROPERTIES[schema_name]
    )
    mdata = metadata.write(mdata, (), 'selected', True)

    for field_name in schema['properties']:
        if field_name in KEY_PROPERTIES[schema_name]:
            mdata = metadata.write(
                mdata, ('properties', field_name), 'inclusion', 'automatic'
            )
        else:
            mdata = metadata.write(
                mdata, ('properties', field_name), 'inclusion', 'available'
            )
            # In interest of security, don't set 'smtp_password' to sync by default.
            if field_name != 'smtp_password':
                mdata = metadata.write(
                    mdata, ('properties', field_name), 'selected-by-default', True
                )

    return mdata


def _load_schema(stream: str):
    return singer.utils.load_json(_get_abs_path(f'schemas/{stream}.json'))


def _load_schemas():
    schemas = {}
    for filename in _get_abs_path('schemas').iterdir():
        stream = filename.stem
        schemas[stream] = _load_schema(stream)
    return schemas


def _transform_and_write_record(
    row: Dict, schema: str, stream: str, time_extracted: dt.datetime
):
    with singer.Transformer() as transformer:
        rec = transformer.transform(
            row,
            schema,
            metadata=metadata.to_map(Context.get_catalog_entry(stream)['metadata']),
        )
    singer.write_record(stream, rec, time_extracted=time_extracted)


def _validate_dependencies(selected_stream_ids: FrozenSet[str]) -> None:
    errs = []
    msg_tmpl = (
        'Unable to extract the {sub_stream} stream.\n'
        'To extract {sub_stream}, you need to select the {parent_stream} '
        'stream in the catalog, as the {sub_stream} stream depends on it.\n '
    )

    if 'domains' not in selected_stream_ids:
        errs.append(
            "domains stream is required for this tap to work.\n"
            "All other streams depend on the domains stream.\n"
            "Please set 'selected' to 'true' for the domains stream in the catalog file.\n"
        )

    # Sub streams are only dependent on parent stream if a full sync isn't selected.
    if not Context.config['full_suppression_sync']:
        for parent_stream in DEPENDENCIES:
            for sub_stream in DEPENDENCIES[parent_stream]:
                if (
                    sub_stream in selected_stream_ids
                    and parent_stream not in selected_stream_ids
                ):
                    errs.append(
                        msg_tmpl.format(
                            sub_stream=sub_stream, parent_stream=parent_stream
                        )
                    )

    if errs:
        raise DependencyException('\n'.join(errs))


def sync_domains() -> None:
    """
    Domains must be synced first as other streams depend on Context.domains,
    sync_domains populates this variable.
    """
    stream = 'domains'
    schema = Context.get_schema(stream)
    time_extracted = singer.utils.now()
    for domain in Context.mailgun_client.get_domains():
        # Domains will be needed in other syncs as other endpoints require the domain name
        Context.domains[domain['id']] = domain['name']
        domain['created_at'] = singer.utils.strptime_to_utc(
            domain['created_at']
        ).isoformat()
        _transform_and_write_record(domain, schema, stream, time_extracted)
        Context.counts[stream] += 1


def sync_single_suppression(stream: str, address: str) -> None:
    """
    Syncs a single suppression (bounce, unsubscribe, complaint).
    This function is only called during sync_events when a suppression is encountered.
    This function is only called if Context.config['full_suppression_sync'] is False.

    :param stream: The stream to populate (bounce, unsubscribe, complaint).
    :param address: The email address the suppression affected.
    """
    schema = Context.get_schema(stream)

    suppression = Context.mailgun_client.get_single_suppression(
        domain_name=Context.current_domain_name,
        suppression_type=stream,
        address=address,
    )

    if suppression:
        suppression['domain_id'] = Context.current_domain_id
        suppression['created_at'] = singer.utils.strptime_to_utc(
            suppression['created_at']
        ).isoformat()
        time_extracted = singer.utils.now()
        _transform_and_write_record(suppression, schema, stream, time_extracted)
        Context.counts[stream] += 1


def sync_all_suppressions(stream: str) -> None:
    """
    Syncs all suppressions in stream (bounce, unsubscribe, complaint)
    This function is only completed if Context.config['full_suppression_sync'] is True.
    Context.config['full_suppression_sync'] may be true if no State file was passed, or if set to true in config.
    """
    if not Context.config['full_suppression_sync']:
        logger.info(
            '{} stream will not be synced in full as full_suppression_sync is not enabled.'.format(
                stream
            )
        )
        return

    schema = Context.get_schema(stream)

    for domain_id in Context.domains:
        Context.current_domain_id = domain_id
        Context.current_domain_name = Context.domains[domain_id]
        time_extracted = singer.utils.now()
        for suppression in Context.mailgun_client.get_all_suppressions_of_type(
            domain_name=Context.current_domain_name, suppression_type=stream
        ):
            suppression['domain_id'] = domain_id
            suppression['created_at'] = singer.utils.strptime_to_utc(
                suppression['created_at']
            ).isoformat()
            _transform_and_write_record(suppression, schema, stream, time_extracted)
            Context.counts[stream] += 1


def sync_events() -> None:
    """
    Syncs events and suppressions encountered in event stream.
    Messages encountered are added to Context.messages to be synced in sync_messages().
    """
    stream = 'events'
    schema = Context.get_schema(stream)

    from_datetime = _get_start(stream)
    to_datetime = singer.utils.now()

    logger.info('Syncing events data from %s to %s', from_datetime, to_datetime)
    bookmark = from_datetime

    for domain_id in Context.domains:
        Context.current_domain_id = domain_id
        Context.current_domain_name = Context.domains[domain_id]

        for row in Context.mailgun_client.get_events(
            domain_name=Context.current_domain_name,
            begin=from_datetime.timestamp(),
            end=to_datetime.timestamp(),
        ):
            row['domain_id'] = domain_id

            row_timestamp = dt.datetime.fromtimestamp(
                int(row['timestamp']), dt.timezone.utc
            )
            row['timestamp'] = row_timestamp.isoformat()

            _transform_and_write_record(row, schema, stream, time_extracted=to_datetime)

            # Check if sub-streams should be synced
            if Context.is_selected('messages'):
                # As messages will appear multiple times in each sync, they are being added to a set to be
                # processed once per unique storage_url, to avoid repetitive calls to the messages endpoint.
                # Messages are only retained for 3 days (see README), so we check if it's worth querying the API
                # for the message.
                storage_url = row.get('storage', {}).get('url')
                time_since_event = singer.utils.now() - row_timestamp
                if storage_url and time_since_event.days <= 3:
                    Context.messages.add(row['storage']['url'])

            # Bounces
            if (
                Context.is_selected('bounces')
                and row['event'] == 'failed'
                and row['reason'] == 'bounce'
            ):
                sync_single_suppression("bounces", row['recipient'])
            # Unsubscribes
            if Context.is_selected('unsubscribes') and row['event'] == 'unsubscribed':
                sync_single_suppression("unsubscribes", row['recipient'])
            # Complaints
            if Context.is_selected('complaints') and row['event'] == 'complained':
                sync_single_suppression("complaints", row['recipient'])

            if row_timestamp > bookmark:
                bookmark = row_timestamp
            Context.counts[stream] += 1

    # Update state
    singer.utils.update_state(Context.state, stream, bookmark)


def sync_messages() -> None:
    """
    Syncs messages that have been added to the 'Context.messages' set during sync_events.
    We do this so that each message is only synced once, to cut down on API usage.
    """
    if Context.messages:
        stream = 'messages'
        schema = Context.get_schema(stream)
        time_extracted = singer.utils.now()
        for storage_url in Context.messages:
            message = Context.mailgun_client.get_message(storage_url=storage_url)
            message['storage_url'] = storage_url
            _transform_and_write_record(message, schema, stream, time_extracted)
            Context.counts[stream] += 1


def do_discover(*, stdout: bool = True) -> dict:
    """
    Generates a catalog and prints to stdout. By default, all streams and fields are enabled.
    """
    raw_schemas = _load_schemas()
    streams = []

    for schema_name, schema in raw_schemas.items():
        # Get metadata for each field
        mdata = _populate_metadata(schema_name, schema)

        # Create and add Catalog entry
        catalog_entry = {
            'stream': schema_name,
            'tap_stream_id': schema_name,
            'schema': schema,
            'metadata': metadata.to_list(mdata),
            'key_properties': KEY_PROPERTIES[schema_name],
        }
        streams.append(catalog_entry)

    catalog = {'streams': streams}

    if stdout:
        # Dump catalog to stdout
        sys.stdout.write(json.dumps(catalog))

    return catalog


def do_sync() -> None:
    """
    Syncs all streams selected in Context.catalog.
    Writes out state file for events stream once sync completed.
    """
    selected_stream_ids = _get_streams_to_sync()
    _validate_dependencies(selected_stream_ids)

    for stream in selected_stream_ids:
        singer.write_schema(stream, Context.get_schema(stream), KEY_PROPERTIES[stream])
        Context.counts[stream] = 0

    logger.info(
        'Starting sync. Will sync these streams: \n%s', '\n'.join(selected_stream_ids),
    )

    # Syncs must happen in a specific order.
    # All syncs depend on 'domains' stream.
    # 'events' should run after 'sync_all_suppression' to catch potential changes that happened during full sync.
    # 'messages' depends on completed 'events' stream.
    sync_domains()
    if Context.is_selected('bounces'):
        sync_all_suppressions('bounces')
    if Context.is_selected('complaints'):
        sync_all_suppressions('complaints')
    if Context.is_selected('unsubscribes'):
        sync_all_suppressions('unsubscribes')
    if Context.is_selected('events'):
        sync_events()
    if Context.is_selected('messages'):
        sync_messages()

    singer.write_state(Context.state)
    logger.info('Sync completed')


@singer.utils.handle_top_exception(logger)
def main() -> None:
    args = singer.utils.parse_args(REQUIRED_CONFIG_KEYS)
    Context.config.update(args.config)

    if args.state:
        Context.state.update(args.state)
    else:
        Context.config['full_suppression_sync'] = True

    if args.discover:
        do_discover()
    else:
        Context.catalog.update(
            args.catalog.to_dict() if args.catalog else do_discover(stdout=False)
        )

        Context.mailgun_client = get_client(
            base_url=Context.config['base_url'],
            private_key=Context.config['private_key'],
            headers={'User-Agent': Context.config['user_agent']}
            if 'user_agent' in Context.config
            else {},
        )

        do_sync()
        Context.print_counts()


if __name__ == '__main__':
    main()
