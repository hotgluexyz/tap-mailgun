DEFAULT_BASE_URL = 'https://api.mailgun.net/v3/'
DEPENDENCIES = {
    # Parent stream: [Dependent streams]
    'events': ['bounces', 'unsubscribes', 'complaints', 'messages'],
    'domains': ['events', 'bounces', 'complaints', 'unsubscribes', 'messages'],
    'mailing_lists': ['members']
}
KEY_PROPERTIES = {
    'domains': ['id'],
    'events': ['id'],
    'messages': ['storage_url'],
    'mailing_lists': ['address'],
    'members': ['address'],
    'bounces': ['domain_id', 'address', 'created_at'],
    'complaints': ['domain_id', 'address', 'created_at'],
    'unsubscribes': ['domain_id', 'address', 'created_at'],
}
REQUIRED_CONFIG_KEYS = ['start_date', 'private_key']
