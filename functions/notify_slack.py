import base64
import json
import logging
import os
import urllib.parse
import urllib.request

import boto3


# Decrypt encrypted URL with KMS
def decrypt(encrypted_url):
    region = os.environ['AWS_REGION']
    try:
        kms = boto3.client('kms', region_name=region)
        plaintext = kms.decrypt(CiphertextBlob=base64.b64decode(encrypted_url))['Plaintext']
        return plaintext.decode()
    except Exception:
        logging.exception('Failed to decrypt URL with KMS')


def cloudwatch_notification(message, region):
    states = {
        'OK': ['good', ':white_check_mark:'],
        'INSUFFICIENT_DATA': ['warning', ':warning:'],
        'ALARM': ['danger', ':exclamation:'],
    }
    link = 'https://console.aws.amazon.com/cloudwatch/home?region={}#alarm:alarmFilter=ANY;name={}'.format(
        region, urllib.parse.quote_plus(message['AlarmName']),
    )

    return {
        'color': states[message['NewStateValue']][0],
        'fallback': '[{}] {} in {}'.format(message['NewStateValue'], message['AlarmName'], region),
        'fields': [
            {
                'value': '{} *[{}]* <{}|{}> in *{}*'.format(states[message['NewStateValue']][1],
                                                            message['NewStateValue'], link, message['AlarmName'],
                                                            region),
                'short': False,
            },
            {
                'title': 'Alarm reason', 'value': message['NewStateReason'],
                'short': False,
            },
        ],
    }


def codepipeline_approval(message):
    """Uses Slack's Block Kit."""
    console_link = message['consoleLink']
    approval = message['approval']
    pipeline_name = approval['pipelineName']
    action_name = approval['actionName']
    approval_review_link = approval['approvalReviewLink']
    expires = approval['expires']

    return (
        {
            'type': 'section',
            'text': {
                'type': 'plain_text',
                'text': f'Pipeline "{pipeline_name}" is waiting for approval.',
            },
            'accessory': {
                'type': 'button',
                'text': {
                    'type': 'plain_text',
                    'text': 'Open in :aws: Console',
                    'emoji': True,
                },
                'url': console_link,
            },
        },
        {
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f'*Action name*:\n{action_name}',
                },
                {
                    'type': 'mrkdwn',
                    'text': f'*Expires:* {expires}',
                },
            ],
        },
        {
            'type': 'actions',
            'elements': [
                {
                    'type': 'button',
                    'text': {
                        'type': 'plain_text',
                        'emoji': False,
                        'text': 'Review approve',
                    },
                    'style': 'primary',
                    'url': approval_review_link,
                },
            ],
        },
    )


def codepipeline_detail(message):
    """Uses Slack's Block Kit."""
    def get_emoji(state):
        states = {
            'CANCELLED': ('#9D9D9D', ':grey_exclamation:'),  # grey
            'FAILED': ('#D10C20', ':x:'),
            'RESUMED': ('#006234', ':recycle:'),  # dark green
            'STARTED': ('#0059C6', ':information_source:'),  # blue
            'SUCCEEDED': ('#41AA58', ':heavy_check_mark:'),
            'SUPERSEDED': ('#DAA038', ':heavy_minus_sign:'),
        }
        return states.get(state, ('#DAA038', ':grey_question:'))

    time = message['time']
    detail = message['detail']
    pipeline = detail['pipeline']
    execution_id = detail['execution-id']
    state = detail['state']
    color, emoji = get_emoji(state)

    return {
        'color': color,
        'blocks': (
            {
                'type': 'section',
                'text': {
                    'type': 'plain_text',
                    'emoji': True,
                    'text': f'{emoji} {state.capitalize()} pipeline "{pipeline}".',
                },
            },
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*State:*\n{state}',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Execution ID:*\n`{execution_id}`',
                    },
                ],
            },
            {
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*Timestamp:* {time}',
                    },
                ],
            },
        ),
    }


# Send a message to a slack channel
def handle_cloudwatch(event, payload):
    def _default_notification(subject, message):
        return {
            'fallback': 'A new message',
            'fields': [{'title': subject if subject else 'Message', 'value': json.dumps(message), 'short': False}],
        }

    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(':')[3]

    if 'AlarmName' in message:
        notification = cloudwatch_notification(message, region)
        payload['attachments'].append(notification)
    else:
        payload['text'] = 'AWS notification'
        payload['attachments'].append(_default_notification(subject, message))
    return payload


def handle_codepipeline(event, payload):
    if 'approval' in event:
        notification = codepipeline_approval(event)
        payload['blocks'] = notification
    if 'detail' in event:
        notification = codepipeline_detail(event)
        payload['attachments'].append(notification)
    return payload


def lambda_handler(event, context):
    slack_url = os.environ['SLACK_WEBHOOK_URL']
    if not slack_url.startswith('http'):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ['SLACK_CHANNEL']
    slack_emoji = os.environ['SLACK_EMOJI']
    slack_username = os.environ['SLACK_USERNAME']
    service = os.environ['SERVICE']

    payload = {
        'attachments': [],
        'blocks': [],
        'channel': slack_channel,
        'icon_emoji': slack_emoji,
        'username': slack_username,
    }

    if type(event) is str:
        try:
            event = json.loads(event)
        except json.JSONDecodeError as ex:
            logging.exception(f'JSON decode error: {ex}')

    if service == 'codepipeline':
        payload = handle_codepipeline(event, payload)
    else:
        payload = handle_cloudwatch(event, payload)

    data = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode('utf-8')
    req = urllib.request.Request(slack_url)
    urllib.request.urlopen(req, data)  # TODO: Error handling

    return event
