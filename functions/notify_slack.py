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

    return {
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
    }


def codepipeline_detail(message):
    """Uses Slack's Block Kit."""
    def get_emoji(state):
        states = {
            'CANCELLED': ':x:',
            'FAILED': ':exclamation:',
            'RESUMED': ':recycle:',
            'STARTED': ':information_source:',
            'SUCCEEDED': ':heavy_check_mark:',
            'SUPERSEDED': ':heavy_minus_sign:',
        }
        emoji = states.get(state)
        return f'{emoji} ' if emoji is not None else ''

    time = message['time']
    detail = message['detail']
    pipeline = detail['pipeline']
    execution_id = detail['execution-id']
    state = detail['state']

    return {
        {
            'type': 'section',
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': f'{get_emoji(state)}{state.capitalize()} pipeline "{pipeline}".',
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
    }


def default_notification(subject, message):
    return {
        'fallback': 'A new message',
        'fields': [{'title': subject if subject else 'Message', 'value': json.dumps(message), 'short': False}],
    }


# Send a message to a slack channel
def notify_slack(subject, message, region):
    slack_url = os.environ['SLACK_WEBHOOK_URL']
    if not slack_url.startswith('http'):
        slack_url = decrypt(slack_url)

    slack_channel = os.environ['SLACK_CHANNEL']
    slack_emoji = os.environ['SLACK_EMOJI']
    slack_username = os.environ['SLACK_USERNAME']

    payload = {
        'attachments': [],
        'blocks': [],
        'channel': slack_channel,
        'icon_emoji': slack_emoji,
        'username': slack_username,
    }
    if type(message) is str:
        try:
            message = json.loads(message)
        except json.JSONDecodeError as err:
            logging.exception(f'JSON decode error: {err}')
    if 'AlarmName' in message:
        notification = cloudwatch_notification(message, region)
        payload['attachments'].append(notification)
    elif 'source' in message and message['source'] == 'aws.codepipeline':
        if 'approval' in message:
            notification = codepipeline_approval(message)
            payload['blocks'].append(notification)
        if 'detail' in message:
            notification = codepipeline_detail(message)
            payload['blocks'].append(notification)
    else:
        payload['text'] = 'AWS notification'
        payload['attachments'].append(default_notification(subject, message))

    data = urllib.parse.urlencode({'payload': json.dumps(payload)}).encode('utf-8')
    req = urllib.request.Request(slack_url)
    urllib.request.urlopen(req, data)


def lambda_handler(event, context):
    subject = event['Records'][0]['Sns']['Subject']
    message = event['Records'][0]['Sns']['Message']
    region = event['Records'][0]['Sns']['TopicArn'].split(':')[3]
    notify_slack(subject, message, region)
    return message
