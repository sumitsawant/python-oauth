import json
import secrets
import time
import logging
from typing import List
from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
import httpx
import asyncio

from integrations.integration_item import IntegrationItem
from redis_client import add_key_value_redis, get_value_redis, delete_key_redis

# ========== Configuration Constants ==========

CLIENT_ID = '6c589afb-5fe9-4aee-85ae-dbba0e06f98d'
CLIENT_SECRET = 'c5737250-5666-45ce-a5f5-1ad0ac7fcd31'
REDIRECT_URI = 'http://localhost:8000/integrations/hubspot/oauth2callback'
AUTHORIZATION_BASE_URL = 'https://app.hubspot.com/oauth/authorize'
TOKEN_URL = 'https://api.hubapi.com/oauth/v1/token'
CONTACTS_API_URL = 'https://api.hubapi.com/crm/v3/objects/contacts'

SCOPES = ['crm.objects.contacts.read']
AUTHORIZATION_URL = (
    f'{AUTHORIZATION_BASE_URL}?client_id={CLIENT_ID}'
    f'&redirect_uri={REDIRECT_URI}'
    f'&scope={"%20".join(SCOPES)}'
)

STATE_TTL = 600
CREDENTIAL_TTL = 600

# ========== Logging Setup ==========

logger = logging.getLogger("hubspot_integration")
logger.setLevel(logging.INFO)

# ========== Prometheus Metrics (Optional) ==========
# from prometheus_client import Counter
# HUBSPOT_API_CALLS = Counter('hubspot_api_calls', 'Total API Calls to HubSpot', ['endpoint'])
# HUBSPOT_TOKEN_REFRESHES = Counter('hubspot_token_refreshes', 'Total token refreshes')


# ========== OAuth Authorization ==========

async def authorize_hubspot(user_id: str, org_id: str) -> str:
    logger.info(f"Starting HubSpot auth flow for org_id={org_id}, user_id={user_id}")

    state_payload = {
        'state': secrets.token_urlsafe(32),
        'user_id': user_id,
        'org_id': org_id
    }
    encoded_state = json.dumps(state_payload)
    redis_key = f'hubspot_state:{org_id}:{user_id}'
    await add_key_value_redis(redis_key, encoded_state, expire=STATE_TTL)

    return f'{AUTHORIZATION_URL}&state={encoded_state}'


async def oauth2callback_hubspot(request: Request) -> HTMLResponse:
    if error := request.query_params.get('error'):
        raise HTTPException(status_code=400, detail=error)

    code = request.query_params.get('code')
    encoded_state = request.query_params.get('state')

    if not code or not encoded_state:
        raise HTTPException(status_code=400, detail='Missing code or state.')

    state_data = json.loads(encoded_state)
    user_id = state_data.get('user_id')
    org_id = state_data.get('org_id')
    received_state = state_data.get('state')
    redis_key = f'hubspot_state:{org_id}:{user_id}'

    logger.info(f"OAuth2 callback received for org_id={org_id}, user_id={user_id}")

    stored_state_raw = await get_value_redis(redis_key)
    if not stored_state_raw:
        raise HTTPException(status_code=400, detail='OAuth state expired or missing.')

    stored_state = json.loads(stored_state_raw)
    if received_state != stored_state.get('state'):
        raise HTTPException(status_code=400, detail='State mismatch detected.')

    async with httpx.AsyncClient() as client:
        token_response, _ = await asyncio.gather(
            client.post(
                TOKEN_URL,
                data={
                    'grant_type': 'authorization_code',
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'redirect_uri': REDIRECT_URI,
                    'code': code
                },
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ),
            delete_key_redis(redis_key)
        )

    if token_response.status_code != 200:
        raise HTTPException(status_code=token_response.status_code, detail=token_response.text)

    credentials = token_response.json()
    credentials['issued_at'] = int(time.time())

    await add_key_value_redis(
        f'hubspot_credentials:{org_id}:{user_id}',
        json.dumps(credentials),
        expire=CREDENTIAL_TTL
    )

    logger.info(f"Token stored successfully for org_id={org_id}, user_id={user_id}")

    return HTMLResponse(content="<html><script>window.close();</script></html>")


# ========== Token Management ==========

async def refresh_hubspot_token(refresh_token: str) -> dict:
    logger.info("Refreshing HubSpot token")
    # HUBSPOT_TOKEN_REFRESHES.inc()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_URL,
            data={
                'grant_type': 'refresh_token',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET,
                'refresh_token': refresh_token
            },
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail='Token refresh failed.')

    refreshed = response.json()
    refreshed['issued_at'] = int(time.time())
    return refreshed


async def get_hubspot_credentials(user_id: str, org_id: str) -> dict:
    redis_key = f'hubspot_credentials:{org_id}:{user_id}'
    credentials_raw = await get_value_redis(redis_key)

    if not credentials_raw:
        raise HTTPException(status_code=400, detail='No credentials found or expired.')

    credentials = json.loads(credentials_raw)

    if 'expires_in' in credentials and 'issued_at' in credentials:
        now = int(time.time())
        if now > credentials['issued_at'] + credentials['expires_in'] - 300:
            logger.info(f"Token about to expire. Refreshing for org_id={org_id}, user_id={user_id}")
            refreshed = await refresh_hubspot_token(credentials['refresh_token'])
            await add_key_value_redis(redis_key, json.dumps(refreshed), expire=CREDENTIAL_TTL)
            return refreshed

    return credentials


# ========== Fetching HubSpot Contact Items ==========

async def get_items_hubspot(credentials: dict) -> List[IntegrationItem]:
    # Convert credentials from JSON string to dict if necessary
    if isinstance(credentials, str):
        credentials = json.loads(credentials)
        
    headers = {
        'Authorization': f'Bearer {credentials["access_token"]}',
        'Content-Type': 'application/json'
    }

    logger.info("Fetching HubSpot contact items")
    # HUBSPOT_API_CALLS.labels(endpoint='contacts').inc()

    async with httpx.AsyncClient() as client:
        response = await client.get(CONTACTS_API_URL, headers=headers, params={'limit': 10})

    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail=response.text)

    contacts = response.json().get('results', [])
    integration_items = await asyncio.gather(*[
        create_integration_item_metadata_object(contact) for contact in contacts
    ])
    return integration_items

# ========== Metadata Fetching ==========

async def create_integration_item_metadata_object(contact_data: dict) -> IntegrationItem:
    properties = contact_data.get('properties', {})
    first_name = properties.get('firstname', '').strip()
    last_name = properties.get('lastname', '').strip()
    full_name = f"{first_name} {last_name}".strip() or "Unnamed Contact"

    return IntegrationItem(
        id=contact_data['id'],
        type='contact',
        name=full_name,
        creation_time=contact_data.get('createdAt'),
        last_modified_time=contact_data.get('updatedAt'),
        parent_id=None
    )
