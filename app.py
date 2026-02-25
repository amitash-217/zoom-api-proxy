import datetime
import hashlib
import os

from fastapi import FastAPI, HTTPException, Header, Request
import hmac

import httpx
import jwt

APP_SECRET = os.getenv('APP_SECRET', '')
JWT_SECRET = os.getenv('JWT_SECRET', '')
N8N_URL = os.getenv('N8N_WEBHOOK_URL', '')
app = FastAPI()

@app.post('/zm_hook')
async def process_webhook(request: Request, x_zm_signature: str = Header(None), x_zm_request_timestamp: str = Header(None)):
    # v0:${req.headers['x-zm-request-timestamp']}:${JSON.stringify(req.body)}
    if not x_zm_signature or not x_zm_request_timestamp:
        raise HTTPException(status_code=401, detail="Missing signature header")
    
    body_bytes = await request.body()
    body = body_bytes.decode('utf-8')
    payload = 'v0:' + x_zm_request_timestamp + ":" + body
    
    expected_hash = hmac.new(
        key=APP_SECRET.encode(), 
        msg=payload.encode('utf-8'), 
        digestmod=hashlib.sha256
    ).hexdigest()

    expected_hash_v0 = "v0=" + expected_hash

    if not hmac.compare_digest(expected_hash_v0, x_zm_signature):
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    #redirect to n8n
    jwt_payload = {
        "iat": datetime.datetime.now(),
        # Set expiration time (e.g., 1 hour from now)
        "exp": datetime.datetime.now() + datetime.timedelta(hours=1)
    }
    encoded_jwt = jwt.encode(jwt_payload, JWT_SECRET, algorithm="HS256")

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {encoded_jwt}"
    }

    async with httpx.AsyncClient() as client:
        try:
            await client.post(N8N_URL, content=body_bytes, headers=headers, timeout=10.0)
            print(f"Background: Forwarded to {N8N_URL}")
        except Exception as e:
            print(f"Background: Failed to forward. Error: {e}")
    
@app.get('/oauth2redirect')
def process_redirect(code: str):
    print(code)