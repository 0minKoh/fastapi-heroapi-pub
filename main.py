from fastapi import FastAPI, HTTPException, Request, Header, Response, Form
from fastapi.responses import RedirectResponse
from typing import Optional, Dict, Any
from pydantic import BaseModel
import secrets
import uuid
import json
import base64
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# FastAPI 앱 초기화
app = FastAPI(title="Oauth 2.0 Supaja Hero API")

# 클라이언트 정보 
class OAuthConfig:
    CLIENT_ID = "example_client_id"
    CLIENT_SECRET = "example_client_secret"
    REDIRECT_URI = "http://127.0.0.1:8000/redoc"
    ENCRYPT_KEY = b"this_is_a_32_byte_key_for_aes256"
    ALLOWED_IP = ["127.0.0.1"]

# 임시 저장소 (실제 구현에서는 데이터베이스 사용)
auth_codes = {}  # {code: {client_id, redirect_uri, user_id, expires_at}}
access_tokens = {}  # {token: {user_id, expires_at}}
user_sessions = {}  # {session_id: user_id}

# 응답 모델
class TokenResponse(BaseModel):
    token_type: str
    access_token: str

class UserInfoResponse(BaseModel):
    ciphertext: str
    iv: str

# 암호화 함수 (AES-256-CBC)
def encrypt_data(data: Dict[str, Any], encrypt_key: bytes) -> Dict[str, str]:
    # 랜덤 IV 생성 (16바이트)
    iv = os.urandom(16)
    
    # JSON 데이터를 바이트로 변환
    data_bytes = json.dumps(data).encode('utf-8')
    
    # 패딩 추가 (16바이트 블록 크기에 맞춤)
    padding_length = 16 - (len(data_bytes) % 16)
    padded_data = data_bytes + (chr(padding_length) * padding_length).encode('utf-8')
    
    # AES-256-CBC 암호화
    cipher = Cipher(algorithms.AES(encrypt_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Base64 인코딩
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8')
    }

# 인가 코드 생성
def generate_auth_code() -> str:
    return secrets.token_urlsafe(32)

# 액세스 토큰 생성
def generate_access_token() -> str:
    return secrets.token_urlsafe(64)

# 클라이언트 검증
def verify_client(client_id: str, client_secret: Optional[str] = None) -> bool:
    """
    클라이언트 ID와 시크릿 유효성 검증
    
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    SELECT client_id, client_secret FROM oauth_clients 
    WHERE client_id = %s AND (client_secret IS NULL OR client_secret = %s)
    """
    if client_id != OAuthConfig.CLIENT_ID:
        return False
    
    if client_secret is not None and client_secret != OAuthConfig.CLIENT_SECRET:
        return False
    
    return True

# 리다이렉트 URI 검증
def verify_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    # SELECT uri FROM oauth_redirect_uris WHERE client_id = %s AND uri = %s
    """
    return redirect_uri == OAuthConfig.REDIRECT_URI

# 세션에서 사용자 ID 조회
def get_user_from_session(session_id: str) -> Optional[str]:
    """
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    # SELECT user_id FROM user_sessions 
    # WHERE session_id = %s AND expires_at > NOW()
    """
    return user_sessions.get(session_id)

# 액세스 토큰 유효성 검증
def validate_access_token(token: str) -> Optional[str]:
    """
    액세스 토큰 유효성 검증 및 사용자 ID 반환
    
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    SELECT user_id, expires_at FROM access_tokens WHERE token = %s
    """
    token_data = access_tokens.get(token)
    if not token_data:
        return None
    
    if datetime.now() > token_data["expires_at"]:
        # 만료된 토큰 삭제
        # 실제 구현에서는: DELETE FROM access_tokens WHERE token = %s
        del access_tokens[token]
        return None
        
    return token_data["user_id"]

# 사용자 정보 조회
def get_user_info(user_id: str) -> Optional[Dict[str, Any]]:
    """
    사용자 정보 조회
    
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    SELECT id, is_firefighter, name, phone_number, birth_date 
    FROM users WHERE id = %s
    """
    # Mock 데이터
    mock_users = {
        "user123": {
            "id": str(uuid.uuid4()),
            "is_firefighter": True,
            "name": "홍길동",
            "phone_number": "010-1234-5678",
            "birth_date": "1990-01-01"
        }
    }
    return mock_users.get(user_id)

@app.get("/api/oauth/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    state: str
):
    # 클라이언트 검증
    if not verify_client(client_id):
        error_uri = f"{redirect_uri}?error=invalid_request&error_description=Invalid+client_id&state={state}"
        return RedirectResponse(url=error_uri, status_code=302)
    
    # 리다이렉트 URI 검증
    if not verify_redirect_uri(client_id, redirect_uri):
        error_uri = f"{redirect_uri}?error=invalid_request&error_description=Invalid+redirect_uri&state={state}"
        return RedirectResponse(url=error_uri, status_code=302)
    
    # 로그인 페이지로 리다이렉트
    login_page_url = (
        f"https://external-login.example.com/login"
        f"?client_id={client_id}&redirect_uri={redirect_uri}&state={state}"
    )
    return RedirectResponse(url=login_page_url, status_code=302)


@app.post("/api/oauth/internal/authorize")
async def internal_authorize(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    state: str = Form(...),
    user_id: str = Form(...)  # 로그인 성공 후 전달된 사용자 ID
):
    # 클라이언트 검증
    if not verify_client(client_id):
        raise HTTPException(status_code=400, detail="Invalid client_id")
    
    # 리다이렉트 URI 검증
    if not verify_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")
    
    # 인가 코드 생성 및 저장
    auth_code = generate_auth_code()
    expires_at = datetime.now() + timedelta(minutes=10)  # 10분 유효

    """
    # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
    INSERT INTO auth_codes (auth_code, client_id, redirect_uri, user_id, expires_at)
    VALUES (%s, %s, %s, %s, %s);
    """
    auth_codes[auth_code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user_id": user_id,
        "expires_at": expires_at
    }
    
    # 성공적으로 인가 코드를 발급한 후 리다이렉트
    success_uri = f"{redirect_uri}?auth_code={auth_code}&state={state}"
    return RedirectResponse(url=success_uri, status_code=302)


@app.post("/api/oauth/token", response_model=TokenResponse)
async def get_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str = Form(...),
    auth_code: str = Form(...)
):
    try:
        # grant_type 검증
        if grant_type != "authorization_code":
            raise HTTPException(
                status_code=400,
                detail="지원하지 않는 grant_type입니다."
            )
        
        # 클라이언트 인증
        if not verify_client(client_id, client_secret):
            raise HTTPException(
                status_code=400,
                detail="클라이언트 인증에 실패했습니다."
            )
        
        # 인가 코드 조회
        """
        # 실제 구현에서는 아래와 같은 DB 쿼리로 대체해야 함
        SELECT client_id, redirect_uri, user_id, expires_at FROM auth_codes WHERE auth_code = %s;
        """
        code_data = auth_codes.get(auth_code)
        if not code_data:
            raise HTTPException(
                status_code=400,
                detail="유효하지 않은 인가 코드입니다."
            )
        
        # 인가 코드 만료 시간 검증
        if datetime.now() > code_data["expires_at"]:
            del auth_codes[auth_code]  # 만료된 인가 코드 삭제
            raise HTTPException(
                status_code=400,
                detail="인가 코드가 만료되었습니다."
            )
        
        # 클라이언트 및 리다이렉트 URI 검증
        if code_data["client_id"] != client_id or code_data["redirect_uri"] != redirect_uri:
            raise HTTPException(
                status_code=400,
                detail="클라이언트 정보가 일치하지 않습니다."
            )
        
        # 액세스 토큰 생성
        access_token = generate_access_token()
        user_id = code_data["user_id"]
        expires_at = datetime.now() + timedelta(minutes=10)  # 10분 유효
        
        # 액세스 토큰 저장
        access_tokens[access_token] = {
            "user_id": user_id,
            "expires_at": expires_at
        }
        
        # 인가 코드는 1회용이므로 사용 후 삭제
        del auth_codes[auth_code]
        
        # 성공 응답 반환
        return {
            "token_type": "Bearer",
            "access_token": access_token
        }
    except HTTPException as e:
        # 명시적으로 처리된 HTTPException 반환
        raise e
    except Exception as e:
        # 서버 내부 오류 처리
        print(f"Internal Server Error: {e}")
        raise HTTPException(
            status_code=500,
            detail="서버 내부 오류가 발생했습니다."
        )

@app.get("/api/oauth/user/info", response_model=UserInfoResponse)
async def get_user_info_endpoint(authorization: str = Header(..., alias="Authorization")):
    try:
        print("authorization", authorization)
        
        # Bearer 토큰 추출
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="유효하지 않은 인증 방식입니다."
            )
        
        token = authorization.replace("Bearer ", "")
        
        # 토큰 유효성 검증
        user_id = validate_access_token(token)
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="액세스 토큰이 유효하지 않거나 만료되었습니다."
            )
        
        # 사용자 정보 조회
        user_info = get_user_info(user_id)
        if not user_info:
            raise HTTPException(
                status_code=404,
                detail="사용자 정보를 찾을 수 없습니다."
            )
        
        # 사용자 정보 암호화
        encrypted_data = encrypt_data(user_info, OAuthConfig.ENCRYPT_KEY)

        # 필요하다면, 토큰을 만료 처리
        """
        실제 구현에서는 DB에서 액세스 토큰 만료 처리하거나
        # UPDATE access_tokens SET expires_at = NOW() WHERE token = %s
        ## ---
        # 실제 구현에서는 DB에서 액세스 토큰 삭제
        # DELETE FROM access_tokens WHERE token = %s
        """
        del access_tokens[token]
        
        return encrypted_data

    except HTTPException as e:
        # 명시적으로 처리된 HTTPException 반환
        raise e
    except Exception as e:
        # 서버 내부 오류 처리
        print(f"Internal Server Error: {e}")
        raise HTTPException(
            status_code=500,
            detail="서버 내부 오류가 발생했습니다."
        )
