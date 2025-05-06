import requests
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class OAuthConfig:
    CLIENT_ID = "example_client_id"
    CLIENT_SECRET = "example_client_secret"
    REDIRECT_URI = "http://127.0.0.1:8000/redoc" # Example REDIRECT_URI
    ENCRYPT_KEY = b"this_is_a_32_byte_key_for_aes256"
    ALLOWED_IP = ["127.0.0.1"]

def get_auth_code():
    """
    /api/oauth/authorize 엔드포인트를 호출하여 인가 코드를 얻는 함수
    """
    # API URL
    url = "http://127.0.0.1:8000/api/oauth/authorize"

    # 요청 파라미터
    params = {
        "client_id": OAuthConfig.CLIENT_ID,
        "redirect_uri": OAuthConfig.REDIRECT_URI,
        "state": "test_state"  # CSRF 방지를 위한 상태 값
    }

    # API 호출
    response = requests.get(url, params=params)

    # 응답 처리
    if response.status_code == 302:  # 리다이렉트 응답
        redirect_url = response.headers.get("Location")
        print("Redirect URL:", redirect_url)

        # 인가 코드 추출
        if "auth_code=" in redirect_url:
            auth_code = redirect_url.split("auth_code=")[1].split("&")[0]
            print("Authorization Code:", auth_code)
            return auth_code
        else:
            print("Authorization Code not found in redirect URL.")
            return None
    else:
        if response.status_code == 200 and "auth_code=" in response.url:
            # URL 파라미터 중 auth_code를 추출
            auth_code = response.url.split("auth_code=")[1].split("&")[0]
            print("Authorization Code:", auth_code)
            return auth_code
        else:
          print("Error:", response.status_code, response.text)
          return None
    
def get_access_token(auth_code_param: str):
    """
    /api/oauth/token 엔드포인트를 호출하여 Access Token을 발급받는 함수

    Args:
        auth_code (str): 인가 코드 (Authorization Code)

    Returns:
        dict: 성공 시 Access Token 정보
        tuple: 실패 시 상태 코드와 오류 메시지
    """
    # API URL
    url = "http://127.0.0.1:8000/api/oauth/token"

    # 요청 데이터 (application/x-www-form-urlencoded 형식)
    data = {
        "grant_type": "authorization_code",  # 고정 값
        "client_id": OAuthConfig.CLIENT_ID,  # OAuthConfig.CLIENT_ID와 동일해야 함
        "client_secret": OAuthConfig.CLIENT_SECRET,  # OAuthConfig.CLIENT_SECRET와 동일해야 함
        "redirect_uri": OAuthConfig.REDIRECT_URI,  # OAuthConfig.REDIRECT_URI와 동일해야 함
        "auth_code": auth_code_param  # 인가 코드
    }

    # API 호출
    response = requests.post(url, data=data)

    # 응답 처리
    if response.status_code == 200:
        print("Access Token Response:", response.json())
        return response.json()
    else:
        print("Error:", response.status_code, response.text)
        return response.status_code, response.text
  

def get_user_info(access_token: str, token_type: str):
    # API URL
    url = "http://127.0.0.1:8000/api/oauth/user/info"

    # 헤더 설정
    headers = {
        "Authorization": f"{token_type} {access_token}",  # Bearer {access_token} 형식
    }

    # API 호출
    response = requests.get(url, headers=headers)

    # 응답 출력
    if response.status_code == 200:
        print("Success:", response.json())
        return response.json()
    else:
        print("Error:", response.status_code, response.text)
        return response.status_code, response.text

def decrypt_data(ciphertext: str, iv: str) -> dict:
    """
    AES-256-CBC로 암호화된 데이터를 복호화하는 함수

    Args:
        ciphertext (str): Base64로 인코딩된 암호화된 텍스트
        iv (str): Base64로 인코딩된 초기화 벡터
        decrypt_key (bytes): 복호화 키 (32바이트)

    Returns:
        dict: 복호화된 JSON 데이터
    """
    # Base64 디코딩
    ciphertext_bytes = base64.b64decode(ciphertext)
    iv_bytes = base64.b64decode(iv)

    # AES-256-CBC 복호화
    cipher = Cipher(algorithms.AES(OAuthConfig.ENCRYPT_KEY), modes.CBC(iv_bytes))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    # 패딩 제거
    padding_length = padded_data[-1]
    data_bytes = padded_data[:-padding_length]

    # JSON 디코딩
    return json.loads(data_bytes.decode('utf-8'))


if __name__ == "__main__":
    # 인가 코드 얻기
    auth_code_res = get_auth_code()
    if auth_code_res is None:
        print("Failed to get authorization code.")
        exit(1)

    # 인가 코드가 유효한 경우 Access Token 발급
    access_token_json = get_access_token(auth_code_res)

    # json 응답에서, token_type, access_token 값을 추출
    token_type = access_token_json.get("token_type")
    access_token = access_token_json.get("access_token")

    # Access Token이 유효한 경우 사용자 정보 조회
    if token_type and access_token:
        print("Access Token:", access_token)
        encrypted_user_info = get_user_info(access_token, token_type)
        # 암호화된 사용자 정보에서 iv와 ciphertext 추출
        iv = encrypted_user_info.get("iv")
        ciphertext = encrypted_user_info.get("ciphertext")
        # 복호화된 사용자 정보 출력
        decrypted_user_info = decrypt_data(ciphertext, iv)
        print("Decrypted User Info:", decrypted_user_info)