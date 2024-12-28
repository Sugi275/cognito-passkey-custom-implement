import boto3
import json
import base64
import hmac
import hashlib
from flask import Flask, request, redirect, make_response, jsonify
from datetime import datetime
import random
import string


app = Flask(__name__)

COGNITO_DOMAIN = "https://auth.cognito-nginx01.sugiaws.tokyo"
COGNITO_USERPOOL_ID = "Masked"
CLIENT_ID = "Masked"
CLIENT_SECRET = "Masked"
LOGOUT_URI = "https://cognito-nginx01.sugiaws.tokyo"

def decode_jwt(token):
    # JWTのペイロード部分（2番目の部分）を取得
    payload = token.split('.')[1]
    # Base64デコード（パディングの調整が必要な場合がある）
    payload += '=' * ((4 - len(payload) % 4) % 4)
    decoded = base64.b64decode(payload)
    # JSONとしてパース
    return json.loads(decoded)

def get_secret_hash(username):
    # ユーザー名、クライアントID、クライアントシークレットを使用してハッシュを生成
    message = username + CLIENT_ID
    dig = hmac.new(
        key=CLIENT_SECRET.encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()

@app.route('/managedlogin')
def managed_login():
    headers = dict(request.headers)
    headers.pop('X-Forwarded-For', None)
    
    formatted_headers = '\n'.join([f"{key}: {value}" for key, value in headers.items()])
    
    # JWTからメールアドレスを抽出
    jwt_data = headers.get('X-Amzn-Oidc-Data')
    email = "Not found"
    if jwt_data:
        try:
            decoded = decode_jwt(jwt_data)
            email = decoded.get('email', 'Email not found in JWT')
        except Exception as e:
            email = f"Error decoding JWT: {str(e)}"

    return f"""
        <h1>Request Headers</h1>
        <pre>{formatted_headers}</pre>
        <h2>Email from JWT</h2>
        <p>{email}</p>
        <p><a href="/">Back to Home</a></p>
        <p><a href="/logout">Logout</a></p>
    """

@app.route('/customlogin')
def custom_login():
    return """
        <h1>カスタムログイン</h1>
        <div style="margin: 20px 0;">
            <p><a href="/customlogin-signup">アカウント登録</a></p>
            <p><a href="/customlogin-passwordlogin">パスワードでログイン</a></p>
            <p><a href="/customlogin-addpasskey">パスキー登録</a></p>
            <p><a href="/customlogin-passkeylogin">パスキーでログイン</a></p>
            <p><a href="/customlogin-mypage">マイページ</a></p>
            <p><a href="/logout">ログアウト</a></p>
        </div>
        <p><a href="/">Back to Home</a></p>
    """

@app.route('/customlogin-signup', methods=['GET', 'POST'])
def custom_signup():
    if request.method == 'POST':
        try:
            # Cognitoクライアントの初期化
            cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
            
            # フォームからメールアドレスのみ取得
            email = request.form.get('email')

            # Admin APIでユーザー登録（一時パスワードは自動生成）
            lowercase = ''.join(random.choices(string.ascii_lowercase, k=3))  # 小文字を3文字
            uppercase = ''.join(random.choices(string.ascii_uppercase, k=3))  # 大文字を3文字
            digits = ''.join(random.choices(string.digits, k=3))             # 数字を3文字
            special = ''.join(random.choices('!@#$%^&*', k=1))              # 特殊文字を1文字

            # すべての文字を結合してシャッフル
            temp_password = list(lowercase + uppercase + digits + special)
            random.shuffle(temp_password)
            temp_password = ''.join(temp_password)

            print(f"Generated temporary password: {temp_password}")  # デバッグ用出力

            response = cognito_client.admin_create_user(
                UserPoolId=COGNITO_USERPOOL_ID,
                Username=email,
                TemporaryPassword=temp_password,
                UserAttributes=[
                    {
                        'Name': 'email',
                        'Value': email
                    },
                    {
                        'Name': 'email_verified',
                        'Value': 'true'
                    }
                ]
            )
            
            return """
                <h1>登録完了</h1>
                <p>アカウントが作成されました。登録したメールアドレスに一時パスワードが送信されます。</p>
                <p><a href="/customlogin-passwordlogin">ログインページへ</a></p>
            """
            
        except cognito_client.exceptions.UsernameExistsException:
            return """
                <h1>エラー</h1>
                <p>このメールアドレスは既に登録されています。</p>
                <p><a href="/customlogin-signup">戻る</a></p>
            """
        except Exception as e:
            return f"""
                <h1>エラー</h1>
                <p>登録中にエラーが発生しました: {str(e)}</p>
                <p><a href="/customlogin-signup">戻る</a></p>
            """
    
    # GETリクエストの場合は登録フォーム表示（パスワード入力欄を削除）
    return """
        <h1>アカウント登録</h1>
        <form method="POST">
            <div>
                <label for="email">メールアドレス:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <div>
                <button type="submit">登録</button>
            </div>
        </form>
        <p><a href="/customlogin">戻る</a></p>
    """

@app.route('/customlogin-passwordlogin', methods=['GET', 'POST'])
def custom_password_login():
    if request.method == 'GET':
        return """
            <h1>パスワードログイン</h1>
            <form method="POST" action="/customlogin-auth">
                <div>
                    <label for="email">メールアドレス:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div>
                    <label for="password">パスワード:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div>
                    <button type="submit">ログイン</button>
                </div>
            </form>
            <p><a href="/customlogin">戻る</a></p>
        """
    else:
        # POSTメソッドの場合は既存の custom_login_auth の処理を行う
        return custom_login_auth()

@app.route('/customlogin-auth', methods=['POST'])
def custom_login_auth():
    try:
        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
        
        email = request.form.get('email')
        password = request.form.get('password')
        new_password = request.form.get('new_password')

        try:
            # 通常のログイン試行
            auth_response = cognito_client.admin_initiate_auth(
                UserPoolId=COGNITO_USERPOOL_ID,
                ClientId=CLIENT_ID,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': email,
                    'PASSWORD': password,
                    'SECRET_HASH': get_secret_hash(email)
                }
            )
            
            print("=== Debug: auth_response ===")
            print(json.dumps(auth_response, indent=2, default=str))
            print("===========================")

            # NEW_PASSWORD_REQUIRED チャレンジの場合
            if auth_response.get('ChallengeName') == 'NEW_PASSWORD_REQUIRED':
                return f"""
                    <h1>新しいパスワードの設定</h1>
                    <p>初回ログインのため、新しいパスワードを設定してください。</p>
                    <form method="POST" action="/customlogin-newpassword">
                        <input type="hidden" name="email" value="{email}">
                        <input type="hidden" name="password" value="{password}">
                        <input type="hidden" name="session" value="{auth_response['Session']}">
                        <div>
                            <label for="new_password">新しいパスワード:</label>
                            <input type="password" id="new_password" name="new_password" required>
                        </div>
                        <div>
                            <button type="submit">パスワードを設定</button>
                        </div>
                    </form>
                    <p><a href="/customlogin">戻る</a></p>
                """
            
            # 通常のログイン成功の場合
            response = make_response("""
                <h1>ログイン成功</h1>
                <p><a href="/customlogin">ホームに戻る</a></p>
            """)

            auth_result = auth_response.get('AuthenticationResult', {})
            if auth_result:
                response.set_cookie(
                    'id_token',
                    auth_result.get('IdToken', ''),
                    httponly=True,
                    secure=True,
                    samesite='Lax'
                )
                
                response.set_cookie(
                    'access_token',
                    auth_result.get('AccessToken', ''),
                    httponly=True,
                    secure=True,
                    samesite='Lax'
                )

            return response

        except cognito_client.exceptions.NotAuthorizedException as e:
            return f"""
                <h1>エラー</h1>
                <p>ログイン処理中にエラーが発生しました: {str(e)}</p>
                <p><a href="/customlogin">戻る</a></p>
            """

    except Exception as e:
        return f"""
            <h1>エラー</h1>
            <p>ログイン処理中にエラーが発生しました: {str(e)}</p>
            <p><a href="/customlogin">戻る</a></p>
        """

@app.route('/customlogin-newpassword', methods=['POST'])
def custom_login_newpassword():
    try:
        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
        
        email = request.form.get('email')
        password = request.form.get('password')
        new_password = request.form.get('new_password')

        # 認証を開始して Session を取得
        auth_response = cognito_client.admin_initiate_auth(
            UserPoolId=COGNITO_USERPOOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(email)
            }
        )

        # 新しいパスワードでチャレンジレスポンス
        auth_response = cognito_client.admin_respond_to_auth_challenge(
            UserPoolId=COGNITO_USERPOOL_ID,
            ClientId=CLIENT_ID,
            ChallengeName='NEW_PASSWORD_REQUIRED',
            ChallengeResponses={
                'USERNAME': email,
                'NEW_PASSWORD': new_password,
                'SECRET_HASH': get_secret_hash(email)
            },
            Session=auth_response['Session']
        )

        response = make_response("""
            <h1>パスワード更新完了</h1>
            <p>新しいパスワードが設定されました。</p>
            <p><a href="/customlogin">ログインページに戻る</a></p>
        """)

        auth_result = auth_response.get('AuthenticationResult', {})
        if auth_result:
            response.set_cookie(
                'id_token',
                auth_result.get('IdToken', ''),
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            
            response.set_cookie(
                'access_token',
                auth_result.get('AccessToken', ''),
                httponly=True,
                secure=True,
                samesite='Lax'
            )
        
        return response

    except Exception as e:
        return f"""
            <h1>エラー</h1>
            <p>パスワードの更新中にエラーが発生しました: {str(e)}</p>
            <p><a href="/customlogin">戻る</a></p>
        """

@app.route('/customlogin-addpasskey')
def custom_login_addpasskey():
    return """
        <h1>パスキー登録</h1>
        <script>
            async function registerPasskey() {
                try {
                    // サーバーから challenge を取得
                    const response = await fetch('/customlogin-addpasskey/start', {
                        method: 'POST'
                    });
                    
                    if (!response.ok) {
                        throw new Error('認証エラー - ログインが必要かもしれません');
                    }

                    const data = await response.json();
                    
                    // credentialCreationOptions を準備
                    const options = {
                        publicKey: {
                            ...data.publicKey,
                            challenge: base64URLToBuffer(data.publicKey.challenge),
                            user: {
                                ...data.publicKey.user,
                                id: base64URLToBuffer(data.publicKey.user.id)
                            },
                            
                            excludeCredentials: data.publicKey.excludeCredentials ? 
                                data.publicKey.excludeCredentials.map(cred => ({
                                    ...cred,
                                    id: base64URLToBuffer(cred.id)
                                })) : []
                        }
                    };

                    // パスキーを作成
                    const credential = await navigator.credentials.create(options);

                    // WebAuthn の RegistrationResponseJSON 形式に準拠した形に変換
                    const attestationResponse = {
                        id: credential.id,
                        rawId: bufferToBase64URL(credential.rawId),
                        response: {
                            clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                            authenticatorData: bufferToBase64URL(credential.response.getAuthenticatorData()),
                            transports: credential.response.getTransports(),
                            publicKey: bufferToBase64URL(credential.response.getPublicKey()),
                            publicKeyAlgorithm: credential.response.getPublicKeyAlgorithm(),
                            attestationObject: bufferToBase64URL(credential.response.attestationObject)
                        },
                        authenticatorAttachment: credential.authenticatorAttachment || "",
                        clientExtensionResults: credential.getClientExtensionResults() || {},
                        type: credential.type
                    };

                    // Cognitoに送信
                    const finishResponse = await fetch('/customlogin-addpasskey/finish', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(attestationResponse)
                    });

                    if (finishResponse.ok) {
                        alert('パスキーの登録が完了しました');
                        window.location.href = '/customlogin';
                    } else {
                        throw new Error('パスキーの登録に失敗しました');
                    }

                } catch (err) {
                    console.error('Error:', err);
                    alert(err.message);
                }
            }

            // Base64 URL を ArrayBuffer に変換
            function base64URLToBuffer(base64URL) {
                const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
                const padding = '='.repeat((4 - base64.length % 4) % 4);
                const binary = atob(base64 + padding);
                const buffer = new ArrayBuffer(binary.length);
                const view = new Uint8Array(buffer);
                for (let i = 0; i < binary.length; i++) {
                    view[i] = binary.charCodeAt(i);
                }
                return buffer;
            }

            // ArrayBuffer を Base64 URL に変換
            function bufferToBase64URL(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                const base64 = btoa(binary);
                return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            }
        </script>
        <div>
            <button onclick="registerPasskey()">パスキーを登録</button>
        </div>
        <p><a href="/customlogin">戻る</a></p>
    """

@app.route('/customlogin-addpasskey/start', methods=['POST'])
def custom_login_addpasskey_start():
    try:
        # クライアントの初期化
        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
        
        # アクセストークンはリクエストのCookieから取得
        access_token = request.cookies.get('access_token')
        if not access_token:
            return jsonify({'error': 'アクセストークンが必要です'}), 401

        # Cognitoのstart-web-authn-registrationを呼び出し
        response = cognito_client.start_web_authn_registration(
            AccessToken=access_token
        )

        # Cognitoのレスポンスをそのままクライアントに返す
        return jsonify({
            'publicKey': response['CredentialCreationOptions']
        })

    except cognito_client.exceptions.NotAuthorizedException:
        print(f"Error in start registration: {str(e)}")  # デバッグ用
        return jsonify({'error': '認証エラー'}), 401
    except Exception as e:
        print(f"Error in start registration: {str(e)}")  # デバッグ用
        return jsonify({'error': str(e)}), 400

@app.route('/customlogin-addpasskey/finish', methods=['POST'])
def custom_login_addpasskey_finish():
    try:
        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
        
        access_token = request.cookies.get('access_token')
        if not access_token:
            return jsonify({'error': 'アクセストークンが必要です'}), 401

        # クライアントから送られてきた RegistrationResponseJSON を取得
        credential = request.get_json()

        # デバッグ出力
        print("=== Debug: credential ===")
        print(json.dumps(credential, indent=2))
        print("========================")
        
        # Cognitoにクレデンシャルを送信
        response = cognito_client.complete_web_authn_registration(
            AccessToken=access_token,
            Credential=credential  # RegistrationResponseJSON をそのまま渡す
        )

        return jsonify({'success': True})

    except cognito_client.exceptions.NotAuthorizedException:
        print(f"Error in finish registration: {str(e)}")
        return jsonify({'error': '認証エラー'}), 401
    except Exception as e:
        print(f"Error in finish registration: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/customlogin-passkeylogin')
def custom_passkey_login():
    return """
        <h1>パスキーログイン</h1>
        <div>
            <label for="email">メールアドレス:</label>
            <input type="email" id="email" required>
            <button onclick="handlePasskeyAuth()">パスキーでログイン</button>
        </div>
        <p><a href="/customlogin">戻る</a></p>

        <script>
            async function handlePasskeyAuth() {
                try {
                    const email = document.getElementById('email').value;
                    
                    // Step 1: 認証を開始 (直接WEB_AUTHNを指定)
                    const initiateAuthResponse = await fetch('/customlogin-passkeylogin/initiate', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ username: email })
                    });
                    const response = await initiateAuthResponse.json();

                    console.log("=== Debug: initiateAuthResponse ===");
                    console.log(JSON.stringify(response, null, 2));
                    console.log("================================================");

                    // Step 2: パスキーで認証
                    response.publicKey.challenge = base64URLToBuffer(response.publicKey.challenge);
                    response.publicKey.allowCredentials = response.publicKey.allowCredentials.map(cred => ({
                        ...cred,
                        id: base64URLToBuffer(cred.id)
                    }));

                    const credential = await navigator.credentials.get({
                        publicKey: response.publicKey
                    });

                    // Step 3: 認証レスポンスを送信
                    const authenticatorResponse = {
                        id: credential.id,
                        rawId: bufferToBase64URL(credential.rawId),
                        response: {
                            clientDataJSON: bufferToBase64URL(credential.response.clientDataJSON),
                            authenticatorData: bufferToBase64URL(credential.response.authenticatorData),
                            signature: bufferToBase64URL(credential.response.signature),
                            userHandle: credential.response.userHandle ? bufferToBase64URL(credential.response.userHandle) : null
                        },
                        authenticatorAttachment: credential.authenticatorAttachment || null,
                        clientExtensionResults: credential.getClientExtensionResults() || {},
                        type: credential.type
                    };

                    const finalResponse = await fetch('/customlogin-passkeylogin/complete', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            username: email,
                            session: response.session,
                            credential: authenticatorResponse
                        })
                    });

                    if (finalResponse.ok) {
                        window.location.href = '/customlogin';
                    } else {
                        throw new Error('認証に失敗しました');
                    }

                } catch (error) {
                    console.error('Error:', error);
                    alert('エラーが発生しました: ' + error.message);
                }
            }

            // Base64 URL を ArrayBuffer に変換する関数
            function base64URLToBuffer(base64URL) {
                const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
                const padding = '='.repeat((4 - base64.length % 4) % 4);
                const binary = atob(base64 + padding);
                const buffer = new ArrayBuffer(binary.length);
                const view = new Uint8Array(buffer);
                for (let i = 0; i < binary.length; i++) {
                    view[i] = binary.charCodeAt(i);
                }
                return buffer;
            }

            // ArrayBuffer を Base64 URL に変換する関数
            function bufferToBase64URL(buffer) {
                const bytes = new Uint8Array(buffer);
                let binary = '';
                for (let i = 0; i < bytes.byteLength; i++) {
                    binary += String.fromCharCode(bytes[i]);
                }
                const base64 = btoa(binary);
                return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            }
        </script>
    """

@app.route('/customlogin-passkeylogin/initiate', methods=['POST'])
def custom_passkey_login_initiate():
    try:
        data = request.get_json()
        username = data.get('username')

        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')

        initial_response = cognito_client.initiate_auth(
            AuthFlow='USER_AUTH',
            ClientId=CLIENT_ID,
            AuthParameters={
                'USERNAME': username,
                'SECRET_HASH': get_secret_hash(username)
            }
        )

        # デバッグ出力
        print("=== Debug: initiate_auth response ===")
        print(json.dumps(initial_response, indent=2))
        print("========================")

        # SELECT_CHALLENGEが返ってきた場合、WEB_AUTHNを選択
        if initial_response.get('ChallengeName') == 'SELECT_CHALLENGE':
            challenge_response = cognito_client.respond_to_auth_challenge(
                ClientId=CLIENT_ID,
                ChallengeName='SELECT_CHALLENGE',
                Session=initial_response['Session'],
                ChallengeResponses={
                    'USERNAME': username,
                    'ANSWER': 'WEB_AUTHN',
                    'SECRET_HASH': get_secret_hash(username)
                }
            )

            print("=== Debug: challenge_response ===")
            print(json.dumps(challenge_response, indent=2))
            print("========================")

            # CREDENTIAL_REQUEST_OPTIONSを取得して返す
            credential_request_options = json.loads(
                challenge_response['ChallengeParameters']['CREDENTIAL_REQUEST_OPTIONS']
            )

            return jsonify({
                'publicKey': credential_request_options,
                'session': challenge_response['Session']
            })

    except Exception as e:
        print(f"Error in initiate auth: {str(e)}")
        return jsonify({'error': str(e)}), 400

    except Exception as e:
        print(f"Error in initiate auth: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/customlogin-passkeylogin/complete', methods=['POST'])
def custom_passkey_login_complete():
    try:
        data = request.get_json()
        username = data.get('username')
        session = data.get('session')
        credential = data.get('credential')

        # AuthenticationResponseJSON の形式を確認
        required_fields = ['id', 'rawId', 'response', 'type']
        response_fields = ['clientDataJSON', 'authenticatorData', 'signature']
        
        if not all(field in credential for field in required_fields):
            return jsonify({'error': '必須フィールドが不足しています'}), 400
            
        if not all(field in credential['response'] for field in response_fields):
            return jsonify({'error': 'responseに必須フィールドが不足しています'}), 400

        # clientExtensionResults が存在しない場合は空のオブジェクトを設定
        if 'clientExtensionResults' not in credential:
            credential['clientExtensionResults'] = {}

        cognito_client = boto3.client('cognito-idp', region_name='ap-northeast-1')
        complete_response = cognito_client.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName='WEB_AUTHN',
            Session=session,
            ChallengeResponses={
                'USERNAME': username,
                'CREDENTIAL': json.dumps(credential),  # 検証済みの AuthenticationResponseJSON
                'SECRET_HASH': get_secret_hash(username)
            }
        )

        print("=== Debug: complete_response ===")
        print(json.dumps(complete_response, indent=2))
        print("========================")

        # レスポンスを作成してCookieを設定
        response_data = make_response(jsonify({'success': True}))

        auth_result = complete_response.get('AuthenticationResult', {})
        if auth_result:
            response_data.set_cookie(
                'id_token',
                auth_result.get('IdToken', ''),
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            
            response_data.set_cookie(
                'access_token',
                auth_result.get('AccessToken', ''),
                httponly=True,
                secure=True,
                samesite='Lax'
            )

        return response_data

    except Exception as e:
        print(f"Error in complete challenge: {str(e)}")
        return jsonify({'error': str(e)}), 400

@app.route('/customlogin-mypage')
def custom_mypage():
    try:
        # Cookieからid_tokenを取得
        id_token = request.cookies.get('id_token')
        if not id_token:
            return """
                <h1>エラー</h1>
                <p>ログインが必要です</p>
                <p><a href="/customlogin">ログインページへ</a></p>
            """

        # JWTをデコード
        decoded = decode_jwt(id_token)

        # トークンから必要な情報を取得
        email = decoded.get('email', 'Not found')
        sub = decoded.get('sub', 'Not found')
        token_use = decoded.get('token_use', 'Not found')
        auth_time = datetime.fromtimestamp(decoded.get('auth_time', 0)).strftime('%Y-%m-%d %H:%M:%S')
        exp_time = datetime.fromtimestamp(decoded.get('exp', 0)).strftime('%Y-%m-%d %H:%M:%S')

        return f"""
            <h1>マイページ</h1>
            <div style="margin: 20px 0;">
                <h2>ユーザー情報</h2>
                <p>メールアドレス: {email}</p>
                <p>ユーザーID: {sub}</p>
                <h2>トークン情報</h2>
                <p>トークンタイプ: {token_use}</p>
                <p>認証時刻: {auth_time}</p>
                <p>有効期限: {exp_time}</p>
                <pre style="background: #f5f5f5; padding: 10px; overflow: auto;">
                    <code>{json.dumps(decoded, indent=2)}</code>
                </pre>
            </div>
            <div style="margin: 20px 0;">
                <p><a href="/customlogin">メニューに戻る</a></p>
                <p><a href="/logout">ログアウト</a></p>
            </div>
        """

    except Exception as e:
        return f"""
            <h1>エラー</h1>
            <p>情報の取得に失敗しました: {str(e)}</p>
            <p><a href="/customlogin">メニューに戻る</a></p>
        """

@app.route('/logout')
def logout():
    logout_url = f"{COGNITO_DOMAIN}/logout?client_id={CLIENT_ID}&logout_uri={LOGOUT_URI}"
    response = make_response(redirect(logout_url))
    
    # Delete ALB auth cookies by setting them to empty and expired
    response.set_cookie('AWSELBAuthSessionCookie-0', '', expires=0, domain=None, path='/', httponly=True)
    response.set_cookie('AWSELBAuthSessionCookie-1', '', expires=0, domain=None, path='/', httponly=True)
    response.set_cookie('access_token', '', expires=0, domain=None, path='/', httponly=True)
    response.set_cookie('id_token', '', expires=0, domain=None, path='/', httponly=True)


    return response

@app.route('/')
def home():
    return """
        <h1>Cognito Testpage</h1>
        <p><a href="/managedlogin">ログイン (ALB + Managed Login)</a></p>
        <p><a href="/customlogin">ログイン (パスキー独自実装)</a></p>
    """

if __name__ == '__main__':
    app.run()
