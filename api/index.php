
<?php
declare(strict_types=1);

/*
 * Dark Google Login - PHP OAuth 2.0
 * Vercel PHP runtime
 */

$isHttps = (
    ($_SERVER['HTTPS'] ?? '') === 'on'
    || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https'
);

$cookieOptions = [
    'expires' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
];

function envv(string $key): string {
    return trim((string) getenv($key));
}

function config(string $key): string {
    $value = envv($key);
    if ($value === '') {
        http_response_code(500);
        exit('Missing environment variable: ' .
            htmlspecialchars($key, ENT_QUOTES, 'UTF-8'));
    }
    return $value;
}

function b64url(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function signData(string $data): string {
    return hash_hmac('sha256', $data, config('APP_KEY'));
}

function makeCookie(string $name, array $data): void {
    global $cookieOptions;

    $json = json_encode($data, JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        throw new RuntimeException('Could not encode cookie');
    }

    $payload = b64url($json);
    $value = $payload . '.' . signData($payload);

    setcookie($name, $value, $cookieOptions);
}

function readCookie(string $name): ?array {
    $value = $_COOKIE[$name] ?? '';

    if (!is_string($value) || !str_contains($value, '.')) {
        return null;
    }

    [$payload, $signature] = explode('.', $value, 2);

    if (!hash_equals(signData($payload), $signature)) {
        return null;
    }

    $json = base64_decode(
        strtr($payload, '-_', '+/') .
        str_repeat('=', (4 - strlen($payload) % 4) % 4)
    );

    if ($json === false) {
        return null;
    }

    $data = json_decode($json, true);

    if (!is_array($data)) {
        return null;
    }

    if (($data['exp'] ?? 0) < time()) {
        return null;
    }

    return $data;
}

function clearCookie(string $name): void {
    global $cookieOptions;

    setcookie($name, '', array_merge($cookieOptions, [
        'expires' => time() - 3600,
    ]));
}

function redirectTo(string $url): never {
    header('Location: ' . $url, true, 302);
    exit;
}

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function httpPostForm(string $url, array $fields): array {
    if (!function_exists('curl_init')) {
        throw new RuntimeException('PHP cURL extension is required');
    }

    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
        ],
    ]);

    $body = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);

    curl_close($ch);

    if ($body === false || $status < 200 || $status >= 300) {
        error_log('OAuth HTTP error: ' . $status . ' ' . $error);
        throw new RuntimeException('OAuth request failed');
    }

    $result = json_decode($body, true);

    if (!is_array($result)) {
        throw new RuntimeException('Invalid OAuth response');
    }

    return $result;
}

function httpGetJson(string $url): array {
    $ch = curl_init($url);

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => ['Accept: application/json'],
    ]);

    $body = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);

    curl_close($ch);

    if ($body === false || $status < 200 || $status >= 300) {
        error_log('Google API error: ' . $status . ' ' . $error);
        throw new RuntimeException('Google API request failed');
    }

    $result = json_decode($body, true);

    if (!is_array($result)) {
        throw new RuntimeException('Invalid Google API response');
    }

    return $result;
}

function baseUrl(): string {
    $host = envv('APP_URL');

    if ($host === '') {
        $host = $_SERVER['HTTP_HOST'] ?? '';
    }

    if ($host === '') {
        throw new RuntimeException('APP_URL is not configured');
    }

    // APP_URL must be your own HTTPS domain.
    if (!str_starts_with($host, 'https://')
        && !str_starts_with($host, 'http://')) {
        $host = 'https://' . $host;
    }

    return rtrim($host, '/');
}

function callbackUrl(): string {
    return baseUrl() . '/callback';
}

function googleAuthorizeUrl(string $state): string {
    $params = [
        'client_id' => config('GOOGLE_CLIENT_ID'),
        'redirect_uri' => callbackUrl(),
        'response_type' => 'code',
        'scope' => 'openid email profile',
        'state' => $state,
        'prompt' => 'select_account',
    ];

    return 'https://accounts.google.com/o/oauth2/v2/auth?' .
        http_build_query($params);
}

function pageStart(string $title): void {
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    ?>
    <!doctype html>
    <html lang="vi">
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">
        <meta name="theme-color" content="#09090f">
        <title><?= e($title) ?></title>
        <style>
        *{box-sizing:border-box}
        :root{color-scheme:dark}
        body{margin:0;min-height:100vh;background:#09090f;color:#f4f4f8;
        font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;
        display:flex;align-items:center;justify-content:center;padding:24px;
        background-image:radial-gradient(ellipse at 50% 0%,#30205c 0%,transparent 55%)}
        .card{width:100%;max-width:440px;padding:38px;
        background:rgba(18,18,29,.9);border:1px solid #29283b;
        border-radius:24px;box-shadow:0 24px 100px #0008}
        .brand{display:flex;align-items:center;gap:12px;margin-bottom:32px}
        .logo{width:42px;height:42px;border-radius:14px;
        display:grid;place-items:center;background:linear-gradient(135deg,#8b5cf6,#4f46e5);
        font-weight:800;font-size:20px}
        .brand strong{font-size:15px;letter-spacing:.2px}
        .brand small{display:block;color:#88889e;font-size:12px;margin-top:3px}
        h1{font-size:30px;line-height:1.2;letter-spacing:-1px;margin:0 0 12px}
        p{color:#a5a5bb;line-height:1.7;font-size:14px}
        .btn{display:flex;align-items:center;justify-content:center;gap:12px;
        width:100%;padding:15px 18px;border:1px solid #39394b;
        border-radius:14px;background:#fff;color:#17171c;
        font-weight:650;font-size:15px;text-decoration:none;cursor:pointer;
        transition:transform .2s,box-shadow .2s}
        .btn:hover{transform:translateY(-2px);box-shadow:0 10px 30px #0005}
        .google{width:20px;height:20px}
        .muted{font-size:12px;color:#77778e;text-align:center;margin-top:24px}
        .divider{height:1px;background:#29283b;margin:26px 0}
        .profile{text-align:center}
        .avatar{width:88px;height:88px;border-radius:50%;object-fit:cover;
        border:3px solid #7c3aed;margin:4px auto 20px;display:block}
        .avatar-placeholder{width:88px;height:88px;border-radius:50%;
        background:#30205c;display:grid;place-items:center;margin:4px auto 20px;
        font-size:32px}
        .pill{display:inline-block;background:#172c27;color:#75e2b4;
        border:1px solid #245442;padding:6px 11px;border-radius:99px;font-size:12px}
        .details{margin:24px 0;text-align:left;padding:16px;
        background:#10101a;border:1px solid #29283b;border-radius:14px}
        .details small{color:#77778e;display:block;margin-bottom:6px}
        .details strong{font-size:14px;overflow-wrap:anywhere}
        .logout{background:#171722;color:#ddd;border-color:#39394b;margin-top:12px}
        .error{padding:12px;border:1px solid #713b4a;background:#29151c;
        color:#ffb8c7;border-radius:12px;font-size:13px;margin:20px 0}
        @media(max-width:480px){.card{padding:26px 22px}h1{font-size:27px}}
        </style>
    </head>
    <body>
    <?php
}

function pageEnd(): void {
    ?>
    </body>
    </html>
    <?php
}

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

try {
    // HOME / LOGIN
    if ($path === '/' && $method === 'GET') {
        $user = readCookie('auth_user');

        if ($user !== null) {
            redirectTo('/dashboard');
        }

        pageStart('Dark Login — Sign in');
        ?>
        <main class="card">
            <div class="brand">
                <div class="logo">D</div>
                <div>
                    <strong>Dark Login</strong>
                    <small>Secure identity platform</small>
                </div>
            </div>

            <h1>Welcome back<span style="color:#a78bfa">.</span></h1>
            <p>
                Đăng nhập để tiếp tục vào không gian cá nhân của bạn.
                Nhanh chóng, an toàn và bảo mật với Google.
            </p>

            <?php if (isset($_GET['error'])): ?>
                <div class="error">
                    Đăng nhập chưa thành công. Vui lòng thử lại.
                </div>
            <?php endif; ?>

            <div class="divider"></div>

            <a class="btn" href="/login">
                <svg class="google" viewBox="0 0 48 48"
                     aria-hidden="true">
                    <path fill="#EA4335"
                      d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
                      transform="translate(0 4)"/>
                    <path fill="#4285F4"
                      d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.74 7.18l7.73 6C44.44 37.96 46.98 31.9 46.98 24.55z"/>
                    <path fill="#FBBC05"
                      d="M10.53 28.59A14.4 14.4 0 0 1 9.75 24c0-1.59.27-3.13.76-4.59l-7.98-6.2A23.9 23.9 0 0 0 0 24c0 3.88.93 7.55 2.56 10.78l7.97-6.19z"
                      transform="translate(0 0)"/>
                    <path fill="#34A853"
                      d="M24 48c6.48 0 11.93-2.13 15.91-5.8l-7.73-6c-2.15 1.45-4.92 2.3-8.18 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                </svg>
                Continue with Google
            </a>

            <div class="muted">
                Bằng cách tiếp tục, bạn đồng ý với các điều khoản
                và chính sách bảo mật của website.
            </div>
        </main>
        <?php
        pageEnd();
        exit;
    }

    // START OAUTH
    if ($path === '/login' && $method === 'GET') {
        $state = bin2hex(random_bytes(32));

        makeCookie('oauth_state', [
            'state' => $state,
            'exp' => time() + 600,
        ]);

        redirectTo(googleAuthorizeUrl($state));
    }

    // GOOGLE CALLBACK
    if ($path === '/callback' && $method === 'GET') {
        $error = $_GET['error'] ?? '';

        if ($error !== '') {
            clearCookie('oauth_state');
            redirectTo('/?error=oauth');
        }

        $code = $_GET['code'] ?? '';
        $state = $_GET['state'] ?? '';
        $savedState = readCookie('oauth_state');

        clearCookie('oauth_state');

        if (!is_string($code) || $code === ''
            || !is_string($state)
            || !$savedState
            || !isset($savedState['state'])
            || !hash_equals((string)$savedState['state'], $state)) {
            http_response_code(400);
            exit('Invalid OAuth state. Please try again.');
        }

        $token = httpPostForm(
            'https://oauth2.googleapis.com/token',
            [
                'code' => $code,
                'client_id' => config('GOOGLE_CLIENT_ID'),
                'client_secret' => config('GOOGLE_CLIENT_SECRET'),
                'redirect_uri' => callbackUrl(),
                'grant_type' => 'authorization_code',
            ]
        );

        $idToken = $token['id_token'] ?? '';

        if (!is_string($idToken) || $idToken === '') {
            throw new RuntimeException('Missing ID token');
        }

        /*
         * Verify the ID token with Google's tokeninfo endpoint.
         * For production systems with high traffic, use a maintained
         * Google API client / JWT library and verify Google's signing
         * keys locally.
         */
        $claims = httpGetJson(
            'https://oauth2.googleapis.com/tokeninfo?id_token=' .
            rawurlencode($idToken)
        );

        $clientId = config('GOOGLE_CLIENT_ID');

        if (!isset($claims['aud'])
            || !hash_equals($clientId, (string)$claims['aud'])) {
            throw new RuntimeException('Invalid token audience');
        }

        if (($claims['iss'] ?? '') !== 'https://accounts.google.com'
            && ($claims['iss'] ?? '') !== 'accounts.google.com') {
            throw new RuntimeException('Invalid token issuer');
        }

        if ((int)($claims['exp'] ?? 0) <= time()) {
            throw new RuntimeException('Expired ID token');
        }

        if (($claims['email_verified'] ?? '') !== 'true'
            && ($claims['email_verified'] ?? '') !== true) {
            throw new RuntimeException('Email is not verified');
        }

        $sub = (string)($claims['sub'] ?? '');
        $email = (string)($claims['email'] ?? '');

        if ($sub === '' || $email === '') {
            throw new RuntimeException('Missing Google identity');
        }

        $user = [
            'sub' => $sub,
            'email' => $email,
            'name' => (string)($claims['name'] ?? 'Google User'),
            'picture' => (string)($claims['picture'] ?? ''),
            'exp' => time() + 3600,
        ];

        makeCookie('auth_user', $user);

        redirectTo('/dashboard');
    }

    // PRIVATE DASHBOARD
    if ($path === '/dashboard' && $method === 'GET') {
        $user = readCookie('auth_user');

        if (!$user) {
            redirectTo('/');
        }

        $name = (string)($user['name'] ?? 'Google User');
        $email = (string)($user['email'] ?? '');
        $picture = (string)($user['picture'] ?? '');

        pageStart('Dashboard — Dark Login');
        ?>
        <main class="card">
            <div class="brand">
                <div class="logo">D</div>
                <div>
                    <strong>Dark Login</strong>
                    <small>Your personal dashboard</small>
                </div>
            </div>

            <div class="profile">
                <?php if ($picture !== ''): ?>
                    <img class="avatar"
                         src="<?= e($picture) ?>"
                         alt="Profile picture"
                         referrerpolicy="no-referrer">
                <?php else: ?>
                    <div class="avatar-placeholder">👤</div>
                <?php endif; ?>

                <span class="pill">✓ Google verified</span>
                <h1 style="margin-top:20px">
                    Hello, <?= e($name) ?>
                </h1>
                <p>Bạn đã đăng nhập thành công.</p>
            </div>

            <div class="details">
                <small>Email address</small>
                <strong><?= e($email) ?></strong>
                <div class="divider"></div>
                <small>Authentication provider</small>
                <strong>Google OAuth 2.0</strong>
            </div>

            <form method="post" action="/logout">
                <button class="btn logout" type="submit">
                    Sign out
                </button>
            </form>

            <div class="muted">
                Your session is protected with a signed cookie.
            </div>
        </main>
        <?php
        pageEnd();
        exit;
    }

    // LOGOUT
    if ($path === '/logout' && $method === 'POST') {
        clearCookie('auth_user');
        clearCookie('oauth_state');
        redirectTo('/');
    }

    http_response_code(404);
    pageStart('404 — Not found');
    echo '<main class="card"><h1>404</h1><p>Page not found.</p>
          <a class="btn" href="/">Back to home</a></main>';
    pageEnd();

} catch (Throwable $e) {
    error_log('Application error: ' . $e->getMessage());

    http_response_code(500);
    pageStart('Login error');
    ?>
    <main class="card">
        <h1>Something went wrong</h1>
        <p>Không thể hoàn tất đăng nhập. Hãy kiểm tra cấu hình OAuth
           và thử lại.</p>
        <a class="btn" href="/">Back to login</a>
    </main>
    <?php
    pageEnd();
}
