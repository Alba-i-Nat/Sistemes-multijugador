<?php

//iniciem sessio segura
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict'
    //'cookie_secure' => true, //si despres utilitzarem https
]);

// defaults
$template = 'home';
$db_connection = 'sqlite:..\private\users.db';

// fitxer log, per ara no esborrem res
$log_file = __DIR__ . '/../private/log.txt';
$attempts_file = __DIR__ . '/../private/attempts.txt';
date_default_timezone_set('Europe/Madrid');

// regles de password i usernames
define('PASSWORD_MIN_LEN', 8);
define('PASSWORD_MAX_LEN', 48);
define('USERNAME_MAX_LEN', 48);
define('MAX_ATTEMPTS', 3);
define('BLOCK_TIME', 90); // 15 minutes


// funcions
function write_log($action, $username = '-'){
    global $log_file;
    // mirem si existeix el fitxer log, sino creem
    $log_dir = dirname($log_file);
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0700, true);
    }

    $time = date(DATE_RFC2822); //ha de produir sortida com : Wed, 25 Sep 2013 15:28:57 -0700
    $line = sprintf("%s\t%s\t%s\n", $time, $action, $username);
    @file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);
}

function get_client_ip() {
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

function check_attempts($ip) {
    global $attempts_file;
    $attempts = [];

    if (file_exists($attempts_file)) {
        $lines = file($attempts_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            [$stored_ip, $time, $count] = explode('|', $line);
            $attempts[$stored_ip] = ['time' => strtotime($time), 'count' => (int)$count];
        }
    }

    //if blocked
    if (isset($attempts[$ip])) {
        $diff = time() - $attempts[$ip]['time'];
        if ($attempts[$ip]['count'] >= MAX_ATTEMPTS && $diff < BLOCK_TIME) {
            return BLOCK_TIME - $diff;
        }
    }
    return 0; //not blocked
}

function register_attempt($ip, $success) {
    global $attempts_file;
    $attempts = [];

    if (file_exists($attempts_file)) {
        $lines = file($attempts_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            [$stored_ip, $time, $count] = explode('|', $line);
            $attempts[$stored_ip] = ['time' => strtotime($time), 'count' => (int)$count];
        }
    }

    if ($success) {
        unset($attempts[$ip]); //reset on success
    } else {
        if (!isset($attempts[$ip])) {
            $attempts[$ip] = ['time' => time(), 'count' => 1];
        } else {
            $diff = time() - $attempts[$ip]['time'];
            if ($diff > BLOCK_TIME) {
                $attempts[$ip] = ['time' => time(), 'count' => 1];
            } else {
                $attempts[$ip]['count']++;
                $attempts[$ip]['time'] = time();
            }
        }
    }

    //write back
    $lines = [];
    foreach ($attempts as $stored_ip => $info) {
        $lines[] = $stored_ip . '|' . date('Y-m-d H:i:s', $info['time']) . '|' . $info['count'];
    }
    file_put_contents($attempts_file, implode("\n", $lines));
}

$configuration = array(
    '{FEEDBACK}'          => '',
    '{LOGIN_LOGOUT_TEXT}' => 'Identificar-me',
    '{LOGIN_LOGOUT_URL}'  => '/?page=login',
    '{METHOD}'            => 'POST', // cambiat per POST perque no es vegin els paràmetres a l'URL i a la consola
    '{REGISTER_URL}'      => '/?page=register',
    '{SITE_NAME}'         => 'La meva pàgina',
    '{BLOCK_MESSAGE}'     => '',
    '{BLOCKED}'           => '',
    '{BLOCK_TIME_LEFT}'   => '0'
);

// agafem la pagin amb GET pero els parametres amb POST
// parameter processing
//$parameters = $_GET;

$page = $_GET['page'] ?? null;
if ($page) {
    if ($page === 'register') {
        $template = 'register';
        $configuration['{REGISTER_USERNAME}'] = '';
        $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Ja tinc un compte';
        //log
        write_log('page_view_register', '-');
    } else if ($page === 'login') {
        $ip = get_client_ip();
        $blocked_time = check_attempts($ip);
        if ($blocked_time > 0) {
            $template = 'home';
            $configuration['{BLOCKED}'] = 'true';
            $configuration['{BLOCK_TIME_LEFT}'] = $blocked_time;
            $configuration['{BLOCK_MESSAGE}'] = '<mark>Has superat el nombre maxim d\'intents. Pots tornar-ho a provar en <span id="countdown"></span> segons.</mark>';
            //log
            write_log('login_blocked_view', $ip);
        } else {
            $template = 'login';
            $configuration['{LOGIN_USERNAME}'] = '';
            //log
            write_log('page_view_login', '-');
        } 
    } else if ($page === 'logout') { //si abans teniem cookie i ho volem treure
        $username = $_SESSION['username'] ?? '-';
        write_log('logout', $username);

        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();

        header("Location: /");
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // registracio
    if (isset($_POST['register'])) {
        $username = trim((string)($_POST['user_name'] ?? '-'));
        $password = (string)($_POST['user_password'] ?? '-');
        //log
        write_log('register_attempt', $username);

        // validem dades per part del server
        if ($username === '') {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Es requereix nom d usuari</mark>';
            //log
            write_log('register_fail', $username);
        } else if (strlen($username) > USERNAME_MAX_LEN) {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Nom d usuari no pot eccedir 48 caracters</mark>';
            //log
            write_log('register_fail', $username);
        } else if (strlen($password) > PASSWORD_MAX_LEN) {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Password ha de ser com a minim de 8 caracters</mark>';
            //log
            write_log('register_fail', $username);
        } else { //si no hi han errors
            //fem hash per passwords amb bcrypt
            $hash = password_hash($password, PASSWORD_BCRYPT);
            if ($hash === false) {
                $configuration['{FEEDBACK}'] = '<mark>ERROR: No em pogut hashejar el password</mark>';
                //log
                write_log('register_fail', $username);
            } else {
                try {
                    $db = new PDO($db_connection);
                    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $sql = 'INSERT INTO users (user_name, user_password) VALUES (:user_name, :user_password)';
                    $query = $db->prepare($sql);
                    $query->bindValue(':user_name', $username);
                    $query->bindValue(':user_password', $hash);
                    $query->execute();

                    $configuration['{FEEDBACK}'] = 'Creat el compte <b>' . htmlentities($username) . '</b>';
                    $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
                    //log
                    write_log('register_success', $username);
                } catch (PDOException $e) {
                    //control d'errors
                    $code = $e->getCode();
                    $msg = $e->getMessage();
                    if ($code === '23000' or stripos($msg, 'UNIQUE') !== false) {
                        $configuration['{FEEDBACK}'] = '<mark>ERROR: Nom d usuari no permitit</mark>';
                        //log
                        write_log('register_fail', $username);
                    } else {
                        $configuration['{FEEDBACK}'] = '<mark>ERROR: Error de base de dades</mark>';
                        //log
                        write_log('register_fail', $username);
                    }
                }
            }
        }
        
    // login
    } else if (isset($_POST['login'])) {
        $username = trim((string)($_POST['user_name'] ?? '-'));
        $password = (string)($_POST['user_password'] ?? '-');
        $ip = get_client_ip();
        $blocked_time = check_attempts($ip);

        if ($blocked_time > 0) {
            $configuration['{FEEDBACK}'] = '<mark>ERROR: Massa intents. Espera uns minuts</mark>';
            //log
            write_log('login_blocked', $username);
        } else {
            //log
            write_log('login_attempt', $username);

            // validem dades
            if ($username === '') {
                $configuration['{FEEDBACK}'] = '<mark>ERROR: Es requereix nom d usuari</mark>';
                //log
                write_log('login_fail', $username);
                register_attempt($ip, false);
            } else { //comprovem el password
                try {
                    $db = new PDO($db_connection);
                    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                    $sql = 'SELECT * FROM users WHERE user_name = :user_name';
                    $query = $db->prepare($sql);
                    $query->bindValue(':user_name', $username);
                    $query->execute();
                    //$result_row = $query->fetchObject();
                    $row = $query->fetch(PDO::FETCH_ASSOC);
                    if ($row) {
                        $stored = $row['user_password'];
                        // s'assumeix que tots passwords que tenim en la bd son hashejats
                        
                        if (password_verify($password, $stored)) {
                            //mirem si cal fer un rehash
                            if (password_needs_rehash($stored, PASSWORD_BCRYPT)) {
                                $newHash = password_hash($password, PASSWORD_BCRYPT);
                                if ($newHash !== false) { //canviem password en la bd
                                    $upd = $db->prepare('UPDATE users SET user_password = :hash WHERE user_id = :id');
                                    $upd->bindValue(':hash', $newHash);
                                    $upd->bindValue(':id', $row['user_id']);
                                    $upd->execute();
                                    //log
                                    write_log('password_rehash', $username);
                                }
                            }

                            $_SESSION['user_id'] = $row['user_id'];
                            $_SESSION['username'] = $username;

                            $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($username) . '</b>';
                            //$configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
                            //$configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
                            //log
                            write_log('login_success', $username);
                            register_attempt($ip, true);
                        } else if ($password === $stored) {
                            $newHash = password_hash($password, PASSWORD_BCRYPT);
                            if ($newHash !== false) { //canviem password en la bd
                                $upd = $db->prepare('UPDATE users SET user_password = :hash WHERE user_id = :id');
                                $upd->bindValue(':hash', $newHash);
                                $upd->bindValue(':id', $row['user_id']);
                                $upd->execute();
                                //log
                                write_log('password_migrate', $username);
                            }
                            
                            $_SESSION['user_id'] = $row['user_id'];
                            $_SESSION['username'] = $username;

                            $configuration['{FEEDBACK}'] = '"Sessió" iniciada com <b>' . htmlentities($username) . '</b>';
                            //$configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar "sessió"';
                            //$configuration['{LOGIN_LOGOUT_URL}'] = '/?page=logout';
                            //log
                            write_log('login_success', $username);
                            register_attempt($ip, true);
                        } else {
                            $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta</mark>';
                            //log
                            write_log('login_fail', $username);
                            register_attempt($ip, false);
                        }
                    } else {
                        $configuration['{FEEDBACK}'] = '<mark>ERROR: Usuari desconegut o contrasenya incorrecta</mark>';
                        //log
                        write_log('login_fail', $username);
                        register_attempt($ip, false);
                    }
                } catch (PDOException $e) {
                    $configuration['{FEEDBACK}'] = '<mark>ERROR: Error de base de dades</mark>';
                    //log
                    write_log('login_fail', $username);
                    register_attempt($ip, false);
                }
            }
        }
        
    }
}

if (!empty($_SESSION['username'])) {
    $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Tancar sessió';
    $configuration['{LOGIN_LOGOUT_URL}']  = '/?page=logout';
} else {
    $configuration['{LOGIN_LOGOUT_TEXT}'] = 'Identificar-me';
    $configuration['{LOGIN_LOGOUT_URL}']  = '/?page=login';
}

// process template and show output
$html = file_get_contents('plantilla_' . $template . '.html', true);
$html = str_replace(array_keys($configuration), array_values($configuration), $html);

if ($configuration['{BLOCKED}'] === 'true') {
    $html .= "
    <script>
    let remaining = {$configuration['{BLOCK_TIME_LEFT}']};
    function updateCountdown() {
        if (remaining <= 0) {
            location.href='/?page=login';
        } else {
            document.getElementById('countdown').innerText = remaining;
            remaining--;
            setTimeout(updateCountdown, 1000);
        }
    }
    updateCountdown();
    </script>";
}

echo $html;
