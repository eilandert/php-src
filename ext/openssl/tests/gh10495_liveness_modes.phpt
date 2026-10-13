--TEST--
GH-10495: feof preserves blocking modes and detects a closed TLS peer
--EXTENSIONS--
openssl
--SKIPIF--
<?php
if (!function_exists("proc_open")) die("skip no proc_open");
?>
--FILE--
<?php
$certFile = __DIR__ . DIRECTORY_SEPARATOR . 'gh10495-liveness-modes.pem.tmp';

$peerName = 'gh10495-liveness-modes';
$clientCode = <<<'CODE'
    $context = stream_context_create(['ssl' => ['verify_peer' => false, 'peer_name' => '%s']]);
    $fp = stream_socket_client("tlsv1.2://{{ ADDR }}", $errornum, $errorstr, 1, STREAM_CLIENT_CONNECT, $context);

    phpt_wait('proxy');
    var_dump(stream_get_meta_data($fp)['blocked']);
    $time = microtime(true);
    var_dump(feof($fp));
    var_dump(microtime(true) - $time < 0.5);
    var_dump(stream_get_meta_data($fp)['blocked']);
    phpt_notify('proxy');
    var_dump(stream_get_contents($fp, 5));

    phpt_notify('server');
    phpt_wait('proxy');
    stream_set_blocking($fp, false);
    var_dump(stream_get_meta_data($fp)['blocked']);
    $time = microtime(true);
    var_dump(feof($fp));
    var_dump(microtime(true) - $time < 0.5);
    var_dump(stream_get_meta_data($fp)['blocked']);
    phpt_notify('proxy');

    $payload = '';
    while (strlen($payload) < 6) {
        $read = [$fp];
        $write = $except = null;
        if (stream_select($read, $write, $except, 1)) {
            $payload .= stream_get_contents($fp);
        }
    }
    var_dump($payload);

    stream_set_blocking($fp, true);
    phpt_notify('server');
    phpt_wait('proxy');
    $read = [$fp];
    $write = $except = null;
    if (stream_select($read, $write, $except, 1) === false) {
        throw new RuntimeException('Failed to wait for the closed TLS peer');
    }
    var_dump(feof($fp));
    var_dump(stream_get_meta_data($fp)['blocked']);
CODE;
$clientCode = sprintf($clientCode, $peerName);

$serverCode = <<<'CODE'
    $context = stream_context_create(['ssl' => ['local_cert' => %s]]);
    $flags = STREAM_SERVER_BIND | STREAM_SERVER_LISTEN;
    $server = stream_socket_server("tlsv1.2://127.0.0.1:0", $errornum, $errorstr, $flags, $context);
    phpt_notify_server_start($server);

    $conn = stream_socket_accept($server);
    sleep(2);
    fwrite($conn, 'first');
    phpt_wait();
    sleep(2);
    fwrite($conn, 'second');
    phpt_wait();
    fclose($conn);
CODE;
$serverCode = sprintf($serverCode, var_export($certFile, true));

$proxyCode = <<<'CODE'
    $upstream = stream_socket_client("tcp://{{ ADDR }}", $errornum, $errorstr, 1, STREAM_CLIENT_CONNECT);
    stream_set_blocking($upstream, false);

    $flags = STREAM_SERVER_BIND | STREAM_SERVER_LISTEN;
    $server = stream_socket_server("tcp://127.0.0.1:0", $errornum, $errorstr, $flags);
    phpt_notify_server_start($server);
    $conn = stream_socket_accept($server);
    stream_set_blocking($conn, false);

    $applicationRecords = 0;
    $upstreamBuffer = '';
    $read = [$upstream, $conn];
    while (true) {
        $selected = stream_select($read, $write, $except, 1);
        if ($selected === false) {
            throw new RuntimeException('Failed to select TLS proxy streams');
        }
        if ($selected === 0) {
            if (feof($upstream)) {
                fclose($conn);
                phpt_notify();
                break;
            }
            if (feof($conn)) {
                throw new RuntimeException('TLS proxy client closed unexpectedly');
            }
            $read = [$upstream, $conn];
            continue;
        }
        foreach ($read as $fp) {
            $data = stream_get_contents($fp);
            if ($fp === $conn) {
                fwrite($upstream, $data);
                continue;
            }
            $upstreamBuffer .= $data;
            foreach (phpt_extract_tls_records($upstreamBuffer) as $record) {
                if ($record !== '' && $record[0] === chr(23) && $applicationRecords < 2) {
                    ++$applicationRecords;
                    fwrite($conn, $record[0]);
                    phpt_notify();
                    phpt_wait();
                    fwrite($conn, substr($record, 1));
                } else {
                    fwrite($conn, $record);
                }
            }
        }
        if (feof($upstream)) {
            fclose($conn);
            phpt_notify();
            break;
        }
        if (feof($conn)) {
            throw new RuntimeException('TLS proxy client closed unexpectedly');
        }
        $read = [$upstream, $conn];
    }
CODE;

include 'CertificateGenerator.inc';
$certificateGenerator = new CertificateGenerator();
$certificateGenerator->saveNewCertAsFileWithKey($peerName, $certFile);

include 'ServerClientTestCase.inc';
ServerClientTestCase::getInstance()->run($clientCode, [
    'server' => $serverCode,
    'proxy' => $proxyCode,
]);
?>
--CLEAN--
<?php
@unlink(__DIR__ . DIRECTORY_SEPARATOR . 'gh10495-liveness-modes.pem.tmp');
?>
--EXPECT--
bool(true)
bool(false)
bool(true)
bool(true)
string(5) "first"
bool(false)
bool(false)
bool(true)
bool(false)
string(6) "second"
bool(true)
bool(true)
