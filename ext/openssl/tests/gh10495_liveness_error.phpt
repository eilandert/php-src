--TEST--
GH-10495: feof restores blocking mode after an abruptly closed TLS peer
--EXTENSIONS--
openssl
--SKIPIF--
<?php
if (!function_exists("proc_open")) die("skip no proc_open");
?>
--FILE--
<?php
$certFile = __DIR__ . DIRECTORY_SEPARATOR . 'gh10495-liveness-error.pem.tmp';

$peerName = 'gh10495-liveness-error';
$clientCode = <<<'CODE'
    $context = stream_context_create(['ssl' => ['verify_peer' => false, 'peer_name' => '%s']]);
    $fp = stream_socket_client("tlsv1.2://{{ ADDR }}", $errornum, $errorstr, 1, STREAM_CLIENT_CONNECT, $context);
    var_dump(stream_get_contents($fp, 6));

    phpt_notify('proxy');
    phpt_wait('proxy');
    var_dump(stream_get_meta_data($fp)['blocked']);
    var_dump(feof($fp));
    var_dump(stream_get_meta_data($fp)['blocked']);

    phpt_notify('server');
    phpt_notify('proxy');
CODE;
$clientCode = sprintf($clientCode, $peerName);

$serverCode = <<<'CODE'
    $context = stream_context_create(['ssl' => ['local_cert' => %s]]);
    $flags = STREAM_SERVER_BIND | STREAM_SERVER_LISTEN;
    $server = stream_socket_server("tlsv1.2://127.0.0.1:0", $errornum, $errorstr, $flags, $context);
    phpt_notify_server_start($server);

    $conn = stream_socket_accept($server);
    fwrite($conn, 'warmup');
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

    $applicationData = false;
    $upstreamBuffer = '';
    $read = [$upstream, $conn];
    while (stream_select($read, $write, $except, 1)) {
        foreach ($read as $fp) {
            $data = stream_get_contents($fp);
            if ($fp === $conn) {
                fwrite($upstream, $data);
            } else {
                fwrite($conn, $data);
                $upstreamBuffer .= $data;
                foreach (phpt_extract_tls_records($upstreamBuffer) as $record) {
                    if ($record !== '' && $record[0] === chr(23)) {
                        $applicationData = true;
                    }
                }
            }
        }
        if ($applicationData) {
            break;
        }
        $read = [$upstream, $conn];
    }

    phpt_wait();
    stream_socket_shutdown($conn, STREAM_SHUT_RDWR);
    fclose($conn);
    phpt_notify();
    phpt_wait();
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
@unlink(__DIR__ . DIRECTORY_SEPARATOR . 'gh10495-liveness-error.pem.tmp');
?>
--EXPECT--
string(6) "warmup"
bool(true)
bool(true)
bool(true)
