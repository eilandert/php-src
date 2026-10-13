--TEST--
TLS record extraction retains incomplete input across arbitrary chunks
--EXTENSIONS--
openssl
--FILE--
<?php
include 'ServerClientTestCase.inc';

function makeTlsRecord(string $payload): string {
    return "\x17\x03\x03" . pack('n', strlen($payload)) . $payload;
}

function extractRecordLengths(string &$buffer): array {
    return array_map('strlen', phpt_extract_tls_records($buffer));
}

$first = makeTlsRecord('first!');
$second = makeTlsRecord('second');

$buffer = $first;
var_dump(extractRecordLengths($buffer), strlen($buffer));

$buffer = substr($first, 0, 3);
var_dump(extractRecordLengths($buffer), strlen($buffer));
$buffer .= substr($first, 3);
var_dump(extractRecordLengths($buffer), strlen($buffer));

$buffer = substr($first, 0, 7);
var_dump(extractRecordLengths($buffer), strlen($buffer));
$buffer .= substr($first, 7);
var_dump(extractRecordLengths($buffer), strlen($buffer));

$buffer = $first . $second;
var_dump(extractRecordLengths($buffer), strlen($buffer));

$buffer = $first . substr($second, 0, 6);
var_dump(extractRecordLengths($buffer), strlen($buffer));
$buffer .= substr($second, 6);
var_dump(extractRecordLengths($buffer), strlen($buffer));

$buffer = "\x17\x03\x03\xff\xffmalformed";
var_dump(extractRecordLengths($buffer), strlen($buffer));
?>
--EXPECT--
array(1) {
  [0]=>
  int(11)
}
int(0)
array(0) {
}
int(3)
array(1) {
  [0]=>
  int(11)
}
int(0)
array(0) {
}
int(7)
array(1) {
  [0]=>
  int(11)
}
int(0)
array(2) {
  [0]=>
  int(11)
  [1]=>
  int(11)
}
int(0)
array(1) {
  [0]=>
  int(11)
}
int(6)
array(1) {
  [0]=>
  int(11)
}
int(0)
array(0) {
}
int(14)
