<?php
header('Content-Type: application/json');
echo json_encode([
  'post'   => isset($_POST)   ? array_map(fn($v)=>is_string($v)?['len'=>strlen($v)]:$v, $_POST) : 'NULL',
  'server' => $_SERVER['REQUEST_URI'] ?? null,
]);
