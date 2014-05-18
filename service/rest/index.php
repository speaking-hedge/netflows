<?php
namespace Netflows;

require_once('netflows_controler.php');

// Requests from the same server don't have a HTTP_ORIGIN header
if (!array_key_exists('HTTP_ORIGIN', $_SERVER)) {
    $_SERVER['HTTP_ORIGIN'] = $_SERVER['SERVER_NAME'];
}

try {
    $controller = new Controller($_REQUEST['request'], $_SERVER['HTTP_ORIGIN']);
    echo $controller->processRESTCall();
} catch (Exception $e) {
    echo json_encode(Array('error' => $e->getMessage()));
}
?>
