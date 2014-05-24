<?php
namespace Netflows;

/**
 * Communication interface between the PHP front-end application and C back-end application
 **/
class BackendCommunicator
{
    public function __construct()
    {

    }

    public function verifyPCAP($args)
    {
        echo "<p>File will be verified, please wait....</p>";
        print_r($args);
        return "valid";
    }
}
?>
