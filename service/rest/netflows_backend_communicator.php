<?php
namespace Netflows;

/**
 * Communication interface between the PHP front-end application and C back-end application
 **/
class BackendCommunicator
{
    /**
     * the path or command to the netflows-executable
     **/
    const NETFLOWS_EXECUTABLE = "netflows-packetprocessor";

    public function __construct()
    {

    }

    public function verifyPCAP($pathToPCAP)
    {
        return exec(self::NETFLOWS_EXECUTABLE." -j -c $pathToPCAP");
    }

    public function startJob($jobID, $pathToPCAP, $analyzerFlags)
    {
        $analyzerFlagsString = implode(" ", $analyzerFlags);

        exec(self::NETFLOWS_EXECUTABLE." $analyzerFlagsString -a $pathToPCAP -r -J $jobID > /dev/null &");

        //future work: when implementing a job-queue "waiting" might also be returned
        return JobsDB::JOB_STATE_CREATED;
    }
}
?>
