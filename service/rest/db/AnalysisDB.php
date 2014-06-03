<?php
namespace Netflows;

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";
require_once "DBConnector.php";

class AnalysisDB extends \DBConnector
{
    const JOB_ID_INDEX        = "job_id";
    const FLOW_ID_INDEX       = "flow_id";
    const SNAPSHOT_ID_INDEX   = "snapshot_id";
    const ANALYZER_ID_INDEX   = "analyzer_id";
    const CREATION_TIME_INDEX = "created";
    const DATA_INDEX          = "data";

    protected $entityManager;

    public function __construct()
    {
         parent::__construct();
    }

    public function __destruct()
    {

    }

    public function getLatestSnapshotOfAnalysis($args)
    {
        $jobID      = null;
        $flowID     = null;
        $analyzerID = null;

        if(parent::isValidIndex($args, self::JOB_ID_INDEX))
            $jobID = $args[self::JOB_ID_INDEX];

        if(parent::isValidIndex($args, self::FLOW_ID_INDEX))
            $flowID = $args[self::FLOW_ID_INDEX];

        if(parent::isValidIndex($args, self::ANALYZER_ID_INDEX))
            $analyzerID = $args[self::ANALYZER_ID_INDEX];

        $result = $this->entityManager->getRepository('FlowsAnalysis')->findBy(array('job_id'   => $jobID,
                                                                                  'flow_id'     => $flowID,
                                                                                  'analyzer_id' => $analyzerID),
                                                                               array('snapshot_id' => 'DESC'), 3, 0);
        if(isset($result[0]))
            return $this->resultToArray($result[0]);
        else
            return array("status"  => "Error",
                         "message" => "No Result-Set found with job-id '$jobID', flow-id '$flowID', analyzer-id '$analyzerID'");
    }

    public function getResultOfAnalysis($args)
    {
        $jobID      = null;
        $flowID     = null;
        $analyzerID = null;

        if(parent::isValidIndex($args, self::JOB_ID_INDEX))
            $jobID = $args[self::JOB_ID_INDEX];

        if(parent::isValidIndex($args, self::FLOW_ID_INDEX))
            $flowID = $args[self::FLOW_ID_INDEX];

        if(parent::isValidIndex($args, self::ANALYZER_ID_INDEX))
            $analyzerID = $args[self::ANALYZER_ID_INDEX];

        $results = $this->entityManager->getRepository('FlowsAnalysis')->findBy(array('job_id'      => $jobID,
                                                                                      'flow_id'     => $flowID,
                                                                                      'analyzer_id' => $analyzerID));
        $retArr = array();

        foreach($results as $result)
        {
            array_push($retArr, $this->resultToArray($result));
        }

        return $retArr;
    }

    public function addResult($args)
    {
        $jobID      = null;
        $flowID     = null;
        $analyzerID = null;
        $snapshotID = null;
        $data      = null;

        //check if primary key are provided
        if(!parent::isValidIndex($args, self::JOB_ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::JOB_ID_INDEX."' must be provided!");
        }
        if(!parent::isValidIndex($args, self::FLOW_ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::FLOW_ID_INDEX."' must be provided!");
        }
        if(!parent::isValidIndex($args, self::ANALYZER_ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::ANALYZER_ID_INDEX."' must be provided!");
        }
        if(!parent::isValidIndex($args, self::SNAPSHOT_ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::SNAPSHOT_ID_INDEX."' must be provided!");
        }

        //retrieve all values
        if(parent::isValidIndex($args, self::DATA_INDEX))
            $data = $args[self::DATA_INDEX];

        $jobID      = $args[self::JOB_ID_INDEX];
        $analyzerID = $args[self::ANALYZER_ID_INDEX];
        $flowID     = $args[self::FLOW_ID_INDEX];
        $snapshotID = $args[self::SNAPSHOT_ID_INDEX];

        $analysis = new \FlowsAnalysis();

        //check against foreign key constraints
        $jobObj = $this->entityManager->find("Jobs",$jobID);
        if(isset($jobObj))     //if id of job is invalid, a null-object will be returned
            $analysis->setAssociatedJob($jobObj);
        else
           return array("status"  => "Error",
                        "message" => "The provided '".self::JOB_ID_INDEX."' violates foreign key restrictions. No job found of ID :'$jobID' !");

       $flowObj = $this->entityManager->getRepository('Flows')->findBy(array(FlowsDB::ID_INDEX     => $args[self::FLOW_ID_INDEX],
                                                                              FlowsDB::JOB_ID_INDEX => $args[self::JOB_ID_INDEX]));
        if(isset($flowObj[0]))     //if id of job is invalid, a null-object will be returned
            $analysis->setAssociatedFlow($flowObj[0]);
        else
           return array("status"  => "Error",
                        "message" => "The provided '".self::FLOW_ID_INDEX."' violates foreign key restrictions. No flow found of ID :'$flowID' !");

        $analyzerObj = $this->entityManager->find("Analysers",$analyzerID);
        if(isset($analyzerObj))     //if id of job is invalid, a null-object will be returned
            $analysis->setAssociatedAnalyzer($analyzerObj);
        else
           return array("status"  => "Error",
                        "message" => "The provided '".self::ANALYZER_ID_INDEX."' violates foreign key restrictions. No analyzer found of ID :'$analyzerID' !");

        $analysis->setSnapshotId($snapshotID);
        $analysis->setData($data);
        $analysis->setCreationDate(new \DateTime("now"));

        //write to DB
        $this->entityManager->persist($analysis);
        $this->entityManager->flush();


        return array("status"  => "Sucess",
                     "message" => "Created a new flow-analysis result.");
    }

    private function resultToArray($result)
    {
        $ret = array();

        $ret[self::JOB_ID_INDEX]        = $result->getAssociatedJob()->getId();
        $ret[self::FLOW_ID_INDEX]       = $result->getAssociatedFlow()->getId();
        $ret[self::ANALYZER_ID_INDEX]   = $result->getAssociatedAnalyzer()->getId();
        $ret[self::SNAPSHOT_ID_INDEX]   = $result->getSnapshotId();
        $ret[self::CREATION_TIME_INDEX] = $result->getCreationDate();
        $ret[self::DATA_INDEX]          = $result->getData();

        return $ret;
    }
}
?>
