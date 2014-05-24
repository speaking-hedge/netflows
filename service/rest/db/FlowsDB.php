<?php
namespace Netflows;

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";
require_once "DBConnector.php";

class FlowsDB extends \DBConnector
{
    const ID_INDEX        = "id";
    const JOB_ID_INDEX    = "job_id";
    const ENDPOINT_A_IP   = "endpt_a_ip";
    const ENDPOINT_B_IP   = "endpt_b_ip";
    const ENDPOINT_A_PORT = "endpt_a_port";
    const ENDPOINT_B_PORT = "endpt_b_port";
        
    protected $entityManager;

    public function __construct()
    {
         parent::__construct();
    }

    public function __destruct()
    {

    }

    public function getFlow($args)
    {
        //some integrity checks first: check if non-NULL values are provided
        if(!parent::isValidIndex($args, self::ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "An '".self::ID_INDEX."' must be provided!");
        }
        
        $flow = $this->entityManager->find("Flows",$args[self::ID_INDEX]);

        if(!empty($flow))
        {
            return $this->flowToArray($flow);
        }

        return array("status"  => "Error",
                     "message" => "There was no Flow associated to the provided ID in the database!");
    }

    public function insertFlow($args)
    {
        $id         = null;
        $jobId      = null;
        $endptAip   = null;
        $endptBip   = null;
        $endptAport = null;
        $endptBport = null;

        //some integrity checks first: check if non-NULL values are provided
        if(!parent::isValidIndex($args, self::ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::ID_INDEX."' must be provided!");
        }
        if(!parent::isValidIndex($args, self::JOB_ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::JOB_ID_INDEX."' must be provided!");
        }
        
        //retrieve all provided data
        $jobId  = $args[self::JOB_ID_INDEX];
        $id    = $args[self::ID_INDEX];
        
        if(parent::isValidIndex($args, self::ENDPOINT_A_IP))
            $endptAip = $args[self::ENDPOINT_A_IP];

        if(parent::isValidIndex($args, self::ENDPOINT_B_IP))
            $endptBip = $args[self::ENDPOINT_B_IP];

        if(parent::isValidIndex($args, self::ENDPOINT_A_PORT))
            $endptAport = $args[self::ENDPOINT_A_PORT];

        if(parent::isValidIndex($args, self::ENDPOINT_B_PORT))
            $endptBport = $args[self::ENDPOINT_B_PORT];
            
        //assemble a new Analyzer
        $flow = new \Flows();
        $jobObj = $this->entityManager->find("Jobs",$jobId);
        if(isset($jobObj))     //if id of job is invalid, a null-object will be returned
            $flow->setAssociatedJob($jobObj);
        else
           return array("status"  => "Error",
                        "message" => "The provided '".self::JOB_ID_INDEX."' violates foreign key restrictions. No job found of ID :'$jobId' !"); 

        $flow->setId($id);
        $flow->setEndptAip($endptAip);
        $flow->setEndptBip($endptBip);
        $flow->setEndptAport($endptAport);
        $flow->setEndptBport($endptBport);

        //write to DB
        $this->entityManager->persist($flow);
        $this->entityManager->flush();

        return array("status"  => "Sucess",
                     "message" => "Created flow with ID:".$flow->getId());
    }
    
    public function getLatestSnapshotOfAnalysis($args)
    {
        
    }

    public function getResultOfAnalysis($args)
    {

    }
        
    private function flowToArray($flow)
    {
        $ret = array();
    
        $ret[self::ID_INDEX]        = $flow->getId();
        $ret[self::JOB_ID_INDEX]    = $flow->getAssociatedJob()->getId();
        $ret[self::ENDPOINT_A_IP]   = $flow->getEndptAip();
        $ret[self::ENDPOINT_B_IP]   = $flow->getEndptBip();
        $ret[self::ENDPOINT_A_PORT] = $flow->getEndptAport();
        $ret[self::ENDPOINT_B_PORT] = $flow->getEndptBport();
        
        return $ret;
    }
}
?>
