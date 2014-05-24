<?php
namespace Netflows;

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";
require_once "DBConnector.php";

class JobsDB extends \DBConnector
{
    const ID_INDEX              = "id";
    const JOB_STATE_INDEX       = "jobstate";
    const DESCRIPTION_INDEX     = "description";
    const IS_PUBLIC_INDEX       = "ispublic";
    const START_TIME_INDEX      = "started";
    const FINISHED_INDEX        = "finished";
    const PERCENTAGE_DONE_INDEX = "percentage";
    const FILENAME_INDEX        = "filename";
    const FILESIZE_INDEX        = "filesize";
    const T_PACKTES_INDEX       = "packets";
    const T_TIME_MS_INDEX       = "time_ms";
    const ANALYZERS_INDEX       = "analyzers";

    protected $entityManager;

    public function __construct()
    {
         parent::__construct();
    }

    public function __destruct()
    {

    }

    /**
     * Get the last n public jobs (each as a associative array) in an array.
     * @param n the number of jobs to be returned
     **/
    public function lastNJobs($args)
    {
        $n          = 0;
        $ispublic   = 1;

        if(parent::isValidIndex($args, 'numofjobs'))
            $n = $args['numofjobs'];

        if(parent::isValidIndex($args, 'public'))
            $ispublic = $args['public'];

        $jobs = $this->entityManager->getRepository('Jobs')->findBy(array('is_public' => $ispublic),
                                                                    array('started'   => 'ASC'), $n, 0);
        $retArr = array();

       foreach($jobs as $job)
       {
          array_push($retArr, $this->jobToArray($job));
       }

        return $retArr;
    }

    /**
     * Get all jobs (each as a associative array) in an array.
     * No additional parameters needed.
     **/
    public function showAllJobs()
    {
        $jobsRepository = $this->entityManager->getRepository('Jobs');
        $jobs           = $jobsRepository->findAll();

        $retArr = array();

        foreach($jobs as $job)
        {
            array_push($retArr, $this->jobToArray($job));
        }

        return $retArr;
    }

    /**
     * return an associative array representing the attributes of the queried job
     * @param id job-id
     **/
    public function getJob($args)
    {
        if(!parent::isValidIndex($args,self::ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "Invalid or unkwon Job-ID!");
        }

        $job = $this->entityManager->find("Jobs",$args[self::ID_INDEX]);

        if(!empty($job))
        {
            return $this->jobToArray($job);
        }

        return array("status"  => "Error",
                     "message" => "There was no Job associated to the provided ID in the database!");
    }

    /**
     * inserts a job with the porvided attributed into the DB (works with GET or POST)
     * GET-Example: http://localhost/accessjobs/insertJob?id=abcd&jobstate=0&description=Ein%20kleiner%20Testjob.&ispublic=0&percentage=63&filename=test.pcap&filesize=1024&packets=2000&time_ms=384&analyzers=1,3,5
     * @param id            (MANDATORY) the job-id
     * @param jobstate      (MANDATORY) the current state the job is in
     * @param description   a brief descrption of the job
     * @param ispublic      determines whete the job will be marked as a public job
     * @param started       the time the job was started, DateTime
     * @param finished      the time the job was finshed, DateTime
     * @param percentage    the progress of the job
     * @param filename      the name of the pcap-file that is associated with this job
     * @param filesize      the size of the pcap-file that is associated with this job
     * @param packets       ??????
     * @param time_ms       ???? capture time?
     * @param analyzers     the ids of the analyzers used for this job, Note: must be a comma-seperated string
     **/
    public function insertJob($args)
    {
        $id               = null;
        $state            = null;
        $descr            = null;
        $public           = null;
        $start            = null;
        $finished         = null;
        $percentage       = null;
        $filename         = null;
        $filesize         = null;
        $packets          = null;
        $timeMS           = null;
        $analyzersObjsArr = array();

        //some integrity checks first:
        //  a) check if non-NULL values are provided
        //  b) check if ID is a valid primary key
        if(!parent::isValidIndex($args,self::ID_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "An '".self::ID_INDEX."' must be provided!");
        }

        if(!parent::isValidIndex($args,self::JOB_STATE_INDEX))        {
            return array("status"  => "Error",
                         "message" => "A '".self::JOB_STATE_INDEX."' must be provided!");
        }

        $alreadyExistingJob = $this->entityManager->find("Jobs",$args[self::ID_INDEX]);
        if(isset($alreadyExistingJob))
        {
            return array("status"  => "Error",
                         "message" => "The provided ID ('".$args[self::ID_INDEX]."') is already used!");
        }

        //get all provided attributes
        $id    = $args[self::ID_INDEX];
        $state = $args[self::JOB_STATE_INDEX];

        if(parent::isValidIndex($args,self::DESCRIPTION_INDEX))
            $descr = $args[self::DESCRIPTION_INDEX];

        if(parent::isValidIndex($args,self::IS_PUBLIC_INDEX))
            $public = $args[self::IS_PUBLIC_INDEX];

        if(parent::isValidIndex($args,self::START_TIME_INDEX))
            $start = $args[self::START_TIME_INDEX];

        if(parent::isValidIndex($args,self::FINISHED_INDEX))
            $finished = $args[self::FINISHED_INDEX];

        if(parent::isValidIndex($args,self::PERCENTAGE_DONE_INDEX))
            $percentage = $args[self::PERCENTAGE_DONE_INDEX];

        if(parent::isValidIndex($args,self::FILENAME_INDEX))
            $filename = $args[self::FILENAME_INDEX];

        if(parent::isValidIndex($args,self::FILESIZE_INDEX))
            $filesize = $args[self::FILESIZE_INDEX];

        if(parent::isValidIndex($args,self::T_PACKTES_INDEX))
            $packets = $args[self::T_PACKTES_INDEX];

        if(parent::isValidIndex($args,self::T_TIME_MS_INDEX))
            $timeMS = $args[self::T_TIME_MS_INDEX];

        if(parent::isValidIndex($args,self::ANALYZERS_INDEX))
            $analyzers = explode(",",$args[self::ANALYZERS_INDEX]);

        //assemble the new job
        $job = new \Jobs();

        $job->setId($id);

        $jobStateObj = $this->entityManager->find("JobStates",$state);
        if(isset($jobStateObj))     //if id of job-state is invalid, a null-object will be returned
            $job->setJobState($jobStateObj);

        $job->setIsPublic($public);

        $job->setStartTime($start);

        $job->setFinishedTime($finished);

        $job->setPercentageDone($percentage);

        $job->setDescription($descr);

        $job->setFileName($filename);

        $job->setFileSize($filesize);

        $job->setTPackets($packets);

        $job->setTTimeMS($timeMS);

        $associatedAnalysers = $job->getAssociatedAnalyzers();
        for($i = 0; $i < count($analyzers); $i++)
        {
            $analyzer = $this->entityManager->find("Analysers",$analyzers[$i]);
            if(isset($analyzer))    //if id of Analyser is invalid, a null-object will be returned
                $associatedAnalysers->add($analyzer);
        }

        $this->entityManager->persist($job);
        $this->entityManager->flush();

        return array("status"  => "Sucess",
                     "message" => "Created job with ID: '".$job->getId()."'");
    }

    public function updateprogress($args)
    {
        $id         = null;
        $percentage = null;

        if(parent::isValidIndex($args,self::ID_INDEX))
            $id = $args[self::ID_INDEX];

        if(parent::isValidIndex($args,self::PERCENTAGE_DONE_INDEX))
            $percentage = $args[self::PERCENTAGE_DONE_INDEX];

        $job = $this->entityManager->find("Jobs",$id);

        if(!isset($job))
        {
            return array("status"  => "Error",
                         "message" => "Job with ID: '".$id."' not found!");
        }

        if(!isset($percentage) || $percentage < 0)
        {
            return array("status"  => "Error",
                         "message" => "The progress must be set and non-negative!");
        }

        $job->setPercentageDone($percentage);

        $this->entityManager->persist($job);
        $this->entityManager->flush();

        return array("status"  => "Sucess",
                     "message" => "Updated job with ID: '".$job->getId()."'");
    }

    public function updateState($args)
    {
        $jobID   = null;
        $stateID = null;

        if(parent::isValidIndex($args,"jobid"))
            $jobID =  $args["jobid"];

        if(parent::isValidIndex($args,"stateid"))
            $stateID = $args["stateid"];

        $job   = $this->entityManager->find("Jobs",$jobID);
        $state = $this->entityManager->find("JobStates",$stateID);

        if(!isset($job))
        {
            return array("status"  => "Error",
                         "message" => "Job with ID: '".$jobID."' not found!");
        }
        if(!isset($state))
        {
            return array("status"  => "Error",
                         "message" => "Job-State with ID: '".$stateID."' not found!");
        }

        $job->setJobState($state);

        $this->entityManager->persist($job);
        $this->entityManager->flush();

        return array("status"  => "Sucess",
                     "message" => "Updated job with ID: '".$job->getId()."'");
    }

    /**
     * Convertes the provided Jobs-Object into an associative array.
     **/
    private function jobToArray($job)
    {
        $entry = array();
        $entry[self::ID_INDEX]              = $job->getId();
        $entry[self::DESCRIPTION_INDEX]     = $job->getDescription();
        $entry[self::IS_PUBLIC_INDEX]       = $job->isPublic();
        $entry[self::JOB_STATE_INDEX]       = $job->getJobState()->getName();
        $entry[self::START_TIME_INDEX]      = $job->getStartTime();
        $entry[self::FINISHED_INDEX]        = $job->getFinishedTime();
        $entry[self::PERCENTAGE_DONE_INDEX] = $job->getPercentageDone();
        $entry[self::FILENAME_INDEX]        = $job->getFileName();
        $entry[self::FILESIZE_INDEX]        = $job->getFileSize();
        $entry[self::T_PACKTES_INDEX]       = $job->getTPackets();
        $entry[self::T_TIME_MS_INDEX]       = $job->getTTimeMS();

        $analyzers = array();
        foreach($job->getAssociatedAnalyzers() as $analyzer)
            array_push($analyzers, $analyzer->getName());

        $entry[self::ANALYZERS_INDEX] = $analyzers;

        return $entry;
    }
}
?>
