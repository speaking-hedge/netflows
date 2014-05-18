<?php
/**
 * @Entity @Table(name="analysers_jobs")
 **/
class AnalysersJobs
{
    /**
     * @Id
     * @Column(type="string", length=100)
     **/
    protected $job_id;

    /**
     * @Column(type=integer)
     **/
    protected $analyzer_id;


    public function getJobId()
    {
        return $this->job_id;
    }

    public function getAnalyzerId()
    {
        return $this->analyzer_id;
    }

    public function setJobId($job_id)
    {
        $this->job_id = $job_id;
    }

    public function setAnalyzerId($analyzer_id)
    {
        $this->analyzer_id = $analyzer_id;
    }
}

?>
