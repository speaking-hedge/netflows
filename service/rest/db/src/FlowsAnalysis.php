<?php
/**
 * @Entity @Table(name="flows_analysis")
 **/
class FlowsAnalysis
{
    /**
     * @Id
     * @OneToOne(targetEntity="Jobs")
     * @JoinColumn(name="job_id", referencedColumnName="id")
     **/
    protected $job_id;
    
    /**
     * @Id
     * @OneToOne(targetEntity="Flows")
     * @JoinColumn(name="flow_id", referencedColumnName="id")
     **/   
     protected $flow_id;

     /**
      * @Id
      * @OneToOne(targetEntity="Analysers")
      * @JoinColumn(name="analyzer_id", referencedColumnName="id")
      **/
     protected $analyzer_id;

    /**
     * @Id
     * @Column(type="integer")
     **/
    protected $snapshot_id;
     
    /**
     * @Column(type="datetime", nullable=FALSE)
     **/
    protected $created;
    
    /**
     *@Column(type="text", nullable=TRUE)
     **/
    protected $data;

    public function getAssociatedJob()
    {
        return $this->job_id;
    }

    public function getAssociatedFlow()
    {
        return $this->flow_id;
    }

    public function getAssociatedAnalyzer()
    {
        return $this->analyzer_id;
    }

    public function getSnapshotId()
    {
        return $this->snapshot_id;
    }

    public function getCreationDate()
    {
        return $this->created;
    }
    
    public function getData()
    {
        return $this->data;
    }
    
    public function setAssociatedJob($job_id)
    {
        $this->job_id = $job_id;
    }

    public function setAssociatedFlow($flowid)
    {
        $this->flow_id = $flowid;
    }

    public function setSnapshotId($snapshot)
    {
        $this->snapshot_id = $snapshot;
    }

    public function setData($data)
    {
        $this->data = $data;
    }

    public function setAssociatedAnalyzer($analyzer)
    {
        $this->analyzer_id = $analyzer;
    }
    
    public function setCreationDate($date)
    {
        $this->created = $date;
    }
}
?>