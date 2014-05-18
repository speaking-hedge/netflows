<?php
/**
 * @Entity @Table(name="jobs")
 **/
class Jobs
{
    /**
     * @Id
     * @Column(type="string", length=100)
     **/
    protected $id;

    /**
     * @OneToOne(targetEntity="JobStates")
     * @JoinColumn(name="job_state_id", referencedColumnName="id")
     **/
    protected $job_state_id;

    /**
     * @Column(type="smallint", nullable=TRUE)
     **/
    protected $is_public;

    /**
     * @Column(type="datetime", nullable=TRUE)
     **/
    protected $started;

    /**
     * @Column(type="datetime", nullable=TRUE)
     **/
    protected $finished;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $percent_done;

    /**
     * @Column(type="string", length=100, nullable=TRUE)
     **/
    protected $description;

    /**
     * @Column(type="string", length=100, nullable=TRUE)
     **/
    protected $filename;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $filesize;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $t_packets;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $t_time_ms;

    /**
     * @ManyToMany(targetEntity="Analysers")
     * @JoinTable(name="analysers_jobs",
     *            joinColumns={
     *                  @JoinColumn(name="job_id", referencedColumnName="id")},
     *            inverseJoinColumns={
     *                 @JoinColumn(name="analyzer_id", referencedColumnName="id")}
     *          )
     **/
    protected $associated_analyzers;

    public function __construct() {
        $this->associated_analyzers = new \Doctrine\Common\Collections\ArrayCollection();
    }

    public function getId()
    {
        return $this->id;
    }

    public function getJobState()
    {
        return $this->job_state_id;
    }

    public function isPublic()
    {
        return $this->is_public;
    }

    public function getStartTime()
    {
        return $this->started;
    }

    public function getFinishedTime()
    {
        return $this->finished;
    }

    public function getPercentageDone()
    {
        return $this->percent_done;
    }

    public function getDescription()
    {
        return $this->description;
    }

    public function getFileName()
    {
        return $this->filename;
    }

    public function getFileSize()
    {
        return $this->filesize;
    }

    public function getTPackets()
    {
        return $this->t_packets;
    }

    public function getTTimeMS()
    {
        return $this->t_time_ms;
    }

    public function getAssociatedAnalyzers()
    {
        return $this->associated_analyzers;
    }

    public function setId($id)
    {
        $this->id = $id;
    }

    public function setJobState($job_state_id)
    {
        $this->job_state_id = $job_state_id;
    }

    public function setIsPublic($is_public)
    {
        $this->is_public = $is_public;
    }

    public function setStartTime($started)
    {
        $this->started = $started;
    }

    public function setFinishedTime($finished)
    {
        $this->finished = $finished;
    }

    public function setPercentageDone($percent_done)
    {
        $this->percent_done = $percent_done;
    }

    public function setDescription($description)
    {
        $this->description = $description;
    }

    public function setFileName($filename)
    {
        $this->filename = $filename;
    }

    public function setFileSize($filesize)
    {
        $this->filesize = $filesize;
    }

    public function setTPackets($t_packets)
    {
        $this->t_packets = $t_packets;
    }

    public function setTTimeMS($t_time_ms)
    {
        $this->t_time_ms = $t_time_ms;
    }

    //~ public function setAssociatedAnalyzers($analyzers)
    //~ {
        //~ $this->associated_analyzers = $analyzers;
    //~ }

}

?>
