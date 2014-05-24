<?php
/**
 * @Entity @Table(name="flows")
 **/
class Flows
{
    /**
     * @Id
     * @Column(type="integer", nullable=FALSE)
     **/
    protected $id;

    /**
     * @OneToOne(targetEntity="Jobs")
     * @JoinColumn(name="job_id", referencedColumnName="id")
     **/
    protected $job_id;

    /**
     * @Column(type="string", length=100, nullable=TRUE)
     **/
    protected $ep_a_ip;

    /**
     * @Column(type="string", length=100, nullable=TRUE)
     **/
    protected $ep_b_ip;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $ep_a_port;

    /**
     * @Column(type="integer", nullable=TRUE)
     **/
    protected $ep_b_port;


    public function getId()
    {
        return $this->id;
    }

    public function getAssociatedJob()
    {
        return $this->job_id;
    }

    public function getEndptAip()
    {
        return $this->ep_a_ip;
    }

    public function getEndptBip()
    {
        return $this->ep_b_ip;
    }

    public function getEndptAport()
    {
        return $this->ep_a_port;
    }

    public function getEndptBport()
    {
        return $this->ep_a_port;
    }
    public function setId($id)
    {
        $this->id = $id;
    }

    public function setAssociatedJob($job_id)
    {
        $this->job_id = $job_id;
    }

    public function setEndptAip($endpt_a_ip)
    {
        $this->ep_a_ip = $endpt_a_ip;
    }

    public function setEndptBip($endpt_b_ip)
    {
        $this->ep_b_ip = $endpt_b_ip;
    }

    public function setEndptAport($endpt_a_port)
    {
        $this->ep_a_port = $endpt_a_port;
    }

    public function setEndptBport($endpt_b_port)
    {
        $this->ep_b_port = $endpt_b_port;
    }
}

?>