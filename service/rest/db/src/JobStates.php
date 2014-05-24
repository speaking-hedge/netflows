<?php
/**
 * @Entity @Table(name="job_states")
 **/
class JobStates
{
    /**
     * @Id
     * @GeneratedValue(strategy="SEQUENCE")
     * @Column(type="integer")
     **/
    protected $id;

    /**
     * @Column(type="string", length=100)
     **/
    protected $name;


    public function getId()
    {
        return $this->id;
    }

    public function getName()
    {
        return $this->name;
    }

    public function setId($id)
    {
        $this->id = $id;
    }

    public function setName($name)
    {
        $this->name = $name;
    }
}

?>
