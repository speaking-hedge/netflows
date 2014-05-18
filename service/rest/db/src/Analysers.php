<?php
/**
 * @Entity @Table(name="analysers")
 **/
class Analysers
{
    /**
     * @Id
     * @GeneratedValue(strategy="AUTO")
     * @Column(type="integer")
     **/
    protected $id;

    /**
     * @Column(type="datetime", nullable=TRUE)
     **/
    protected $created;

    /**
     * @Column(type="smallint", nullable=TRUE)
     **/
    protected $is_active;

    /**
     * @Column(type="string", length=100)
     **/
    protected $name;

    /**
     * @Column(type="string", nullable=TRUE)
     **/
    protected $description;

    /**
     * @Column(type="string", length=100, nullable=TRUE)
     **/
    protected $icon;

    /**
     * @Column(type="string", length=45)
     **/
    protected $pp_cmd_flag;


    public function getId()
    {
        return $this->id;
    }

    public function getCreationDate()
    {
        return $this->created;
    }

    public function isActive()
    {
        return $this->is_active;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getDescription()
    {
        return $this->description;
    }


    public function getIconLocation()
    {
        return $this->icon;
    }

    public function getAssociatedPacketProcessorFlag()
    {
        return $this->pp_cmd_flag;
    }

    public function setId($id)
    {
        $this->id = $id;
    }

    public function setCreationDate($date)
    {
        $this->created = $date;
    }

    public function setIsActive($is_active)
    {
        $this->is_active = $is_active;
    }

    public function setName($name)
    {
        $this->name = $name;
    }

    public function setDescription($description)
    {
        $this->description = $description;
    }

    public function setIconLocation($icon)
    {
        $this->icon = $icon;
    }

    public function setAssociatedPacketProcessorFlag($flag)
    {
        $this->pp_cmd_flag = $flag;
    }


}

?>
