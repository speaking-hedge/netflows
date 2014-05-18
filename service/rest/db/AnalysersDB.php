<?php
namespace Netflows;

use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";
require_once "DBConnector.php";

class AnalysersDB extends \DBConnector
{
    const ID_INDEX            = "id";
    const CREATION_DATE_INDEX = "created";
    const IS_ACTIVE_INDEX     = "isactive";
    const NAME_INDEX          = "name";
    const DESCRIPTION_INDEX   = "description";
    const ICON_INDEX          = "icon";
    const PP_CMD_FLAG_INDEX   = "cmd_flag";

    protected $entityManager;

    public function __construct()
    {
         parent::__construct();
    }

    public function __destruct()
    {

    }

    /**
     * Get all analyzers (each as a associative array) in an array.
     * No additional parameters needed.
     **/
    public function showAllAnalysers()
    {
        $analysersRepository = $this->entityManager->getRepository('Analysers');
        $analysers           = $analysersRepository->findAll();

        $retArr = array();

        foreach($analysers as $analyser)
        {
            $entry = array();
            $entry[self::NAME_INDEX]        = $analyser->getName();
            $entry[self::DESCRIPTION_INDEX] = $analyser->getDescription();
            array_push($retArr, $entry);
        }

        return $retArr;
    }

   /**
     * inserts an analyzer with the porvided attributed into the DB (works with GET or POST)
     * @param name          (MANDATORY) the job-id
     * @param cmd_flag      (MANDATORY) the flag that will be used by the packet-processor to identify this analyzer
     * @param description   a brief description of the job
     * @param isactive      determines wheter the analyzer is available
     * @param created       the time the analyzer was created, DateTime
     **/
    public function registerAnalyzer($args)
    {
        $name     = null;
        $flag     = null;
        $isActive = null;
        $descr    = null;
        $icon     = null;

        //some integrity checks first: check if non-NULL values are provided
        if(!parent::isValidIndex($args, self::NAME_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::NAME_INDEX."' must be provided!");
        }

        if(!parent::isValidIndex($args, self::PP_CMD_FLAG_INDEX))
        {
            return array("status"  => "Error",
                         "message" => "A '".self::PP_CMD_FLAG_INDEX."' must be provided!");
        }

        //retrieve all provided data
        $name = $args[self::NAME_INDEX];
        $flag = $args[self::PP_CMD_FLAG_INDEX];

        if(parent::isValidIndex($args, self::IS_ACTIVE_INDEX))
            $isActive = $args[self::IS_ACTIVE_INDEX];

        if(parent::isValidIndex($args, self::DESCRIPTION_INDEX))
            $descr = $args[self::DESCRIPTION_INDEX];

        if(parent::isValidIndex($args, self::ICON_INDEX))
            $icon = $args[self::ICON_INDEX];

        //assemble a new Analyzer
        $analyser = new \Analysers();
        $analyser->setName($name);
        $analyser->setAssociatedPacketProcessorFlag($flag);
        $analyser->setCreationDate(new \DateTime("now"));
        $analyser->setIsActive($isActive);
        $analyser->setDescription($descr);
        $analyser->setIconLocation($icon);

        //write to DB
        $this->entityManager->persist($analyser);
        $this->entityManager->flush();

        return array("status"  => "Sucess",
                     "message" => "Created analyser with ID:".$analyser->getId());
    }
}
?>
