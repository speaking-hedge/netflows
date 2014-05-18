<?php
use Doctrine\ORM\Tools\Setup;
use Doctrine\ORM\EntityManager;

require_once "vendor/autoload.php";
require_once "variables.php";

abstract class DBConnector
{
    protected $entityManager;

    /**
     * 1: establishes the databse connection
     * 2: defines the source-directory of the ORM-files for Doctrine
     **/
    public function __construct()
    {
        $isDevMode = true;
        $config    = Setup::createAnnotationMetadataConfiguration(array(__DIR__."/src"), $isDevMode);

        //database configuration parameters
        $con = array(
            'driver'    => DBParams::DRIVER,
            'user'      => DBParams::USER,
            'password'  => DBParams::PASSWORD,
            'dbname'    => DBParams::DBNAME
        );

        $this->entityManager = EntityManager::create($con, $config);
    }

    public function __destruct()
    {

    }

    /**
     * Checks whether the provided index:
     *  a) is present within the provided array
     *  b) will return a non-empty/non-null value
     **/
    protected function isValidIndex($arr, $index)
    {
        if(array_key_exists($index,$arr))
        {
            if(gettype($arr[$index]) == "string")
            {
                return strlen($arr[$index]) > 0;
            }
            else
            {
                return isset($arr[$index]);
            }
        }

        return false;
    }

}
?>
