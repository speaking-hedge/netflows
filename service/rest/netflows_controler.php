<?php
namespace Netflows;

require_once 'rest_controler.php';
require_once 'netflows_backend_communicator.php';
require_once 'netflows_file_io.php';
require_once('db/JobsDB.php');
require_once('db/AnalysersDB.php');


/**
 * Controler of the netflows frontend using RESTful design.
 **/
class Controller extends \RESTController //RESTControler is not in global namespace of 'Netflows'
{
    private $backend;
    private $io;

    /**
     * contructor parsing the request URL in order to invoke the proper model
     * @param request the URL the controler was invoked with
     **/
    public function __construct($request)
    {
        parent::__construct($request);

        $this->backend   = new BackendCommunicator();
        $this->io        = new FileIO();
        $this->jobs      = new JobsDB();
        $this->analysers = new AnalysersDB();

        //check for user token...
    }

    protected function accessBackend($method, $args)
    {
        return $this->callMethodOfObject($this->backend, $method, $args);
    }

    protected function fileIO($method, $args)
    {
        return $this->callMethodOfObject($this->io, $method, $args);
    }

    protected function accessJobs($method, $args)
    {
        return $this->callMethodOfObject($this->jobs, $method, $args);
    }

    protected function accessAnalysers($method, $args)
    {
        return $this->callMethodOfObject($this->analysers, $method, $args);
    }

    private function callMethodOfObject($object, $method, $args)
    {
        if(method_exists($object, $method) > 0)
        {
            return $object->{$method}($args);
        }
        return "NoMethodFound : ".$method;
    }
}
?>

