<?php
/**
 * Abstract controller-class to implement the REST pattern.
 * Most parts adopted from:  http://coreymaynard.com/blog/creating-a-restful-api-with-php/
 * Another great blog: http://rest.elkstein.org/2008/01/how-do-i-handle-authentication-in-rest.html
 **/
abstract class RESTController
{
    //the http-verb used for this request
    protected $verb;

    //the model requested by the URL
    protected $requestedClass;

    //additional descriptor about the requestedModel
    protected $requestedMethod;

    //the params followed by the requestedModel(?arg1=xxx&arg2=yyyy etc)
    protected $args = Array();

    //input of the PUT request
    protected $putIN = Null;

    /**
     * contructor parsing the request URL in order to invoke the proper method of the proper model
     * @param request the URL the controler was invoked with
     **/
    public function __construct($request)
    {
        header("Access-Control-Allow-Origin  : *");                 //allow requests from all src-addresses
        header("Access-Control-Allow-Methods : *");                 //allow request for all htttp-verbs
        header("Content-Type                 : application/json");  //define return type of the REST-request

        //extract all the parts of the URL
        $uri = explode('/', rtrim($request, '/'));

        $this->requestedClass  = array_shift($uri);
        if(array_key_exists(0,$uri) && !is_numeric($uri[0]))
        {
            $this->requestedMethod = array_shift($uri);

        }

        //extract the HTTP-verb
        $this->verb = $_SERVER['REQUEST_METHOD'];
        if($this->verb == 'POST' && array_key_exists('HTTP_X_HTTP_METHOD', $_SERVER))
        {
            $this->verb = $_SERVER['HTTP_X_HTTP_METHOD'];
        }

        //set request data according to the determined HTTP-verb
        switch($this->verb)
        {
            case 'GET':
                unset($_GET['request']); //$_GET['request'] contains the 'request' which is not needed as method-argument
                $this->args = $this->preprocessInput($_GET);
            break;

            case 'POST':
                $this->args = $this->preprocessInput($_POST);
            break;

            case 'DELETE':
            break;

            case 'PUT':
                unset($_GET['request']); //$_GET['request'] contains the 'request' which is not needed as method-argument
                $this->args = array_merge_recursive($_GET, array("content" => file_get_contents('php://input')));
            break;

            default:
                $this->response('Invalid HTTP-Verb', 405);
            break;
        }
    }

    //see: http://stackoverflow.com/a/12018482
    /**
     * Creates an respond with the header of the provided status-code & the provided data
     * @param data the data to be sent
     * @param status the status code of the header, default is 200 ('OK')
     **/
    private function response($data, $status = 200)
    {
        if (function_exists('http_response_code'))  //PHP >= 5.4
        {
            http_response_code($status);
        }
        else                                        //PHP >= 4.3
        {
            header("X-PHP-Response-Code: ".$status,true,$status);
        }

        return json_encode($data);
    }

    /**
     * Removes all html/php tags from the provided input string.
     * String-Arrays will be cleaned recursively.
     * @param data string(-array) to be cleaned
     **/
    private function preprocessInput($data)
    {
        $cleaned_input = Array();

        if(is_array($data))
        {
            foreach($data as $key => $value)
            {
                $cleaned_input[$key] = $this->preprocessInput($value);
            }
        }
        else
        {   //remove any html/php tags
            $cleaned_input = trim(strip_tags($data));
        }

        return $cleaned_input;
    }

    /**
     * Invokes a proper method in the derived class passing the extracted arguments.
     * @return Output of the method or error if no proper method could be found
     **/
    public function processRESTCall()
    {
        if(method_exists($this, $this->requestedClass) > 0)
        {
            return $this->response($this->{$this->requestedClass}($this->requestedMethod, $this->args));
        }
        return $this->response("NoClassDefFound : ".$this->requestedClass, 404);
    }
}
?>
