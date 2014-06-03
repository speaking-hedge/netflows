<?php
namespace Netflows;

require_once "netflows_backend_communicator.php";

/**
 * Communication interface between the PHP front-end application and C back-end application
 **/
class FileIO
{
    const UPLOAD_PATH = "/var/www/html/upload/";

    private $backend;

    public function __construct()
    {
        date_default_timezone_set('Europe/Berlin');

        $this->backend = new BackendCommunicator();
    }

    public function upload($args)
    {
        $filename     = "";
        $filenameHash = "";

        if(array_key_exists("filename", $args))
        {
            $filename = trim($args["filename"]);
        }

        //no filename has been specified: 1: create a generic filename: upload_yyyymmdd_hhmmss_1.pcap
        //                                2: check if a file with that name already exists (most likely a very rare case though)
        if(empty($filename))
        {
            $time = date("His");
            $date = date("Ymd");

            $filename = "upload_".$date."_".$time;

            for($i = 1; file_exists($filename."_".$i.".pcap"); $i++);

            $filename .= "_".$i.".pcap";
        }

        //hash the file-name so noone can do any harm when issuing exec using the file-name
        $filenameHash = md5($filename);

        //check for file content and write to disk
        if(array_key_exists("content",$args))
        {
            //try to upload
            try
            {
                $outputStream = fopen(self::UPLOAD_PATH.$filenameHash, 'w') or die("Cannot open file for writing!");

                fwrite($outputStream, $args["content"]);

                fclose($outputStream);
            }
            catch(Exception $e)
            {
                return array("status"  => "Error",
                             "message" => "There was an I/O error.".$e->getMessage());
            }

            //check if the provided file is a valid pcap
            $jobID = $this->backend->verifyPCAP(self::UPLOAD_PATH.$filenameHash);
            if(!empty($jobID))
            {
                return array("status"    => "Success",
                             "message"   => "File successfully created!",
                             "file-name" => $filename,
                             "file-size" => filesize(self::UPLOAD_PATH.$filenameHash),
                             "job-id"    => $jobID);
            }
            else
            {
                return array("status"  => "Error",
                             "message" => "Invalid PCAP-file uploaded!");
            }

        }

        return array("status"  => "Error",
                     "message" => "No or invalid file content!");

    }
}
?>
