<?php
namespace Netflows;
/**
 * Communication interface between the PHP front-end application and C back-end application
 **/
class FileIO
{
    const UPLOAD_PATH = "../upload/";

    public function __construct()
    {
        date_default_timezone_set('Europe/Berlin');
    }

    public function upload($args)
    {
        $filename = "";
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

        //check for file content and write to disk
        if(array_key_exists("content",$args))
        {
            try
            {
                $outputStream = fopen(self::UPLOAD_PATH.$filename, 'w') or die("Cannot open file for writing!");
                
                fwrite($outputStream, $args["content"]);

                fclose($outputStream);

                return array("status"  => "Success",
                             "message" => "File successfully created!");
            }
            catch(Exception $e)
            {
                return array("status"  => "Error",
                             "message" => "There was an I/O error.".$e->getMessage());            
            }
        }

        return array("status"  => "Error",
                     "message" => "No or invalid file content!");

    }
}
?>
