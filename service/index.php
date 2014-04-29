<?php
	echo "test running static compiled packet processor called by php...<br><br>";
	exec("cgi-bin/packet-processor-static upload/small.pcap", $output);
	foreach($output as $out){
    		echo "$out<br />";
	}
?>

