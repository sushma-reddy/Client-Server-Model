<html>
<head>
<title>ECE/CSC 573</title>
<style>
body{
   background: url("image.jpg");
   background-size: 1200px 800px;
   background-repeat: no-repeat;
}
</style>
</head>

<body>

<h1><font color="white" size="12"><center>Welcome to the Server!!</center></font></h1>
<p><font color="white" size="10"><center>IP-573 Project</center></font>
<font color = "white" size="6"><center>
<?php

$ip = $_SERVER['HTTP_CLIENT_IP']?$_SERVER['HTTP_CLIENT_IP']:($_SERVER['HTTP_X_FORWARDE<200c><200b>D_FOR']?$_SERVER['HTTP_X_FORWARDED_FOR']:$_SERVER['REMOTE_ADDR']);
echo "Your IP is $ip <br>\n";

?>
</center></font>


</p>


</body>
</html>


