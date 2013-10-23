<?php

// In case stupid admin has left magic_quotes enabled in php.ini:
if (get_magic_quotes_gpc())
{
    function stripslashes_deep($value) { $value = is_array($value) ? array_map('stripslashes_deep', $value) : stripslashes($value); return $value; }
    $_POST = array_map('stripslashes_deep', $_POST);
    $_GET = array_map('stripslashes_deep', $_GET);
    $_COOKIE = array_map('stripslashes_deep', $_COOKIE);
}

// trafic_limiter : Make sure the IP address makes at most 1 request every 10 seconds.
// Will return false if IP address made a call less than 10 seconds ago.
function trafic_limiter_canPass($ip)
{
    $tfilename='./data/trafic_limiter.php';
    if (!is_file($tfilename))
    {
        file_put_contents($tfilename,"<?php\n\$GLOBALS['trafic_limiter']=array();\n?>");
        chmod($tfilename,0705);
    }
    require $tfilename;
    $tl=$GLOBALS['trafic_limiter'];
    if (!empty($tl[$ip]) && ($tl[$ip]+10>=time()))
    {
        return false;
        // FIXME: purge file of expired IPs to keep it small
    }
    $tl[$ip]=time();
    file_put_contents($tfilename, "<?php\n\$GLOBALS['trafic_limiter']=".var_export($tl,true).";\n?>");
    return true;
}

/* Convert paste id to storage path.
   The idea is to creates subdirectories in order to limit the number of files per directory.
   (A high number of files in a single directory can slow things down.)
   eg. "f468483c313401e8" will be stored in "data/f4/68/f468483c313401e8"
   High-trafic websites may want to deepen the directory structure (like Squid does).

   eg. input 'e3570978f9e4aa90' --> output 'data/e3/57/'
*/
function dataid2path($dataid)
{
    if (!is_dir('data/'.substr($dataid,0,2))) { mkdir('data/'.substr($dataid,0,2)); }
    if (!is_dir('data/'.substr($dataid,0,2).'/'.substr($dataid,2,2))) { mkdir('data/'.substr($dataid,0,2).'/'.substr($dataid,2,2)); }

    return 'data/'.substr($dataid,0,2).'/'.substr($dataid,2,2).'/';
}

/* Convert paste id to discussion storage path.
   eg. 'e3570978f9e4aa90' --> 'data/e3/57/e3570978f9e4aa90.discussion/'
*/
//function dataid2discussionpath($dataid)
//{
//    return dataid2path($dataid).$dataid.'.discussion/';
//}

// Checks if a json string is a proper SJCL encrypted message.
// False if format is incorrect.
function validSJCLChat($jsonstring)
{
    $accepted_keys=array('user','mess','time');

    // Make sure content is valid json
    $decoded = json_decode($jsonstring);
    if ($decoded==null) { return false; }

    $decoded = (array)$decoded;

    // Make sure required fields are present
    foreach($accepted_keys as $k)
    {
        if (!array_key_exists($k,$decoded))  { return false; }
    }

    // Make sure some fields are base64 data
    if (base64_decode($decoded['user'],$strict=true)==null) { return false; }
    if (base64_decode($decoded['mess'],$strict=true)==null) { return false; }
    if (base64_decode($decoded['time'],$strict=true)==null) { return false; }

    // Make sure no additionnal keys were added.
    if (count(array_intersect(array_keys($decoded),$accepted_keys))!=3) { return false; }

    return true;
}

// Checks if a json string is a proper SJCL encrypted user.
// False if format is incorrect.
function validSJCLUser($jsonstring)
{
    $accepted_keys=array('user','pubkey');

    // Make sure content is valid json
    $decoded = json_decode($jsonstring);
    if ($decoded==null) { return false; }

    $decoded = (array)$decoded;

    // Make sure required fields are present
    foreach($accepted_keys as $k)
    {
        if (!array_key_exists($k,$decoded))  { return false; }
    }

    // Make sure some fields are base64 data
    if (base64_decode($decoded['user'],$strict=true)==null) { return false; }
    if (base64_decode($decoded['pubkey'],$strict=true)==null) { return false; }

    // Make sure no additionnal keys were added.
    if (count(array_intersect(array_keys($decoded),$accepted_keys))!=2) { return false; }

    return true;
}

// Delete a chat and its attachments
// Input: $chatid : the chat identifier.
function deleteChat($chatid)
{
    // Delete the chat itself
    unlink(dataid2path($chatid).$chatid);

    // Delete attachments if they exist.
    $discdir = dataid2discussionpath($chatid);
    if (is_dir($discdir))
    {
        // Delete all files in attachment directory
        $dhandle = opendir($discdir);
        while (false !== ($filename = readdir($dhandle)))
        {
            if (is_file($discdir.$filename))  unlink($discdir.$filename);
        }
        closedir($dhandle);

        // Delete the attachment directory.
        rmdir($discdir);
    }
}

