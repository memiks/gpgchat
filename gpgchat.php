<?php
/*
GPGChat a GPG Chat Encrypted (http://www.memiks.fr/)
Adapted from ZeroBin - a zero-knowledge paste bin
Please Also see ZeroBin project page: http://sebsauvage.net/wiki/doku.php?id=php:zerobin
*/
$VERSION='Alpha 0.01';
//if (version_compare(PHP_VERSION, '5.2.6') < 0) die('ZeroBin requires php 5.2.6 or above to work. Sorry.');
//require_once "lib/serversalt.php";
require_once "lib/vizhash_gd_zero.php";
require_once "lib/gpgchat.php";

if (!empty($_POST['chat']) || !empty($_POST['user'])) // Create new message/user
{
    /* POST contains:
         data (mandatory) = json encoded SJCL encrypted text (containing keys: user,mess,time)
            OR
         user (mandatory) = json encoded SJCL encrypted text (containing keys: user,pubkey)
    */

    header('Content-type: application/json');
    $error = false;

    // Create storage directory if it does not exist.
    if (!is_dir('data'))
    {
        mkdir('data',0705);
        file_put_contents('data/.htaccess',"Allow from none\nDeny from all\n");
    }
    
    if(!empty($_POST['chat']) && validSJCLChat($_POST['chat'])) { 

    } else if (!empty($_POST['user']) && validSJCLUser($_POST['user'])) { 

    } else {
        die("Error JSON is not valid !");
    }
    

}

