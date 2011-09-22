While DKIM relies on cryptographic signatures, it is quite easy to configure
but it requires the use of *OpenSSL* on the command line (from your web 
server or on any platform).

1. Generate the RSA private key (in the example key size if 384 bits 
which is very small and not very secure but it makes the DNS step easier):
`openssl genrsa -out key.priv 384`
2. Generate the RSA public key from the new RSA private key:
`openssl rsa -in key.priv -out key.pub -pubout -outform PEM`
3. Copy and paste the private & public keys into configuration of this component.
4. Configure the remaining items in component configuration
5. You now have to configure the DNS zone file of your domain.
 

Yii configuration
====
I prefer to keep dkim configuration in separate config/dkim.php file as it
includes big chunks of text (RSA keys) that don't look pretty in main config:
```php
'components' => array(
	...
	'dkim' => include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'dkim.php'),
	...
)
```
And here is config/dkim.php file:
```php
return array(
	'class' => 'ext.dkim.Dkim',
	'open_SSL_pub' => '...',	// Here comes public RSA key
	'open_SSL_priv' => '...',	// Enter private RSA key here
	'domain' => 'domain.com',	// Your domain
	'selector' => '...'		// DKIM record selector
);
```

Usage
====
The basic PHP-DKIM usage for an HTML e-mail is:
```php
$sender='john@example.com';
$headers="From: \"Fresh DKIM Manager\" &lt;$sender&gt>\r\n".
	"To: $to\r\n".
	"Reply-To: $sender\r\n".
	"Content-Type: text/html\r\n".
	"MIME-Version: 1.0";
$headers = Yii::app()->dkim->add($headers,$subject,$body) . $headers;
$result=mail($to,$subject,$body,$headers,"-f $sender");
```

The core function is add() which generates the *DKIM-Signature*: 
heading (which must preceede the other headers)).

