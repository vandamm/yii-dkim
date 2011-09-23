Yii DKIM wrapper
===

This project is a wrapper of [PHP-DKIM library](http://php-dkim.sourceforge.net/) as a component for usage in conjunction with Yii framework. Nthing new, just convenient.

## Installation

While DKIM relies on cryptographic signatures, it is quite easy to configure but it requires the use of *OpenSSL* on the command line (from your web server or on any platform).

1. Extract [yii-dkim](/VanDamm/yii-dkim/) from archive to your application's extension directory
1. Generate the RSA private key (in the example key size is 384 bits 
which is very small and not very secure):
`openssl genrsa -out key.priv 384`
1. Generate the RSA public key from the new RSA private key:
`openssl rsa -in key.priv -out key.pub -pubout -outform PEM`
1. Copy and paste the private & public keys into configuration of this component.
1. Configure the remaining items in component configuration
1. Configure the DNS zone file of your domain.
 

## Configuration

I prefer to keep dkim configuration in separate config/dkim.php file as it
includes big chunks of text (RSA keys) that don't look pretty in main config:

```php
<?php
// ...
	'components' => array(
		// ...
		'dkim' => include(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'dkim.php'),
		// ...
	)
```

And here is config/dkim.php file:

```php
<?php
return array(
	'class' => 'ext.dkim.Dkim',
	'open_SSL_pub' => '...',	// Here comes public RSA key
	'open_SSL_priv' => '...',	// Enter private RSA key here
	'domain' => 'domain.com',	// Your domain
	'selector' => '...'		// DKIM record selector
);
```

## Usage
The basic PHP-DKIM usage for an HTML e-mail is:

```php
<?php
$sender = 'john@example.com';
$headers = "From: \"Fresh DKIM Manager\" &lt;$sender&gt>\r\n".
"To: $to\r\n".
	"Reply-To: $sender\r\n".
	"Content-Type: text/html\r\n".
	"MIME-Version: 1.0";
$headers = Yii::app()->dkim->add($headers,$subject,$body) . $headers;
$result = mail($to,$subject,$body,$headers,"-f $sender");
```

The core function is add() which generates the *DKIM-Signature*: 
heading (which must preceede the other headers)).


## Additional information
* [DKIM standard](http://dkim.org/#sign)
* [A great article on delivering email, sent from code](http://www.codinghorror.com/blog/2010/04/so-youd-like-to-send-some-email-through-code.html)
