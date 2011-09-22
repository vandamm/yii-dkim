<?php

/* * *************************************************************************\
 *  PHP-DKIM ($Id: dkim.php,v 1.2 2008/09/30 10:21:52 evyncke Exp $)
 *
 *  Copyright (c) 2008
 *  Eric Vyncke
 *
 * This program is a free software distributed under GNU/GPL licence.
 * See also the file GPL.html
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * ************************************************************************* */

/**
 * Class Dkim is a classic PHP DKIM implementation, modified to work as Yii application component.
 * 
 * While DKIM relies on cryptographic signatures, it is quite easy to configure
 * but it requires the use of <b>OpenSSL</b> on the command line
 * (from your web server or on any platform).
 * <ol>
 * <li>Generate the RSA private key (in the example key size if 384 bits which
 * is very small and not very secure but it makes the DNS step easier):<pre>
 * openssl genrsa -out key.priv 384
 * </pre></li>
 * <li>Generate the RSA public key from the new RSA private key:<pre>
 * openssl rsa -in key.priv -out key.pub -pubout -outform PEM
 * </pre></li>
 * <li>Copy and paste the private & public keys into configuration of this component.</li>
 * <li>Configure the remaining items in component configuration</li>
 * <li>You now have to configure the DNS zone file of your domain.
 * The easiest is to have a look into<b>dkim-test.php</b> and call the function
 * <b>BuildDNSTXTRR()</b> from the command line (or through the web). The
 * exact content of a DNS resource record (RR) of type TXT (mandatory) is
 * displayed and must be entered into your zone file. Depending on your
 * DNS server settings, you may have to wait minutes or hours before the change
 * is propagated world-wide.</li>
 * </ol>
 *
 * <h2>Usage/h2>
 * The basic PHP-DKIM usage for an HTML e-mail is:<pre>
 * $sender='john@example.com';
 * $headers="From: \"Fresh DKIM Manager\" &lt;$sender&gt>\r\n".
 *		"To: $to\r\n".
 *		"Reply-To: $sender\r\n".
 *		"Content-Type: text/html\r\n".
 *		"MIME-Version: 1.0";
 * $headers = AddDKIM($headers,$subject,$body) . $headers;
 * $result=mail($to,$subject,$body,$headers,"-f $sender");
 * </pre>
 * The core function is {@link add()} which generates the <b>DKIM-Signature:</b>
 * heading (which must preceede the other headers)).
 */
class Dkim extends CApplicationComponent
{
	/**
	 * @var string Private key
	 */
	public $open_SSL_priv;
	/**
	 * @var string Public key
	 */
	public $open_SSL_pub;
	/**
	 * @var string Domain of the signing entity (i.e. the email domain)
	 */
	public $domain;
	/**
	 * @var string Selector, defines where the public key is stored in the DNS.
	 * You can choose anything there (respecting the DNS syntax -- like	no
	 * white space), it allows you to have several DKIM signers/servers for
	 * the same email domain. DNS record will be: $selector._domainkey.$domain
	 */
	public $selector;
	/**
	 * @var string Default identity
	 * Optional, defaults to no user @$domain
	 */
	public $identity;

	/**
	 * Check if keys are set
	 */
	public function init()
	{
		if ($this->open_SSL_pub == '' || $this->open_SSL_priv == '')
		{
			throw new Exception("DKIM not configured, please run:\n
			\topenssl genrsa -out key.priv 384\n
			\topenssl rsa -in key.priv -out key.pub -pubout -outform PEM\n
			To generate public and private keys");
		}
	}

	/**
	 *
	 * @param string $headers_line Email headers for the message.
	 * These headers need to include Sender.
	 * @param string $subject
	 * @param string $body
	 * @return string Headers for the message, including DKIM signature
	 */
	public function add($headers_line, $subject, $body)
	{
		//??? a tester	$body=str_replace("\n","\r\n",$body) ;
		$DKIM_a = 'rsa-sha1'; // Signature & hash algorithms
		$DKIM_c = 'relaxed/simple'; // Canonicalization of header/body
		$DKIM_q = 'dns/txt'; // Query method
		$DKIM_t = time(); // Signature Timestamp = number of seconds since 00:00:00 on January 1, 1970 in the UTC time zone
		$subject_header = "Subject: $subject";
		$headers = explode("\r\n", $headers_line);
		foreach ($headers as $header)
			if (strpos($header, 'From:') === 0)
				$from_header = $header;
			elseif (strpos($header, 'To:') === 0)
				$to_header = $header;
		$from = str_replace('|', '=7C', $this->QuotedPrintable($from_header));
		$to = str_replace('|', '=7C', $this->QuotedPrintable($to_header));
		$subject = str_replace('|', '=7C', $this->QuotedPrintable($subject_header)); // Copied header fields (dkim-quoted-printable
		$body = $this->SimpleBodyCanonicalization($body);
		$DKIM_l = strlen($body); // Length of body (in case MTA adds something afterwards)
		$DKIM_bh = base64_encode(pack("H*", sha1($body))); // Base64 of packed binary SHA-1 hash of body
		$i_part = !empty($this->identity) ? '' : " i=$this->identity;";
		$b = ''; // Base64 encoded signature
		$dkim = "DKIM-Signature: v=1; a=$DKIM_a; q=$DKIM_q; l=$DKIM_l; s=$this->selector;\r\n" .
			"\tt=$DKIM_t; c=$DKIM_c;\r\n" .
			"\th=From:To:Subject;\r\n" .
			"\td=$this->domain;$i_part\r\n" .
			"\tz=$from\r\n" .
			"\t|$to\r\n" .
			"\t|$subject;\r\n" .
			"\tbh=$DKIM_bh;\r\n" .
			"\tb=";
		$to_be_signed = $this->RelaxedHeaderCanonicalization("$from_header\r\n$to_header\r\n$subject_header\r\n$dkim");
		$b = $this->BlackMagic($to_be_signed);
		return "X-DKIM: php-dkim.sourceforge.net\r\n" . $dkim . $b . "\r\n";
	}

	private function QuotedPrintable($txt)
	{
		$tmp = "";
		$line = "";
		for ($i = 0; $i < strlen($txt); $i++)
		{
			$ord = ord($txt[$i]);
			if (((0x21 <= $ord) && ($ord <= 0x3A))
				|| $ord == 0x3C
				|| ((0x3E <= $ord) && ($ord <= 0x7E)))
				$line.=$txt[$i];
			else
				$line.="=" . sprintf("%02X", $ord);
		}
		return $line;
	}

	private function BlackMagic($s)
	{
		if (openssl_sign($s, $signature, $this->open_SSL_priv))
			return base64_encode($signature);
		else
			throw new Exception("Cannot sign DKIM message");
	}

	private function SimpleHeaderCanonicalization($s)
	{
		return $s;
	}

	private function RelaxedHeaderCanonicalization($s)
	{
		// First unfold lines
		$s = preg_replace("/\r\n\s+/", " ", $s);
		// Explode headers & lowercase the heading
		$lines = explode("\r\n", $s);
		foreach ($lines as $key => $line)
		{
			list($heading, $value) = explode(":", $line, 2);
			$heading = strtolower($heading);
			$value = preg_replace("/\s+/", " ", $value); // Compress useless spaces
			$lines[$key] = $heading . ":" . trim($value); // Don't forget to remove WSP around the value
		}
		// Implode it again
		$s = implode("\r\n", $lines);
		// Done :-)
		return $s;
	}

	private function SimpleBodyCanonicalization($body)
	{
		if ($body == '')
			return "\r\n";

		// Just in case the body comes from Windows, replace all \r\n by the Unix \n
		$body = str_replace("\r\n", "\n", $body);
		// Replace all \n by \r\n
		$body = str_replace("\n", "\r\n", $body);
		// Should remove trailing empty lines... I.e. even a trailing \r\n\r\n
		// TODO
		while (substr($body, strlen($body) - 4, 4) == "\r\n\r\n")
			$body = substr($body, 0, strlen($body) - 2);
		//	NiceDump('SimpleBody',$body) ;
		return $body;
	}

}