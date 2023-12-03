# Work of Emails

## Introduction :

Recently i started the HTB penetration tester path and i stumbled upon some protocols dedicated only to managing emails, i felt weird. Why there is a protocol dedicated only to sending emails? Why not work with http(s) protocols? How does it work? How to send an email? How to pentest it?

So I will try to write what i understood from it in this post.

## Why there is a protocol for emails?

This was a question that my curious mind won't move on from. It may or may not benefit you in your cyber security journey but i tried to research for it.

SMTP is the main protocol used to transfer emails, so why not use HTTP.

First of all, SMTP was in use before HTTP, which caused the mail infrastructure to rely heavily on SMTP, so there was no time to think about it anyway 🙂.

But still there is diffrences in the philosophy of them both.

|                                                                                                 SMTP                                                                                                |                                            HTTP                                           |
| :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------: |
|                                                                 SMTP is a push protocol, its work is to push mail onto a mail server                                                                |           HTTP is used to pull data from a server, like web pages, images, etc.           |
| Email messages have a specific structure that includes various header fields, message body, attachments, and more. SMTP is specifically designed to handle and process these components efficiently | HTTP, does not have built-in support for the structured representation of email messages. |

You may argue that using POST/PUT methods in HTTP are adding the functionality to push data into a server and we can configure a server to understand emails over HTTP, so don't worry about it, just take the first reason (That's what i did).

## How does it work?

SMTP is the protocol responsible for trasmission of the mails over TCP connection, its default port are 25 (SMTP) or 587 (SMTPS) SMTP over TLS/SSL.

```
    +-----------------+                                +-------------------+
    |   Mail Client   |                                |    Mail Server    |
    +-----------------+                                +-------------------+
           |                                                   |
           |          TCP/IP Connection (Port 25)              |
           |<------------------------------------------------->|
           |             Greeting and Handshaking              |
           |              (EHLO/HELO commands)                 |
           |<------------------------------------------------->|
           |                                                   |
           |          Sender and Recipient Configuration       |
           |            (MAIL FROM, RCPT TO commands)          |
           |-------------------------------------------------->|
           |                                                   |
           |                Message Transmission               |
           |                   (DATA command)                  |
           |                 +-----------------+               |
           |                 |    Email Body   |               |
           |                 +-----------------+               |
           |-------------------------------------------------->|
           |                                                   |
           |                Message Routing (DNS)              |
           |                                                   |
           |                                                   |
           |          Response and Status Codes (2xx, 4xx, 5xx)|
           |<--------------------------------------------------|
           |                                                   |
           |                      Termination                  |
           |                      (QUIT command)               |
           |<------------------------------------------------->|
           |                                                   |
           |                TCP/IP Connection Close            |
           |<------------------------------------------------->|
```

Indeed, we have postponed discussing IMAP and POP3 until now because these protocols come into play after the SMTP process is completed. Once the SMTP protocol successfully delivers the outgoing email to the recipient's mail server, the focus then shifts to the retrieval of incoming email. This is where IMAP and POP3 protocols step in to facilitate email retrieval and management on the client side.

IMAP default port is 143 or 993 TLS/SSL.

POP default port is 110 or 995 over TLS/SSL.

## How to send an email?

Using SMTP we can connect to the SMTP server via telnet

```shell
Mabenchi@space[/space]$  telnet <IP> 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

```

After connecting to the server, we have some commands that we could use to interact with it.

|   Command  |                                            Description                                           |
| :--------: | :----------------------------------------------------------------------------------------------: |
| AUTH PLAIN |                   AUTH is a service extension used to authenticate the client.                   |
|    HELO    |              The client logs in with its computer name and thus starts the session.              |
|  MAIL FROM |                                The client names the email sender.                                |
|   RCPT TO  |                               The client names the email recipient.                              |
|    DATA    |                        The client initiates the transmission of the email.                       |
|    RSET    | The client aborts the initiated transmission but keeps the connection between client and server. |
|    VRFY    |                 The client checks if a mailbox is available for message transfer.                |
|    EXPN    |         The client also checks if a mailbox is available for messaging with this command.        |
|    NOOP    |     The client requests a response from the server to prevent disconnection due to time-out.     |
|    QUIT    |                                The client terminates the session.                                |

```shell
Mabenchi@space[/space]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO domain.com

250-mail1.domain.com
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@domain.com>

250 2.1.0 Ok


RCPT TO: <mrb3n@domain.com> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@domain.com>
To: <mrb3n@domain.com>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

## How to pentest it?

For SMTP, we gonna discuss two major misconfigurations.

### Open Relay Configuration

```
mynetworks = 0.0.0.0/0
```

This configuration allow connection from any IP address to send email relayed to another domain from your server, this can be a security risk as it allows an attacker to abuse the server. Since an unknown user can send mails thru your server. This can let him send spam emails thru your SMTP server to other servers in internet.

Sending spam email relayed from the vurlnerable server may lead to blacklisting of this server and any email coming from it will be discarded.

The correct configuration should be to accept only email that are sent to your domain/network.

```
mynetworks = <Network IP>
```

### Email spoofing

As we saw from the diagram before SMTP uses MAIL FROM, RCPT TO commands for to configure the sender and receiver of the mail.

But still there is another fields that contains the from and to addresses exsiting on the message body, this fields are whats shown on the mailbox.

```shell
Mabenchi@space[/space]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO domain.com

250-mail1.domain.com
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@domain.com>

250 2.1.0 Ok


RCPT TO: <mrb3n@domain.com> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <support@facebook.com>
To: <mrb3n@domain.com>
Subject: Reset password
Date: Tue, 28 Sept 2021 16:32:51 +0200
Send me your password this is my facebook mark
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

Notice the diffrence between the email passed to 'MAIL FROM' command and the email address passed to 'From' field.

This mail will be display to the client as if the mail is from the trusted domain facebook.com.

This feels like an overpower, but this still doesn't work if the DNS server of the domain is configured correctly by adding the SPF check.

#### SPF

This is a configuration that facebook.com should have on there DNS, when the receiption server receives the mail, it checks the 'From' field on the message body, what does it checking exactly?

If there is no SPF, the mail will try to check if the IP of the sender is in fact from the facebook.com domain but since there is no SPF, it has no bassis to determine if the IP reliable or not.

The SPF is a bunch of IPs added by the facebook.com domain to state the IPs that can send @facebook.com mails.

In this scenario your IP will be different and the mail either it will get rejected or put on spam/junk mails.
