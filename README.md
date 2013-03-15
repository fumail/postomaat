postomaat
=========

A policy daemon for postfix written in python

This is a  by-product of the [Fuglu](https://github.com/gryphius/fuglu) mailfilter.
While fuglu focuses on scanning a full message (pre- or after-queue), postomaat only uses the message
fields available in the  [Postfix policy access delegation protocol](http://www.postfix.org/SMTPD_POLICY_README.html)
It can therefore make decisions much faster than fuglu, but only based on envelope data (sender adress, recipient adress, client ip etc).
Postomaat can not make decisions based on message headers or body.

Warning: Postomaat currently doesn't receive the same testing as fuglu before commiting to github.
The master branch therefore might or might not work out of the box.  
