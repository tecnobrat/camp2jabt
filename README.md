THIS IS HEAVILY UNDER DEVELOPMENT.  IT WORKS BUT HAS BUGS.  NEEDS SERIOUS CLEANUP.

Push requests are welcome however.




Introduction
------------

camp2jabt is an xmpp transport that exposes your campfire so jabber clients can view
channels inside their jabber client.

camp2jabt is based off of code from rmailt which was created by Eric Butler and
is licensed under the GPLv3 or later.

camp2jabt is written by Brian Stolz and is also released under GPLv3 or later.

Installation
------------

`gem install dm-core xmpp4r SyslogLogger dm-timestamps dm-sqlite-adapter dm-migrations tinder i18n json`

Currently it is not a gem itself, but I will be changing that shortly.

For now, simply change to the lib directory and run `sh ../bin/camp2jabt`.

That will be changed once its a properly bundled gem.

Configuring ejabberd
--------------------

Ejabberd needs to be configured for the new transport. Find the _Listened ports_
section and add the following inside the `{listen, [` array:

    % Campfire Transport
    {5348, ejabberd_service, [{host, "campfire.xmpp.example.com",
                            [{password, "letmein"}]}]},

Set the port, host (this is the transport's _JID_), and password appropriately
and keep them handy. You'll need to enter these same values into the camp2jabt
configuration file next.

Configuration camp2jabt
--------------------

After installing the package, you'll need to configure it.

Create a file called "/etc/camp2jabt.yml" with the following:

    ---
    :data_dir:
      "/var/lib/camp2jabt/"
    :server:
      "xmpp.example.com"
    :port:
      5348
    :jid:
      "campfire.xmpp.example.com"
    :secret:
      "letmein"

Edit the server, secret, port and jid to match the settings you used in your ejabberd config.

Todo
----

* EventMachine support instead of threads (ewww)
* Proper tests
* Channel history support
* Code cleanup


Usage
-----

Once the transport is successfully connected to your XMPP server, open your
client's service discovery window and look for _Campfire Transport_. Select it and
click _Register_. Then you need to enter your campfire information. You only need
to register once.

After you are registered, relogin to your jabber server (unless you got the channel invite).
The jabber server should automatically invite you to the campfire channel.

Any messages sent to this channel will be sent to the campfire room.  Also any messages sent
to the campfire room will be sent to the jabber channel.