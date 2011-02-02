# Camp2Jabt - An XMPP<->Email transport written in ruby.
# Copyright (C) 2011  Brian Stolz <brian@tecnobrat.com>
# Based on rMailt - An XMPP<->Email transport written by
# Eric Butler <eric@extremeboredom.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


PID_FILE = '/var/run/camp2jabt/camp2jabt.pid'

begin
require 'rubygems'
rescue LoadError
end

require 'optparse'
require 'syslog'
require 'syslog_logger'
require 'yaml'
require 'dm-core'
require 'dm-migrations'
require 'xmpp4r'
require 'xmpp4r/discovery'
require 'xmpp4r/rexmladdons'
require 'xmpp4r/muc'
require 'json'
require 'tinder'
require 'camp2jabt/indifferent_access'

require 'camp2jabt/campfire_watcher'
require 'camp2jabt/stringextensions'
require 'camp2jabt/register'
require 'camp2jabt/gateway'
require 'camp2jabt/user'
require 'camp2jabt/daemonize'

include Daemonize

include Jabber::Discovery
include Jabber::Dataforms

class Camp2JabT
  attr_reader :config
  
  def initialize()
    # Parse command line options
    @options = { :config => '/etc/camp2jabt.yml' }
    OptionParser.new do |opts|
      opts.banner = "Usage: camp2jabt [options]"
      opts.on("--debug", "Enable debug output") do |d|
        @options[:debug] = d
      end    
      opts.on("-d", "--daemon", "Run as a background dameon") do |d|
        @options[:daemon] = d
      end    
      opts.on("--config CONFIGFILE", "Specify configuration file (defaults to /etc/camp2jabt.yml)") do |c|
        @options[:config] = c
      end
    end.parse!

    # Set up debug logging if enabled
    if @options[:debug] == true
      Jabber::debug = true
      DataMapper::Logger.new(STDOUT, :debug)
      Jabber.logger.info('Debug Enabled')
    end
    
    Jabber.logger.info('Initializing...')
  
    # Read configuration file
    @config = YAML::load_file(@options[:config])
    
    # Load users database
    db_path = File.join(@config[:data_dir], 'camp2jabt.db')
    DataMapper.setup(:default, "sqlite3:#{db_path}")
    User.auto_upgrade! # XXX This might not be safe!
    
    # Create component
    jid = @config[:jid]
    @component = Jabber::Component.new(jid)
    
    # Create service discovery responder
    @disco_responder = Jabber::Discovery::Responder.new(@component)
    @disco_responder.identities = [
      Identity.new('conference', 'Campfire Chat', 'text')    
    ]
    @disco_responder.add_features([
      'http://jabber.org/protocol/disco',
      'jabber:iq:register',
      'http://jabber.org/protocol/muc',
      'muc_public'
    ])
    
    # Create registration responder
    @register_responder = Jabber::Register::Responder.new(@component)
    @register_responder.instructions = "Please enter your campfire credentials.  URL should be your subdomain for example dev.campfirenow.com should be 'dev'.  Password should be your API token"
    @register_responder.add_field(:url, true) { |a| true }
    @register_responder.add_field(:password, true) { |a| true }
    @register_responder.add_registered_callback() do |jid, fields|
      Jabber.logger.debug("Callback for #{jid.inspect}")
      user = User.first(:jid => jid.bare.to_s)
      begin
        @campfire_watchers[jid.bare.to_s].destroy
        Jabber.logger.debug("New user registered! #{jid.bare}")
        user = User.new(:jid => jid.bare.to_s) if user.nil?
        Jabber.logger.debug("I have fields #{fields.inspect}")
        user.token = fields["password"]
        user.subdomain = fields["url"].split(".")[0]
        user.roster_items = []
        Jabber.logger.debug "About to save #{user.inspect}"
        unless user.save
          Jabber.logger.debug "Could not save #{user.errors.inspect}"
        end
      rescue => e
        Jabber.logger.debug e.inspect
        Jabber.logger.debug e.backtrace.join("\n")
      end
      #Get Presence info
      probe = Jabber::Presence.new()
      probe.from = @config[:jid]
      probe.to = jid.bare
      probe.type = :probe
      Jabber.logger.debug("Sending: #{probe}")
      @component.send(probe)
    end
    
    # Set up presence management
    @component.add_presence_callback do |presence|
      Jabber.logger.debug "Testing presence #{presence.inspect}"
      unless presence.from.nil?
        begin
          user = User.first(:jid => presence.from.bare.to_s)
          if user
            if not presence.x.nil? and not @campfire_watchers[user.jid].rooms[presence.to.bare.to_s].nil?
              Jabber.logger.debug("Got chat message instruction! #{presence.x.inspect}")
              @campfire_watchers[user.jid].add_jid(presence.from.to_s)
              req = Jabber::Presence.new()
              req.from = presence.to
              req.to = presence.from
              req.add_element(Jabber::MUC::XMUCUserItem.new("owner", "moderator"))
              @component.send(req)
              @campfire_watchers[user.jid].refresh_rooms
            elsif presence.type == :unavailable and presence.to.to_s == @config[:jid]
              Jabber.logger.debug("User is now offline: #{presence.from.to_s}")
              @campfire_watchers[user.jid].remove_jid(presence.from.to_s)
            elsif presence.type == nil and presence.to.to_s == @config[:jid]
              Jabber.logger.debug("User is now online: #{presence.from.to_s}")
              @campfire_watchers[user.jid].add_jid(presence.from.to_s)
              send_presence(presence.from)
            elsif presence.type == nil
              Jabber.logger.debug "Unknown presence type: #{presence.from.to_s}"
            end
          else
            Jabber.logger.debug("User is not registered")
          end
        rescue => e
          Jabber.logger.debug e.inspect
          Jabber.logger.debug e.backtrace.join("\n")
        end
      end
    end
    
    # Set up message handler
    @component.add_message_callback do |message|
      Jabber.logger.debug("Got message: #{message}")
      if message.type == :groupchat
        user = User.first(:jid => message.from.bare.to_s)
        if user
          if not @campfire_watchers[user.jid].rooms[message.to.bare.to_s].nil?
            @campfire_watchers[user.jid].add_jid(message.from.to_s)
            Jabber.logger.debug("Got message from #{message.from.bare.to_s} details #{message.inspect}")
            Jabber.logger.debug("User: #{user.inspect}")
            Jabber.logger.debug("Roster: #{user.roster_items.inspect}")
            room = @campfire_watchers[user.jid].rooms[message.to.bare.to_s]
              
            body = message.first_element_text('body')
              
            # XXX: This should be replaced by a worker thread/queue
            Thread.new do
              begin
              ## DO CAMPFIRE MESSAGE SEND!
                if body =~ /\n/ or body =~ /\r/
                  room.paste body
                else
                  room.speak body
                end
                Jabber.logger.debug("Campfire message sent to #{room.name}")
              rescue Exception => ex
                Jabber.logger.error("ERROR WHILE SENDING CAMPFIRE! #{ex} #{ex.backtrace.join("\n")}")
                msg = Jabber::Message.new(message.from, "Sorry, an error has occured and the following message was not sent:\n\n#{body}")
                msg.from = @config[:jid]
                msg.to = message.from
                @component.send(msg)
              end
            end
          end
        else
          msg = Jabber::Message.new(message.from, 'Sorry, you must be registered to use this service.')
          msg.type = :chat
          msg.from = @config[:jid]
          msg.to = message.from
          @component.send(msg)
        end
      end
    end
  end
  
  def start()
    # Become a daemon if requested
    if @options[:daemon] == true
      pid = daemonize()
      # Use syslog for logging
      Jabber.logger = SyslogLogger.new('camp2jabt')
      # Write out PID file.
      begin
        if File.file?(PID_FILE)
          Jabber.logger.fatal("#{PID_FILE} exists! Exiting!")
          exit 1
          return
        end
        File.open(PID_FILE, 'w') do |file|
          file.puts Process.pid
        end
      rescue Exception
        Jabber.logger.fatal("Failed to write #{PID_FILE}! Exiting.")
        exit 1
        return
      end
    end
  
    server = @config[:server]
    port   = @config[:port]
    secret = @config[:secret]
    
    Jabber.logger.info("Connecting to XMPP server (#{server}:#{port})")
    @component.connect(server, port)
    @component.auth(secret)

    Jabber.logger.info("Connected to XMPP server!")
     
    # Connected! 
    begin
      registered_users.each do |user|
        send_presence(Jabber::JID.new(user.jid))
        
        #Get Presence info
        probe = Jabber::Presence.new()
        probe.from = @config[:jid]
        probe.to = user.jid
        probe.type = :probe
        Jabber.logger.debug("Sending: #{probe}")
        @component.send(probe)
      end
    rescue Exception => ex
      Jabber.logger.error("Error will robinson #{ex}")
      Jabber.logger.error(ex.backtrace.join("\n"))
    end
    Jabber.logger.info('Started')
    Thread.stop()
  end
  
  private
  
  def registered_users
    User.all
  end
  
  def send_presence(jid)
    #Create all watchers
    @campfire_watchers = {} if @campfire_watchers.nil?
    if @campfire_watchers[jid.bare.to_s] == nil
      if user = User.first(:jid => jid.bare.to_s)
        Jabber.logger.debug("Creating campfire watcher for #{jid.bare.to_s}")

        @campfire_watchers[jid.bare.to_s] = CampfireWatcher.new(user.subdomain, user.token, config[:jid])
        Jabber.logger.debug("Watcher is #{@campfire_watchers[jid.bare.to_s].inspect}")
        @campfire_watchers[jid.bare.to_s].add_message_handler do |message|
          begin
            roomjid, jid, user_name, body = message
            from_jid = "#{roomjid}/#{user_name}"
            to_jid   = jid

            Jabber.logger.debug("Received message in room: #{from_jid} from: #{to_jid}")

            # We have a message to send!
            msg = Jabber::Message.new(to_jid, body)
            msg.type = :groupchat
            msg.from = from_jid
            msg.to = to_jid
            Jabber.logger.debug("Sending #{msg}")
            @component.send(msg)
          rescue Exception => ex
            Jabber.logger.error("FAILED TO PARSE CAMPFIRE MESSAGE!! #{jid.bare.to_s} #{ex}")
          end
        end
        @campfire_watchers[jid.bare.to_s].add_room_handler do |roomjid, room, jid|
          # Join room
          req = Jabber::Message.new()
          req.from = roomjid
          req.to = jid
          u = Jabber::MUC::XMUCUser.new
          i = Jabber::MUC::XMUCUserInvite.new(nil, "Campfire chat")
          i.from = jid
          req.add(u).add(i)
          Jabber.logger.debug("Sending: #{req}")
          @component.send(req)
        end
        @campfire_watchers[jid.bare.to_s].add_user_handler do |roomjid, user, jid|
          req = Jabber::Presence.new()
          req.from = roomjid + "/" + user[:name]
          req.to = jid
          u = Jabber::MUC::XMUCUser.new
          p = REXML::Element.new('status')
          p.add_attribute('code', "110")
          u.add(p)
          p = REXML::Element.new('status')
          p.add_attribute('code', "210")
          u.add(p)
          i = Jabber::MUC::XMUCUserItem.new("member", "participant", "#{user[:email_address].gsub(/@/, "%")}@#{@config[:jid]}")
          req.add(u).add(i)
          Jabber.logger.debug("Sending: #{req}")
          @component.send(req)
        end
        @campfire_watchers[jid.bare.to_s].start()
      else
        Jabber.logger.debug "User for JID: #{jid.bare.to_s} could not be found"
      end
    else
      # Already setup connection, send invites etc.
      @campfire_watchers[jid.bare.to_s].rooms.each do |roomjid, room|
        @campfire_watchers[jid.bare.to_s].add_jid(jid.to_s)
        # Join room
        req = Jabber::Message.new()
        req.from = roomjid
        req.to = jid
        u = Jabber::MUC::XMUCUser.new
        i = Jabber::MUC::XMUCUserInvite.new(nil, "Campfire chat")
        i.from = jid
        req.add(u).add(i)
        Jabber.logger.debug("Sending: #{req}")
        @component.send(req)
      end
    end

    # Make transport appear online
    presence = Jabber::Presence.new()
    presence.from = @config[:jid]
    presence.to = jid
    @component.send(presence)
  end
end
