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

class CampfireWatcher
  attr_reader :rooms
  def initialize(subdomain, token, jid)
    @subdomain = subdomain
    @jids = []
    @jid = jid
    @token  = token
    @room_handlers = []
    @user_handlers = []
    @message_handlers = []
    @valid = true
    @rooms = {}
    
    # Set up the IMAP worker
    @mutex = Mutex.new
  end
  
  def add_message_handler(&handler)
    @message_handlers << handler
  end
  
  def add_room_handler(&handler)
    @room_handlers << handler
  end
  
  def destroy
    @valid = false
  end
  
  def add_user_handler(&handler)
    @user_handlers << handler
  end
  
  def send_message(msg)
    @room.speak msg
  end
  
  def add_jid(jid)
    @jids << jid unless @jids.include?(jid)
  end

  def remove_jid(jid)
    @jids.delete(jid)
  end
  
  def refresh_rooms
    @rooms.each do |roomjid, room|
      room.users.each do |user|
        @jids.each do |jid|
          @user_handlers.each do |handler|
            handler.call(roomjid, user, jid)
          end
        end
      end
    end
  end
  
  # XXX: This creates WAY too many threads.
  def start()
    Thread.new do
      while @valid
        campfire_thread = Thread.new do
          begin
            Jabber.logger.info("Campfire connecting to #{@subdomain}")
            @campfire = Tinder::Campfire.new @subdomain, :token => @token, :ssl => true
            rooms = @campfire.rooms  
            rooms.each do |room|
              roomjid = "#{room.name.gsub(/ /, "+")}@#{@jid}".downcase
              @rooms[roomjid] = room

              room.join

              @room_handlers.each do |handler|
                @jids.each do |jid|
                  handler.call(roomjid, room, jid)
                end
              end
              
              room.users.each do |user|
                @user_handlers.each do |handler|
                  @jids.each do |jid|
                    handler.call(roomjid, user, jid)
                  end
                end
              end

              room.listen do |m|
                Jabber.logger.debug("Got campfire message #{m.inspect}")
                @message_handlers.each do |handler|
                  if m["type"] == "LeaveMessage" or m["type"] == "EnterMessage"
                    room.users.each do |user|
                      @user_handlers.each do |handler|
                        @jids.each do |jid|
                          handler.call(roomjid, user, jid)
                        end
                      end
                    end
                  elsif m["type"] == "TextMessage"
                    @jids.each do |jid|
                      handler.call([roomjid, jid, m["user"]["name"], m["body"]])
                    end
                  end
                end
              end
            end
            puts "Got Rooms #{@rooms.inspect}"
          rescue Exception => ex
            # Something bad happened, die horribly!
            Jabber::logger.fatal(ex)
            Process.exit!
          end
        end
        
        campfire_thread.join()
        campfire_thread = nil
        
        sleep(5)
      end
    end
  end
end