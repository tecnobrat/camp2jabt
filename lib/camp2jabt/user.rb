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

require 'dm-timestamps'

class User
  include DataMapper::Resource
  
  property :id,           Serial
  property :created_at,   DateTime
  property :updated_at,   DateTime
  property :jid,          String
  property :token,        String
  property :subdomain,    String
  property :roster_items, Object
end
