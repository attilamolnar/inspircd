#
# InspIRCd -- Internet Relay Chat Daemon
#
#   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
#   Copyright (C) 2007 Craig Edwards <craigedwards@brainbox.cc>
#
# This file is part of InspIRCd.  InspIRCd is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


package make::opensslcert;

require 5.8.0;

use strict;
use warnings FATAL => qw(all);

use Exporter 'import';
use make::configure;
our @EXPORT = qw(make_openssl_cert);


sub make_openssl_cert()
{
	open (FH, ">openssl.template");
	my $commonname = promptstring_s('What is the hostname of your server?', 'irc.example.com');
	my $email = promptstring_s('What email address can you be contacted at?', 'example@example.com');
	my $unit = promptstring_s('What is the name of your unit?', 'Server Admins');
	my $org = promptstring_s('What is the name of your organization?', 'Example IRC Network');
	my $city = promptstring_s('What city are you located in?', 'Example City');
	my $state = promptstring_s('What state are you located in?', 'Example State');
	my $country = promptstring_s('What is the ISO 3166-1 code for the country you are located in?', 'XZ');
	my $time = promptstring_s('How many days do you want your certificate to be valid for?', '365');
	print FH <<__END__;
$country
$state
$city
$org
$unit
$commonname
$email
__END__
close(FH);
system("cat openssl.template | openssl req -x509 -nodes -newkey rsa:1024 -keyout key.pem -out cert.pem -days $time 2>/dev/null");
system("openssl dhparam -out dhparams.pem 1024");
unlink("openssl.template");
}

1;
