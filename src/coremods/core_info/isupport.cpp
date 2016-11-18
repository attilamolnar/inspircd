/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Attila Molnar <attilamolnar@hush.com>
 *   Copyright (C) 2013 Peter Powell <petpow@saberuk.com>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "modules/isupport.h"

ISupportManager::ISupportManager(Module* mod)
	: DataProvider(mod, "isupport")
{
}

void ISupportManager::Build()
{
	/**
	 * This is currently the neatest way we can build the initial ISUPPORT map. In
	 * the future we can use an initializer list here.
	 */
	std::map<std::string, std::string> tokens;

	tokens["AWAYLEN"] = ConvToStr(ServerInstance->Config->Limits.MaxAway);
	tokens["CASEMAPPING"] = "rfc1459";
	tokens["CHANLIMIT"] = InspIRCd::Format("#:%u", ServerInstance->Config->MaxChans);
	tokens["CHANMODES"] = ServerInstance->Modes->GiveModeList(MODETYPE_CHANNEL);
	tokens["CHANNELLEN"] = ConvToStr(ServerInstance->Config->Limits.ChanMax);
	tokens["CHANTYPES"] = "#";
	tokens["ELIST"] = "MU";
	tokens["KICKLEN"] = ConvToStr(ServerInstance->Config->Limits.MaxKick);
	tokens["MAXBANS"] = "64"; // TODO: make this a config setting.
	tokens["MAXTARGETS"] = ConvToStr(ServerInstance->Config->MaxTargets);
	tokens["MODES"] = ConvToStr(ServerInstance->Config->Limits.MaxModes);
	tokens["NETWORK"] = ServerInstance->Config->Network;
	tokens["NICKLEN"] = ConvToStr(ServerInstance->Config->Limits.NickMax);
	tokens["PREFIX"] = ServerInstance->Modes.BuildPrefixes();
	tokens["STATUSMSG"] = ServerInstance->Modes.BuildPrefixes(false);
	tokens["TOPICLEN"] = ConvToStr(ServerInstance->Config->Limits.MaxTopic);
	tokens["VBANLIST"];

	// Modules can add new tokens and also edit or remove existing tokens
	FOREACH_MOD(On005Numeric, (tokens));

	// EXTBAN is a special case as we need to sort it and prepend a comma.
	std::map<std::string, std::string>::iterator extban = tokens.find("EXTBAN");
	if (extban != tokens.end())
	{
		std::sort(extban->second.begin(), extban->second.end());
		extban->second.insert(0, ",");
	}

	// Transform the map into a list of lines, ready to be sent to clients
	Numeric::Numeric numeric(RPL_ISUPPORT);
	unsigned int token_count = 0;
	cachedlines.clear();

	for (std::map<std::string, std::string>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
	{
		numeric.push(it->first);
		std::string& token = numeric.GetParams().back();

		// If this token has a value then append a '=' char after the name and then the value itself
		if (!it->second.empty())
			token.append(1, '=').append(it->second);

		token_count++;

		if (token_count % 13 == 12 || it == --tokens.end())
		{
			// Reached maximum number of tokens for this line or the current token
			// is the last one; finalize the line and store it for later use
			numeric.push("are supported by this server");
			cachedlines.push_back(numeric);
			numeric.GetParams().clear();
		}
	}
}

void ISupportManager::SendTo(LocalUser* user) const
{
	for (std::vector<Numeric::Numeric>::const_iterator i = cachedlines.begin(); i != cachedlines.end(); ++i)
		user->WriteNumeric(*i);
}
