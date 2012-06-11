/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2010 Jackmcbarn <jackmcbarn@jackmcbarn.no-ip.org>
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
#include "command_parse.h"
#include "cull_list.h"

/* $ModDesc: Provides fake clients that respond to messages. */

namespace m_serverbots
{

/** Command definition
 */
class Alias
{
 public:
	/** The text of the alias command */
	irc::string AliasedCommand;

	/** Text to replace with */
	std::string ReplaceFormat;

	/** Nickname required to perform alias */
	std::string RequiredNick;

	/** RequiredNick must be on a ulined server */
	bool ULineOnly;

	/** Requires oper? */
	bool OperOnly;

	/** Format that must be matched for use */
	std::string format;
};

typedef std::multimap<irc::string, Alias>::iterator AliasIter;

class AliasFormatSubst : public FormatSubstitute
{
 public:
	SubstMap info;
	const std::string &line;
	AliasFormatSubst(const std::string &Line) : line(Line) {}
	std::string lookup(const std::string& key)
	{
		if (isdigit(key[0]))
		{
			int index = atoi(key.c_str());
			irc::spacesepstream ss(line);
			bool everything_after = (key.find('-') != std::string::npos);
			bool good = true;
			std::string word;

			for (int j = 0; j < index && good; j++)
				good = ss.GetToken(word);

			if (everything_after)
			{
				std::string more;
				while (ss.GetToken(more))
				{
					word.append(" ");
					word.append(more);
				}
			}

			return word;
		}
		SubstMap::iterator i = info.find(key);
		if (i != info.end())
			return i->second;
		return "";
	}
};

class ServerBot : public FakeUser
{
 public:
	ServerBot(const std::string& uid) : FakeUser(uid, ServerInstance->Config->ServerName) {}
	virtual const std::string& GetFullHost()
	{
		return this->User::GetFullHost();
	}
};

class BotData
{
 public:
	std::multimap<irc::string, Alias> Aliases;
	ServerBot* const bot;
	BotData(ServerBot* Bot) : bot(Bot) {}

	void HandleMessage(LocalUser* user, const std::string& text)
	{
		if(!user)
			return;
		irc::spacesepstream ss(text);
		std::string command, params;
		ss.GetToken(command);
		params = ss.GetRemaining();

		std::pair<AliasIter, AliasIter> range = Aliases.equal_range(command);

		for(AliasIter i = range.first; i != range.second; ++i)
			if(DoAlias(user, &i->second, params, text))
				return;

		// also support no-command aliases (presumably they have format checks)
		range = Aliases.equal_range("");
		for(AliasIter i = range.first; i != range.second; ++i)
			if(DoAlias(user, &i->second, text, text))
				return;
	}

	bool DoAlias(LocalUser *user, Alias *a, const std::string& params, const std::string& text)
	{
		/* Does it match the pattern? */
		if (!a->format.empty())
		{
			if (!InspIRCd::Match(params, a->format))
				return false;
		}

		if ((a->OperOnly) && (!IS_OPER(user)))
			return 0;

		if (!a->RequiredNick.empty())
		{
			User* u = ServerInstance->FindNick(a->RequiredNick);
			if (!u)
			{
				user->WriteFrom(bot, "NOTICE %s :%s is currently unavailable. Please try again later.",
					user->nick.c_str(), a->RequiredNick.c_str());
				return true;
			}
			if (a->ULineOnly && !ServerInstance->ULine(u->server))
			{
				ServerInstance->SNO->WriteToSnoMask('a', "NOTICE -- Service "+a->RequiredNick+" required by alias "+std::string(a->AliasedCommand.c_str())+" is not on a u-lined server, possibly underhanded antics detected!");
				user->WriteFrom(bot, "NOTICE %s :%s is an imposter! Please inform an IRC operator as soon as possible.",
					user->nick.c_str(), a->RequiredNick.c_str());
				return true;
			}
		}

		/* Now, search and replace in a copy of the original_line, replacing $1 through $9 and $1- etc */

		irc::sepstream commands(a->ReplaceFormat, '\n');
		std::string scommand;
		while (commands.GetToken(scommand))
		{
			DoCommand(scommand, user, text);
		}
		return true;
	}

	void DoCommand(const std::string& format, LocalUser* user, const std::string &text)
	{
		AliasFormatSubst subst(text);
		user->PopulateInfoMap(subst.info);
		std::string bothost = bot->GetFullHost();
		subst.info["bot"] = bot->nick;
		subst.info["fullbot"] = bothost;
		std::string result = subst.format(format);

		irc::tokenstream ss(result);
		std::vector<std::string> pars;
		std::string command, token;

		ss.GetToken(command);
		if (irc::string(command) == "BOTNOTICE")
		{
			ss.GetToken(token);
			user->Write(":%s NOTICE %s :%s", bothost.c_str(), user->nick.c_str(), token.c_str());
			return;
		}

		while (ss.GetToken(token) && (pars.size() <= MAXPARAMETERS))
		{
			pars.push_back(token);
		}
		CmdResult res = ServerInstance->Parser->CallHandler(command, pars, user);
		FOREACH_MOD(I_OnPostCommand,OnPostCommand(command, pars, user, res,text));
	}

	std::string GetVar(std::string varname, const std::string &original_line)
	{
		irc::spacesepstream ss(original_line);
		int index = varname[1] - '0';
		bool everything_after = (varname.length() == 3);
		std::string word;

		for (int j = 0; j < index; j++)
			ss.GetToken(word);

		if (everything_after)
			return ss.GetRemaining();

		ss.GetToken(word);
		return word;
	}
};

class BotTracker : public SimpleExtItem<BotData>
{
 public:
	std::map<std::string, BotData*> bots;
	BotTracker(Module* Creator) : SimpleExtItem<BotData>(EXTENSIBLE_USER, "serverbot", Creator) {}

	void free(void* item)
	{
		BotData* ext = static_cast<BotData*>(item);
		if (!ext)
			return;
		bots.erase(ext->bot->nick);
		ServerInstance->GlobalCulls->AddItem(ext->bot);
		delete ext;
	}
};

class ModuleServerBots : public Module
{
	BotTracker dataExt;
	bool recursing;
	int botID;
 public:
	ModuleServerBots() : dataExt(this), recursing(false), botID(0) {}

	void early_init()
	{
		ServerInstance->Modules->AddService(dataExt);
	}

	void init()
	{
		ServerInstance->Modules->Attach(I_OnUserMessage, this);
	}

	Version GetVersion()
	{
		return Version("Provides fake clients for handling IRCd commands.", VF_VENDOR);
	}

	void OnUserMessage(User *user, void *dest, int target_type, const std::string &text, char status, const CUList &exempt_list)
	{
		if (target_type != TYPE_USER)
			return;
		User* b = (User*)dest;
		BotData* bot = dataExt.get(b);
		if (!bot)
			return;

		if (recursing)
		{
			user->WriteFrom(bot->bot, "NOTICE %s :Your command caused a recursive bot message which was not processed.", user->nick.c_str());
			return;
		}

		recursing = true;
		bot->HandleMessage(IS_LOCAL(user), text);
		recursing = false;
	}

	void ReadConfig(ConfigReadStatus&)
	{
		std::map<std::string, BotData*> oldbots;
		oldbots.swap(dataExt.bots);

		ConfigTagList tags = ServerInstance->Config->GetTags("bot");
		for(ConfigIter i = tags.first; i != tags.second; i++)
		{
			ConfigTag* tag = i->second;
			// UID is of the form "12!BOT"
			std::string nick = tag->getString("nick");
			if (nick.empty())
				continue;
			std::map<std::string, BotData*>::iterator found = oldbots.find(nick);
			ServerBot* bot;
			if (found != oldbots.end())
			{
				dataExt.bots.insert(*found);
				bot = found->second->bot;
				found->second->Aliases.clear();
				oldbots.erase(found);
			}
			else
			{
				User* bump = ServerInstance->FindNick(nick);
				if (bump)
					bump->ChangeNick(bump->uuid, true);
				std::string uid = ConvToStr(++botID) + "!BOT";
				bot = new ServerBot(uid);
				BotData* bd = new BotData(bot);
				dataExt.set(bot, bd);
				dataExt.bots.insert(std::make_pair(nick, bd));

				bot->ChangeNick(nick, true);
			}
			bot->ident = tag->getString("ident", "bot");
			bot->host = tag->getString("host", ServerInstance->Config->ServerName);
			bot->dhost = bot->host;
			bot->fullname = tag->getString("name", "Server-side Bot");
			bot->InvalidateCache();
			std::string oper = tag->getString("oper", "Server_Bot");
			if (!oper.empty())
			{
				OperIndex::iterator iter = ServerInstance->Config->oper_blocks.find(" " + oper);
				if (iter != ServerInstance->Config->oper_blocks.end())
					bot->oper = iter->second;
				else
					bot->oper = new OperInfo(oper);
			}
		}
		for(std::map<std::string, BotData*>::iterator i = oldbots.begin(); i != oldbots.end(); i++)
		{
			ServerInstance->GlobalCulls->AddItem(i->second->bot);
		}

		tags = ServerInstance->Config->GetTags("botcmd");
		for(ConfigIter i = tags.first; i != tags.second; i++)
		{
			ConfigTag* tag = i->second;
			std::string botnick = tag->getString("bot");
			std::map<std::string, BotData*>::iterator found = dataExt.bots.find(botnick);
			if (found == dataExt.bots.end())
				continue;
			BotData* bot = found->second;
			Alias a;
			a.AliasedCommand = tag->getString("text").c_str();
			tag->readString("replace", a.ReplaceFormat, true);
			a.RequiredNick = tag->getString("requires");
			a.ULineOnly = tag->getBool("uline");
			a.OperOnly = tag->getBool("operonly");
			a.format = tag->getString("format");

			bot->Aliases.insert(std::make_pair(a.AliasedCommand, a));
		}
 	}
};

}

using m_serverbots::ModuleServerBots;

MODULE_INIT(ModuleServerBots)
