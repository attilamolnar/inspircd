/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2007-2009 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
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

#include "main.h"
#include "utils.h"
#include "treeserver.h"
#include "link.h"
#include "treesocket.h"
#include "resolvers.h"

/* Create server sockets off a listener. */
StreamSocket* ModuleSpanningTree::OnAcceptConnection(int newsock, ListenSocket* from, irc::sockets::sockaddrs* client, irc::sockets::sockaddrs* server)
{
	if (from->bind_tag->getString("type") != "servers")
		return NULL;

	std::string incomingip = client->addr();

	for (std::vector<std::string>::iterator i = Utils->ValidIPs.begin(); i != Utils->ValidIPs.end(); i++)
	{
		if (*i == "*" || *i == incomingip || irc::sockets::cidr_mask(*i).match(*client))
		{
			TreeSocket* sock = new TreeSocket(Utils, newsock, from, client, server);
			Utils->Connections.push_back(sock);
			return sock;
		}
	}
	ServerInstance->SNO->WriteToSnoMask('l', "Server connection from %s denied (no link blocks with that IP address)", incomingip.c_str());
	return NULL;
}

/** Yay for fast searches!
 * This is hundreds of times faster than recursion
 * or even scanning a linked list, especially when
 * there are more than a few servers to deal with.
 * (read as: lots).
 */
TreeServer* SpanningTreeUtilities::FindServer(const std::string &ServerName)
{
	if (ServerInstance->IsSID(ServerName))
		return this->FindServerID(ServerName);

	server_hash::iterator iter = serverlist.find(ServerName);
	if (iter != serverlist.end())
	{
		return iter->second;
	}
	else
	{
		return NULL;
	}
}

/** Find the first server matching a given glob mask.
 * Theres no find-using-glob method of hash_map [awwww :-(]
 * so instead, we iterate over the list using an iterator
 * and match each one until we get a hit. Yes its slow,
 * deal with it.
 */
TreeServer* SpanningTreeUtilities::FindServerMask(const std::string &ServerName)
{
	for (server_hash::iterator i = serverlist.begin(); i != serverlist.end(); i++)
	{
		if (InspIRCd::Match(i->first,ServerName))
			return i->second;
	}
	return NULL;
}

TreeServer* SpanningTreeUtilities::FindServerID(const std::string &id)
{
	server_hash::iterator iter = sidlist.find(id);
	if (iter != sidlist.end())
		return iter->second;
	else
		return NULL;
}

/* A convenient wrapper that returns true if a server exists */
bool SpanningTreeUtilities::IsServer(const std::string &ServerName)
{
	return (FindServer(ServerName) != NULL);
}

SpanningTreeUtilities::SpanningTreeUtilities(ModuleSpanningTree* C) : Creator(C)
{
	TreeRoot = new TreeServer(this);
	this->ReadConfiguration();
}

CullResult SpanningTreeUtilities::cull()
{
	while (TreeRoot->ChildCount())
	{
		TreeServer* child_server = TreeRoot->GetChild(0);
		if (child_server)
		{
			TreeSocket* sock = child_server->GetSocket();
			sock->Close();
		}
	}

	for(size_t i = 0; i < Connections.size(); i++)
	{
		Connections[i]->Close();
	}
	TreeRoot->cull();

	return classbase::cull();
}

SpanningTreeUtilities::~SpanningTreeUtilities()
{
	delete TreeRoot;
}

void SpanningTreeUtilities::AddThisServer(TreeServer* server, TreeSocketSet &list)
{
	list.insert(server->GetSocket());
}

/* returns a list of DIRECT servernames for a specific channel */
void SpanningTreeUtilities::GetListOfServersForChannel(Channel* c, TreeSocketSet &list, char status, const CUList &exempt_list)
{
	unsigned int minrank = 0;
	if (status)
	{
		ModeHandler* mh = ServerInstance->Modes->FindPrefix(status);
		if (mh)
			minrank = mh->GetPrefixRank();
	}

	const UserMembList *ulist = c->GetUsers();

	for (UserMembCIter i = ulist->begin(); i != ulist->end(); i++)
	{
		if (IS_LOCAL(i->first))
			continue;

		if (minrank && i->second->GetAccessRank() < minrank)
			continue;

		if (exempt_list.find(i->first) == exempt_list.end())
		{
			TreeServer* best = this->FindServer(i->first->server);
			if (best)
				AddThisServer(best,list);
		}
	}
	return;
}

bool SpanningTreeUtilities::DoOneToAllButSenderRaw(const std::string &data, const std::string &omit, const std::string &prefix, const irc::string &command, const parameterlist &params)
{
	TreeServer* omitroute = this->FindServer(omit);
	unsigned int items = this->TreeRoot->ChildCount();
	for (unsigned int x = 0; x < items; x++)
	{
		TreeServer* Route = this->TreeRoot->GetChild(x);
		TreeSocket* Sock = Route->GetSocket();
		if (Sock != omitroute->GetSocket())
			Sock->WriteLine(data);
	}
	return true;
}

bool SpanningTreeUtilities::DoOneToAllButSender(const std::string &prefix, const std::string &command, const parameterlist &params, std::string omit)
{
	TreeServer* omitroute = this->FindServer(omit);
	std::string FullLine = ":" + prefix + " " + command;
	unsigned int words = params.size();
	for (unsigned int x = 0; x < words; x++)
	{
		FullLine = FullLine + " " + params[x];
	}
	unsigned int items = this->TreeRoot->ChildCount();
	for (unsigned int x = 0; x < items; x++)
	{
		TreeServer* Route = this->TreeRoot->GetChild(x);
		// Send the line IF:
		// The route has a socket (its a direct connection)
		// The route isnt the one to be omitted
		// The route isnt the path to the one to be omitted
		if ((Route) && (Route->GetSocket()) && (Route->GetName() != omit) && (omitroute != Route))
		{
			TreeSocket* Sock = Route->GetSocket();
			if (Sock)
				Sock->WriteLine(FullLine);
		}
	}
	return true;
}

bool SpanningTreeUtilities::DoOneToMany(const std::string &prefix, const std::string &command, const parameterlist &params)
{
	std::string FullLine = ":" + prefix + " " + command;
	unsigned int words = params.size();
	for (unsigned int x = 0; x < words; x++)
	{
		FullLine = FullLine + " " + params[x];
	}
	unsigned int items = this->TreeRoot->ChildCount();
	for (unsigned int x = 0; x < items; x++)
	{
		TreeServer* Route = this->TreeRoot->GetChild(x);
		if (Route && Route->GetSocket())
		{
			TreeSocket* Sock = Route->GetSocket();
			if (Sock)
				Sock->WriteLine(FullLine);
		}
	}
	return true;
}

bool SpanningTreeUtilities::DoOneToMany(const char* prefix, const char* command, const parameterlist &params)
{
	std::string spfx = prefix;
	std::string scmd = command;
	return this->DoOneToMany(spfx, scmd, params);
}

bool SpanningTreeUtilities::DoOneToAllButSender(const char* prefix, const char* command, const parameterlist &params, std::string omit)
{
	std::string spfx = prefix;
	std::string scmd = command;
	return this->DoOneToAllButSender(spfx, scmd, params, omit);
}

bool SpanningTreeUtilities::DoOneToOne(const std::string &prefix, const std::string &command, const parameterlist &params, std::string target)
{
	TreeServer* Route = this->FindServer(target);
	if (Route)
	{
		std::string FullLine = ":" + prefix + " " + command;
		unsigned int words = params.size();
		for (unsigned int x = 0; x < words; x++)
		{
			FullLine = FullLine + " " + params[x];
		}
		if (Route && Route->GetSocket())
		{
			TreeSocket* Sock = Route->GetSocket();
			if (Sock)
				Sock->WriteLine(FullLine);
		}
		return true;
	}
	else
	{
		return false;
	}
}

void SpanningTreeUtilities::RefreshIPCache()
{
	ValidIPs.clear();
	for (std::vector<reference<Link> >::iterator i = LinkBlocks.begin(); i != LinkBlocks.end(); ++i)
	{
		Link* L = *i;
		if (L->IPAddr.empty() || L->RecvPass.empty() || L->SendPass.empty() || L->Name.empty() || !L->Port)
		{
			/* Invalid link block */
			continue;
		}

		if (L->AllowMask.length())
			ValidIPs.push_back(L->AllowMask);

		irc::sockets::sockaddrs dummy;
		bool ipvalid = irc::sockets::aptosa(L->IPAddr, L->Port, dummy);
		if (ipvalid)
			ValidIPs.push_back(L->IPAddr);
		else
		{
			try
			{
				bool cached;
				SecurityIPResolver* sr = new SecurityIPResolver(Creator, this, L->IPAddr, L, cached, DNS_QUERY_AAAA);
				ServerInstance->AddResolver(sr, cached);
			}
			catch (...)
			{
			}
		}
	}
}

void SpanningTreeUtilities::ReadConfiguration()
{
	ConfigReadStatus& status = ServerInstance->Config->status;
	ConfigTag* tag = status.GetTag("spanningtree");
	FlatLinks = tag->getBool("flatlinks");
	HideULines = tag->getBool("hideulines");
	AllowOptCommon = tag->getBool("allowmismatch");
	ChallengeResponse = !tag->getBool("disablehmac");
	quiet_bursts = tag->getBool("quietbursts");
	PingWarnTime = tag->getInt("pingwarning");
	PingFreq = tag->getInt("serverpingfreq", 60);

	if (PingWarnTime < 0 || PingWarnTime > PingFreq - 1)
		PingWarnTime = 0;

	AutoconnectBlocks.clear();
	LinkBlocks.clear();
	ValidIPs.clear();
	ConfigTagList tags = ServerInstance->Config->GetTags("link");
	for(ConfigIter i = tags.first; i != tags.second; ++i)
	{
		tag = i->second;
		reference<Link> L = new Link(tag);
		L->Name = tag->getString("name");
		L->IPAddr = tag->getString("ipaddr");
		L->AllowMask = tag->getString("allowmask", L->IPAddr);
		L->Port = tag->getInt("port");
		L->SendPass = tag->getString("sendpass", tag->getString("password"));
		L->RecvPass = tag->getString("recvpass", tag->getString("password"));
		L->Fingerprint = tag->getString("fingerprint");
		L->HiddenFromStats = tag->getBool("statshidden");
		L->Timeout = tag->getInt("timeout", 30);
		L->Hook = tag->getString("ssl");
		L->Bind = tag->getString("bind");
		L->Hidden = tag->getBool("hidden");

		if (L->Fingerprint.find(':') != std::string::npos)
		{
			std::string tmp = L->Fingerprint;
			L->Fingerprint.clear();
			for(unsigned int j=0; j < tmp.length(); j++)
				if (tmp[j] != ':')
					L->Fingerprint.push_back(tmp[j]);
		}

		if (L->RecvPass.empty())
			status.ReportError(tag, "<link:recvpass> not defined", true);
		else if (L->SendPass.empty())
			status.ReportError(tag, "<link:sendpass> not defined", true);
		else if (L->Name.empty())
			status.ReportError(tag, "<link:name> not defined", true);
		else if (L->Name.find('.') == std::string::npos)
			status.ReportError(tag, "<link:name> is invalid: must contain a '.'", true);
		else if (L->Name.length() > 64)
			status.ReportError(tag, "<link:name> is invalid: maximum length is 64 characters", true);
		else
			LinkBlocks.push_back(L);
	}

	tags = ServerInstance->Config->GetTags("autoconnect");
	for(ConfigIter i = tags.first; i != tags.second; ++i)
	{
		tag = i->second;
		reference<Autoconnect> A = new Autoconnect(tag);
		A->Period = tag->getInt("period");
		A->NextConnectTime = ServerInstance->Time() + A->Period;
		A->position = -1;
		irc::spacesepstream ss(tag->getString("server"));
		std::string server;
		while (ss.GetToken(server))
		{
			A->servers.push_back(server);
		}

		if (A->Period <= 0)
		{
			status.ReportError(tag, "<autoconnect:period> must be positive", true);
			continue;
		}

		if (A->servers.empty())
		{
			status.ReportError(tag, "<autoconnect:servers> cannot be empty", true);
			continue;
		}

		AutoconnectBlocks.push_back(A);
	}

	RefreshIPCache();
}

Link* SpanningTreeUtilities::FindLink(const std::string& name)
{
	for (std::vector<reference<Link> >::iterator i = LinkBlocks.begin(); i != LinkBlocks.end(); ++i)
	{
		Link* x = *i;
		if (InspIRCd::Match(x->Name.c_str(), name.c_str()))
		{
			return x;
		}
	}
	return NULL;
}
