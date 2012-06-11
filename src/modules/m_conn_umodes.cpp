/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2007 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2006 Craig Edwards <craigedwards@brainbox.cc>
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

/* $ModDesc: Sets (and unsets) modes on users when they connect */

class ModuleModesOnConnect : public Module
{
 public:
	ModuleModesOnConnect() {}

	void init()
	{
		ServerInstance->Modules->Attach(I_OnUserConnect, this);
	}

	void Prioritize()
	{
		// for things like +x on connect, important, otherwise we have to resort to config order (bleh) -- w00t
		ServerInstance->Modules->SetPriority(this, I_OnUserConnect, PRIORITY_FIRST);
	}

	Version GetVersion()
	{
		return Version("Sets (and unsets) modes on users when they connect", VF_VENDOR);
	}

	void OnUserConnect(LocalUser* user)
	{
		std::string ThisModes = user->MyClass->GetConfig("modes");
		if (!ThisModes.empty())
		{
			std::string buf;
			std::stringstream ss(ThisModes);

			std::vector<std::string> modes;
			modes.push_back(user->nick);

			// split ThisUserModes into modes and mode params
			while (ss >> buf)
				modes.push_back(buf);

			ServerInstance->SendMode(modes, ServerInstance->FakeClient);
		}
	}
};

MODULE_INIT(ModuleModesOnConnect)
