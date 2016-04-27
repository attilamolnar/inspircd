/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Attila Molnar <attilamolnar@hush.com>
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


#pragma once

#include "event.h"

namespace IRCv3
{
	namespace Monitor
	{
		class APIBase;
		class API;
		class EventListener;

		typedef std::vector<LocalUser*> WatcherList;
	}
}

class IRCv3::Monitor::EventListener : public Events::ModuleEventListener
{
 public:
	EventListener(Module* mod)
		: ModuleEventListener(mod, "event/monitor")
	{
	}

	/**
	 * @param user User who started watching a nick
	 * @param nick Nick watched
	 */
	virtual void OnMonitorWatch(LocalUser* user, const std::string& nick) = 0;
};

class IRCv3::Monitor::APIBase : public DataProvider
{
 public:
	APIBase(Module* parent);

	/** Get list of users watching a nick.
	 * @param nick Nick
	 * @return List of users watching the nick or NULL if none
	 */
	virtual const WatcherList* GetWatcherList(const std::string& nick) = 0;
};

class IRCv3::Monitor::API : public dynamic_reference<APIBase>
{
 public:
	API(Module* parent)
		: dynamic_reference<APIBase>(parent, "monitor_api")
	{
	}
};
