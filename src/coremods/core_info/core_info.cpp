/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2014 Attila Molnar <attilamolnar@hush.com>
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
#include "core_info.h"
#include "modules/isupport.h"

RouteDescriptor ServerTargetCommand::GetRouting(User* user, const std::vector<std::string>& parameters)
{
	// Parameter must be a server name, not a nickname or uuid
	if ((!parameters.empty()) && (parameters[0].find('.') != std::string::npos))
		return ROUTE_UNICAST(parameters[0]);
	return ROUTE_LOCALONLY;
}

class CoreModInfo : public Module
{
	ISupportManager isupportmanager;

	CommandAdmin cmdadmin;
	CommandCommands cmdcommands;
	CommandInfo cmdinfo;
	CommandModules cmdmodules;
	CommandMotd cmdmotd;
	CommandTime cmdtime;
	CommandVersion cmdversion;

	/** Cached 004 numeric
	 */
	Numeric::Numeric numeric004;

	/** Returns a list of user or channel mode characters.
	 * Used for constructing the parts of the mode list in the 004 numeric.
	 * @param mt Controls whether to list user modes or channel modes
	 * @param needparam Return modes only if they require a parameter to be set
	 * @return The available mode letters that satisfy the given conditions
	 */
	std::string CreateModeList(ModeType mt, bool needparam = false)
	{
		std::string modestr;

		for (unsigned char mode = 'A'; mode <= 'z'; mode++)
		{
			ModeHandler* mh = ServerInstance->Modes.FindMode(mode, mt);
			if ((mh) && ((!needparam) || (mh->NeedsParam(true))))
				modestr.push_back(mode);
		}

		return modestr;
	}

	void HandleUserReg(LocalUser* user)
	{
		user->idle_lastmsg = ServerInstance->Time();

		user->WriteNumeric(RPL_WELCOME, InspIRCd::Format("Welcome to the %s IRC Network %s", ServerInstance->Config->Network.c_str(), user->GetFullRealHost().c_str()));
		user->WriteNumeric(RPL_YOURHOSTIS, InspIRCd::Format("Your host is %s, running version %s", ServerInstance->Config->ServerName.c_str(), INSPIRCD_BRANCH));
		user->WriteNumeric(RPL_SERVERCREATED, InspIRCd::Format("This server was created %s %s", __TIME__, __DATE__));
		user->WriteNumeric(numeric004);

		isupportmanager.SendTo(user);

		// Now registered
		if (ServerInstance->Users.unregistered_count)
			ServerInstance->Users.unregistered_count--;

		// Trigger LUSERS and MOTD output, give modules a chance too
		ModResult MOD_RESULT;
		std::string command("LUSERS");
		std::vector<std::string> parameters;
		FIRST_MOD_RESULT(OnPreCommand, MOD_RESULT, (command, parameters, user, true, command));
		if (!MOD_RESULT)
			ServerInstance->Parser.CallHandler(command, parameters, user);

		MOD_RESULT = MOD_RES_PASSTHRU;
		command = "MOTD";
		FIRST_MOD_RESULT(OnPreCommand, MOD_RESULT, (command, parameters, user, true, command));
		if (!MOD_RESULT)
			ServerInstance->Parser.CallHandler(command, parameters, user);

		if (ServerInstance->Config->RawLog)
			user->WriteServ("PRIVMSG %s :*** Raw I/O logging is enabled on this server. All messages, passwords, and commands are being recorded.", user->nick.c_str());
	}

	void OnServiceChange(const ServiceProvider& prov)
	{
		if (prov.service != SERVICE_MODE)
			return;

		Create004Numeric();
		isupportmanager.Build();
	}

	void Create004Numeric()
	{
		std::vector<std::string>& params = numeric004.GetParams();
		params.erase(params.begin()+2, params.end());

		// Create lists of modes
		// 1. User modes
		// 2. Channel modes
		// 3. Channel modes that require a parameter when set
		numeric004.push(CreateModeList(MODETYPE_USER));
		numeric004.push(CreateModeList(MODETYPE_CHANNEL));
		numeric004.push(CreateModeList(MODETYPE_CHANNEL, true));
	}

 public:
	CoreModInfo()
		: isupportmanager(this)
		, cmdadmin(this), cmdcommands(this), cmdinfo(this), cmdmodules(this), cmdmotd(this), cmdtime(this)
		, cmdversion(this, isupportmanager)
		, numeric004(RPL_SERVERVERSION)
	{
		numeric004.push(ServerInstance->Config->ServerName);
		numeric004.push(INSPIRCD_BRANCH);
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("admin");
		cmdadmin.AdminName = tag->getString("name");
		cmdadmin.AdminEmail = tag->getString("email", "null@example.com");
		cmdadmin.AdminNick = tag->getString("nick", "admin");

		isupportmanager.Build();
	}

	void OnUserConnect(LocalUser* user) CXX11_OVERRIDE
	{
		HandleUserReg(user);
	}

	void OnServiceAdd(ServiceProvider& service) CXX11_OVERRIDE
	{
		OnServiceChange(service);
	}

	void OnServiceDel(ServiceProvider& service) CXX11_OVERRIDE
	{
		OnServiceChange(service);
	}

	void OnLoadModule(Module* mod) CXX11_OVERRIDE
	{
		isupportmanager.Build();
	}

	void OnUnloadModule(Module* mod) CXX11_OVERRIDE
	{
		isupportmanager.Build();
	}

	void Prioritize() CXX11_OVERRIDE
	{
		ServerInstance->Modules->SetPriority(this, PRIORITY_FIRST);
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides the ADMIN, COMMANDS, INFO, MODULES, MOTD, TIME and VERSION commands", VF_VENDOR|VF_CORE);
	}
};

MODULE_INIT(CoreModInfo)
