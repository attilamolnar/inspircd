
#include "inspircd.h"

class ModulePerf : public Module
{
	time_t last;
	unsigned long cmds;
	unsigned long conns;
	unsigned long disconnects;
 public:
	ModulePerf()
		: last(ServerInstance->Time())
		, cmds(0)
		, conns(0)
		, disconnects(0)
	{
	}

	void init()
	{
		ServerInstance->SNO->EnableSnomask('z', "PERFDEBUG");
		Implementation eventlist[] = { I_OnBackgroundTimer, I_OnPostCommand, I_OnPostConnect, I_OnUserDisconnect };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}

	void OnPostCommand(const std::string& command, const std::vector<std::string>& parameters, LocalUser* user, CmdResult result, const std::string& original_line)
	{
		cmds++;
	}

	void OnPostConnect(User* user)
	{
		if (IS_LOCAL(user))
			conns++;
	}

	void OnUserDisconnect(LocalUser *user)
	{
		disconnects++;
	}

	void OnBackgroundTimer(time_t now)
	{
		if (now <= last)
		{
			last = now;
			return;
		}

		if (now != last + 5)
		{
			ServerInstance->SNO->WriteToSnoMask('z', "Missed tick, now = %lu, last = %lu", (unsigned long) now, (unsigned long) last);
		}
		unsigned int diff = now - last;
		ServerInstance->SNO->WriteToSnoMask('z', "Avg. commands/s = %lu | Avg. connects/s = %lu | Avg. disconnects/s = %lu | users = %lu", cmds/diff, conns/diff, disconnects/diff, (unsigned long)ServerInstance->Users->LocalUserCount());
		last = now;
		disconnects = conns = cmds = 0;
	}

	Version GetVersion()
	{
		return Version("m_perf");
	}
};

MODULE_INIT(ModulePerf)
