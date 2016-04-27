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


#include "inspircd.h"
#include "modules/cap.h"
#include "modules/monitor.h"

enum
{
	RPL_WHOISKEYVALUE = 760,   // <Target> <Key> <Visibility> :<Value>
	RPL_KEYVALUE = 761,        // <Target> <Key> <Visibility>[ :<Value>]
	RPL_METADATAEND = 762,     // :end of metadata
	ERR_METADATALIMIT = 764,   // <Target> :metadata limit reached
	ERR_TARGETINVALID = 765,   // <Target> :invalid metadata target
	ERR_NOMATCHINGKEY = 766,   // <Target> <Key> :no matching key
	ERR_KEYINVALID = 767,      // <Key> :invalid metadata key
	ERR_KEYNOTSET = 768,       // <Target> <Key> :key not set
	ERR_KEYNOPERMISSION = 769, // <Target> <Key> :permission denied
	RPL_METADATASUBOK = 770,   // :<Key1> [<Key2> ...]
	RPL_METADATAUNSUBOK = 771, // :<Key1> [<Key2> ...]
	RPL_METADATASUBS = 772,    // :<Key1> [<Key2> ...]
	ERR_METADATATOOMANYSUBS = 773, // <Key>
	ERR_METADATASYNCLATER = 774
};

struct ExtData
{
	struct TSValue
	{
		typedef time_t Timestamp;
		std::string value;
		Timestamp ts;
		TSValue() : ts(0) { }

		bool IsDeathCert() const { return value.empty(); }

		/** Convert this object into a death certificate
		 * @param deltime Timestamp of when the object was deleted
		 */
		void ConvertToDeathCert(Timestamp deltime)
		{
			value.clear();
			ts = deltime;
		}
	};

	typedef insp::flat_map<std::string, TSValue, irc::insensitive_swo> KeyMap;
	static const unsigned int keepdeletedsecs = 3600;
	KeyMap keymap;

	TSValue* GetTsv(const std::string& keyname)
	{
		ExtData::KeyMap::iterator it = keymap.find(keyname);
		if (it != keymap.end())
			return &it->second;
		return NULL;
	}

	const TSValue* GetTsv(const std::string& keyname) const
	{
		ExtData::KeyMap::const_iterator it = keymap.find(keyname);
		if (it != keymap.end())
			return &it->second;
		return NULL;
	}

	const std::string* GetValue(const std::string& keyname) const
	{
		const ExtData::TSValue* tsv = GetTsv(keyname);
		if (!tsv)
			return NULL;
		if (tsv->IsDeathCert())
			return NULL;
		return &tsv->value;
	}

	// returns true if the value string has changed
	bool UpdateValue(const std::string& keyname, const std::string& keyvalue, TSValue::Timestamp keyts)
	{
		TSValue& tsv = keymap[keyname];
		// If our key timestamp is larger discard the update
		if (tsv.ts > keyts)
			return false;

		// If the key timestamps are equal discard one of the values
		if ((tsv.ts == keyts) && (tsv.value >= keyvalue))
			return false;

		tsv.ts = keyts;
		// Return false if the key value remained the same even though the timestamp has changed
		if (tsv.value == keyvalue)
			return false;
		tsv.value = keyvalue;
		return true;
	}

	void GCDeathCerts(TSValue::Timestamp mintime)
	{
		for (KeyMap::iterator i = keymap.begin(); i != keymap.end(); )
		{
			TSValue& tsv = i->second;
			if ((tsv.IsDeathCert()) && (tsv.ts < mintime))
				i = keymap.erase(i);
			else
				++i;
		}
	}

	TSValue* IterToTsv(KeyMap::iterator& it)
	{
		TSValue& tsv = it->second;
		if (!tsv.IsDeathCert())
		{
			// Key is alive
			++it;
			return &tsv;
		}

		// Key is marked as deleted, check whether we should erase it
		if (tsv.ts + keepdeletedsecs <= ServerInstance->Time())
			it = keymap.erase(it);
		else
			++it;
		return NULL;
	}

	bool CheckDCExpire(KeyMap::iterator& it)
	{
		TSValue& tsv = it->second;
		if ((tsv.IsDeathCert()) && (tsv.ts + keepdeletedsecs <= ServerInstance->Time()))
		{
			it = keymap.erase(it);
			return false;
		}
		return true;
	}
};

class LocalUserExtData : public ExtData
{
 public:
 	typedef insp::flat_set<std::string, irc::insensitive_swo> SubscriptionSet;

	bool IsSubscribed(const std::string& keyname) const
	{
		return subscribedset.count(keyname);
	}

	void Subscribe(const std::string& keyname)
	{
		subscribedset.insert(keyname);
	}

	void Unsubscribe(const std::string& keyname)
	{
		subscribedset.erase(keyname);
	}

	const SubscriptionSet& GetSubscriptions() const { return subscribedset; }

 private:
	SubscriptionSet subscribedset;
};

namespace IRCv3
{
	namespace Metadata
	{
		class ExtItem;
		class Manager;
		class UserExtItem;
		class ChanExtItem;
	}
}

class WriteNeighborsWithSubscription : public User::ForEachNeighborHandler
{
	const Cap::Capability& cap;
	const std::string& keyname;
	IRCv3::Metadata::Manager& manager;
	const std::string& msg;

	void Execute(LocalUser* user) CXX11_OVERRIDE;

 public:
	WriteNeighborsWithSubscription(User* user, const std::string& message, const Cap::Capability& capability, const std::string& Keyname, IRCv3::Metadata::Manager& managerref)
		: cap(capability)
		, keyname(Keyname)
		, manager(managerref)
		, msg(message)
	{
		user->ForEachNeighbor(*this, false);
	}
};

class SyncPayload
{
	mutable std::string str;

 public:
	SyncPayload()
		: str(1, '*')
	{
	}

	SyncPayload(User* user)
		: str(user->uuid)
	{
	}

	void add(const std::string& keyname, ExtData::TSValue::Timestamp keyts, const std::string* keyvalue)
	{
		str.push_back(',');
		str.append(keyname).push_back(',');
		str.append(ConvToStr(keyts)).push_back(',');
		if (keyvalue)
			stdalgo::string::escape<',', 'c'>(*keyvalue, str);
	}

	bool empty() const { return (str.find(',') == std::string::npos); }
	const std::string& get() const
	{
		// Return empty string if no keys were added
		if (empty())
			str.clear();
		return str;
	}
};

class IRCv3::Metadata::ExtItem : public ExtensionItem
{
	enum TokenType
	{
		TT_KEY,
		TT_TS,
		TT_VALUE
	};

 protected:
 	IRCv3::Metadata::Manager& manager;

	void SerializeKeyMap(ExtData* extdata, std::string& out) const
	{
		SyncPayload sync;
		for (ExtData::KeyMap::iterator i = extdata->keymap.begin(); i != extdata->keymap.end(); )
		{
			if (!extdata->CheckDCExpire(i))
				continue;
			const std::string& keyname = i->first;
			const ExtData::TSValue& tsv = i->second;
			sync.add(keyname, tsv.ts, &tsv.value);
			++i;
		}
		out.append(sync.get());
	}

	void UnserializeKeyMap(irc::commasepstream& ss, Extensible* container);

 public:
	ExtItem(Module* mod, const std::string& Name, ExtensionItem::ExtensibleType Type, IRCv3::Metadata::Manager& managerref)
		: ExtensionItem(Name, Type, mod)
		, manager(managerref)
	{
	}

	void unset(Extensible* container)
	{
		free(container, unset_raw(container));
	}
};

class IRCv3::Metadata::UserExtItem : public IRCv3::Metadata::ExtItem
{
 public:
	UserExtItem(Module* mod, IRCv3::Metadata::Manager& managerref)
		: IRCv3::Metadata::ExtItem(mod, "ircv3_metadata_u", ExtensionItem::EXT_USER, managerref)
	{
	}

	ExtData* get(Extensible* container, bool create = false)
	{
		ExtData* extdata = static_cast<ExtData*>(get_raw(container));
		if ((!extdata) && (create))
		{
			User* const user = static_cast<User*>(container);
			if (IS_LOCAL(user))
				extdata = new LocalUserExtData;
			else
				extdata = new ExtData;
			set_raw(container, extdata);
		}
		return extdata;
	}

	LocalUserExtData* getlocal(LocalUser* container, bool create = false)
	{
		LocalUserExtData* extdata = static_cast<LocalUserExtData*>(get_raw(container));
		if ((!extdata) && (create))
		{
			extdata = new LocalUserExtData;
			set_raw(container, extdata);
		}
		return extdata;
	}

	void free(Extensible* container, void* item)
	{
		if (IS_LOCAL(static_cast<User*>(container)))
			delete static_cast<LocalUserExtData*>(item);
		else
			delete static_cast<ExtData*>(item);
	}

	std::string serialize(SerializeFormat format, const Extensible* container, void* item) const
	{
		std::string out;

		// Serialize subscriptions first, if applicable
		if ((IS_LOCAL(static_cast<User*>(const_cast<Extensible*>(container)))) && (format != FORMAT_NETWORK))
		{
			LocalUserExtData* extdata = static_cast<LocalUserExtData*>(item);
			const LocalUserExtData::SubscriptionSet& subs = extdata->GetSubscriptions();
			for (LocalUserExtData::SubscriptionSet::const_iterator i = subs.begin(); i != subs.end(); ++i)
				out.append(*i).push_back(' ');

			if (!out.empty())
				out[out.size()-1] = ',';
		}

		// Serialize keymap
		SerializeKeyMap(static_cast<ExtData*>(item), out);
		return out;
	}

	void unserialize(SerializeFormat format, Extensible* container, const std::string& value);
};

class IRCv3::Metadata::ChanExtItem : public IRCv3::Metadata::ExtItem
{
 public:
	ChanExtItem(Module* mod, IRCv3::Metadata::Manager& managerref)
		: IRCv3::Metadata::ExtItem(mod, "ircv3_metadata_c", ExtensionItem::EXT_CHANNEL, managerref)
	{
	}

	ExtData* get(Extensible* container, bool create = false)
	{
		ExtData* extdata = static_cast<ExtData*>(get_raw(container));
		if ((!extdata) && (create))
		{
			extdata = new ExtData;
			set_raw(container, extdata);
		}
		return extdata;
	}

	std::string serialize(SerializeFormat format, const Extensible* container, void* item) const
	{
		std::string out;
		// Serialize keymap only
		SerializeKeyMap(static_cast<ExtData*>(item), out);
		return out;
	}

	void unserialize(SerializeFormat format, Extensible* container, const std::string& value)
	{
		irc::commasepstream ss(value, true);
		UnserializeKeyMap(ss, container);
	}

	void free(Extensible* container, void* item);
};

class IRCv3::Metadata::Manager : public IRCv3::Monitor::EventListener
{
	Cap::Capability cap;
	IRCv3::Monitor::API monitor;

	UserExtItem userext;
	ChanExtItem chanext;

	time_t last_member_sync;

	static std::string ConstructBaseNotifyLine(const std::string& source, const std::string& targetname)
	{
		std::string line(1, ':');
		line.append(source).append(" METADATA ").append(targetname).push_back(' ');
		return line;
	}

	void NotifyChannel(User* user, Channel* chan, const std::string& keyname, const std::string& line)
	{
		const Channel::MemberMap& members = chan->GetUsers();
		for (Channel::MemberMap::const_iterator i = members.begin(); i != members.end(); ++i)
		{
			User* curr = i->first;
			LocalUser* localuser = IS_LOCAL(curr);
			if (!localuser)
				continue;

			if ((cap.get(curr)) && (IsSubscribed(localuser, keyname)) && (user != curr))
				curr->Write(line);
		}
	}

	void SendAllKeys(LocalUser* user, const std::string& target, ExtData* extdata)
	{
		std::string line = ConstructBaseNotifyLine(ServerInstance->FakeClient->GetFullHost(), target);
		const std::string::size_type pos = line.size();
		for (ExtData::KeyMap::iterator i = extdata->keymap.begin(); i != extdata->keymap.end(); )
		{
			const std::string& keyname = i->first;
			const ExtData::TSValue* tsv = extdata->IterToTsv(i);
			if (!tsv)
				continue;

			line.append(keyname).append(" * :").append(tsv->value);
			user->Write(line);
			line.erase(pos);
		}
	}

	void OnMonitorWatch(LocalUser* user, const std::string& nick) CXX11_OVERRIDE
	{
		if (!cap.get(user))
			return;

		User* target = ServerInstance->FindNickOnly(nick);
		if (!target)
			return;

		ExtData* extdata = userext.get(target);
		if (!extdata)
			return;

		if (user->SharesChannelWith(target))
			return;

		SendAllKeys(user, target->nick, extdata);
	}

	void SendUpdate(User* user, User* usertarget, Channel* chantarget, const std::string& keyname, ExtData::TSValue::Timestamp keyts, const std::string* keyvalue = NULL)
	{
		SyncPayload sync(user);
		sync.add(keyname, keyts, keyvalue);
		SendSync(usertarget, chantarget, sync);
	}

	void SendSync(User* usertarget, Channel* chantarget, const SyncPayload& sync)
	{
		if (usertarget)
			ServerInstance->PI->SendMetaData(usertarget, userext.name, sync.get());
		else
			ServerInstance->PI->SendMetaData(chantarget, chanext.name, sync.get());
	}

	bool IsSubscribed(LocalUser* user, const std::string& keyname)
	{
		LocalUserExtData* extdata = userext.getlocal(user);
		if (!extdata)
			return false;
		return extdata->IsSubscribed(keyname);
	}

	void SendNotify(User* user, User* usertarget, Channel* chantarget, const std::string& keyname, const std::string* keyvalue)
	{
		const std::string& targetname = usertarget ? usertarget->nick : chantarget->name;
		std::string line = ConstructBaseNotifyLine(user->GetFullHost(), targetname);
		line.append(keyname).append(" * :");
		if (keyvalue)
			line.append(*keyvalue);

		if (usertarget)
		{
			already_sent_t sentid = ServerInstance->Users.NextAlreadySentId() + 1;
			if (sentid == 0)
				sentid = 1;

			WriteNeighborsWithSubscription(usertarget, line, cap, keyname, *this);

			const IRCv3::Monitor::WatcherList* watchers = monitor->GetWatcherList(usertarget->nick);
			if (watchers)
			{
				for (IRCv3::Monitor::WatcherList::const_iterator i = watchers->begin(); i != watchers->end(); ++i)
				{
					LocalUser* curr = *i;
					if ((cap.get(curr)) && (curr->already_sent != sentid) && (IsSubscribed(curr, keyname)))
						curr->Write(line);
				}
			}
		}
		else
		{
			NotifyChannel(user, chantarget, keyname, line);
		}
	}

	template <typename E>
	void GC(E& ext, Extensible* container)
	{
		ExtData* extdata = ext.get(container);
		if (!extdata)
			return;
		extdata->GCDeathCerts(ServerInstance->Time() - ExtData::keepdeletedsecs);
		if (extdata->keymap.empty())
			ext.unset(container);
	}

	void SendChangeRequest(User* user, User* usertarget, const std::string& keyname, const std::string* keyvalue = NULL)
	{
		std::vector<std::string> params;
		params.push_back(usertarget->uuid);
		params.push_back(keyname);
		if (keyvalue)
		{
			params.push_back(":");
			params.back().append(*keyvalue);
		}
		ServerInstance->PI->SendEncapsulatedData(usertarget->server->GetName(), "MDREQ", params, user);
	}

	void SendClearAllRequest(User* user, User* usertarget, ExtData* extdata)
	{
		std::string keynames;
		for (ExtData::KeyMap::iterator i = extdata->keymap.begin(); i != extdata->keymap.end(); )
		{
			const std::string& keyname = i->first;
			if (!extdata->IterToTsv(i))
				continue;

			keynames.append(keyname).push_back(',');
		}

		if (!keynames.empty())
		{
			keynames.erase(keynames.size()-1);
			SendChangeRequest(user, usertarget, keynames);
		}
	}

	void DoMemberSync(LocalUser* user, Channel* chan)
	{
		last_member_sync = ServerInstance->Time();

		const Channel::MemberMap& members = chan->GetUsers();
		for (Channel::MemberMap::const_iterator i = members.begin(); i != members.end(); ++i)
		{
			User* const curr = i->first;
			ExtData* const extdata = userext.get(curr);
			if (!extdata)
				continue;

			SendAllKeys(user, curr->nick, extdata);
		}
	}

 public:
 	friend class ::WriteNeighborsWithSubscription;

	static bool IsValidKeyName(const std::string& keyname)
	{
		for (std::string::const_iterator i = keyname.begin(); i != keyname.end(); ++i)
		{
			char c = *i;
			if (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')))
				continue;
			if ((c == '_') || (c == '.') || (c == ':'))
				continue;
			return false;
		}
		return true;
	}

	Manager(Module* mod)
		: IRCv3::Monitor::EventListener(mod)
 		, cap(mod, "metadata-notify-2")
		, monitor(mod)
		, userext(mod, *this)
		, chanext(mod, *this)
		, last_member_sync(ServerInstance->Time())
	{
	}

	ExtData* GetExtData(User* usertarget, Channel* chantarget, bool create = false)
	{
		if (usertarget)
			return userext.get(usertarget, create);
		return chanext.get(chantarget, create);
	}

	enum SetResult
	{
		SR_OK,
		SR_PENDING,
		SR_TOOMANY,
		SR_NOTUPDATED
	};

	SetResult SetMetadataRemote(User* user, User* usertarget, Channel* chantarget, const std::string& keyname, ExtData::TSValue::Timestamp keyts, const std::string& keyvalue, unsigned int maxmetadata = UINT_MAX)
	{
		ExtData* extdata = GetExtData(usertarget, chantarget, true);
		if (extdata->keymap.size() >= maxmetadata)
			return SR_TOOMANY;

		if (!extdata->UpdateValue(keyname, keyvalue, keyts))
			return SR_NOTUPDATED;

		SendNotify(user, usertarget, chantarget, keyname, &keyvalue);
		return SR_OK;
	}

	SetResult SetMetadata(User* user, User* usertarget, Channel* chantarget, const std::string& keyname, const std::string& keyvalue, unsigned int maxmetadata)
	{
		if ((usertarget) && (!IS_LOCAL(usertarget)))
		{
			SendChangeRequest(user, usertarget, keyname, &keyvalue);
			return SR_PENDING;
		}
		SetResult res = SetMetadataRemote(user, usertarget, chantarget, keyname, ServerInstance->Time(), keyvalue, maxmetadata);
		if (res == SR_OK)
			SendUpdate(user, usertarget, chantarget, keyname, ServerInstance->Time(), &keyvalue);
		return res;
	}

	enum DeleteResult
	{
		DR_OK,
		DR_PENDING,
		DR_NOSUCHKEY
	};

	DeleteResult DeleteMetadata(User* user, User* usertarget, Channel* chantarget, const std::string& keyname)
	{
		if ((usertarget) && (!IS_LOCAL(usertarget)))
		{
			SendChangeRequest(user, usertarget, keyname);
			return DR_PENDING;
		}

		// Deleting a key, do not create ext if doesn't exist
		ExtData* extdata = GetExtData(usertarget, chantarget);
		if (!extdata)
			return DR_NOSUCHKEY;

		ExtData::TSValue* tsv = extdata->GetTsv(keyname);
		if (!tsv)
			return DR_NOSUCHKEY;

		// Trying to delete already deleted key?
		if (tsv->IsDeathCert())
			return DR_NOSUCHKEY;

		tsv->ConvertToDeathCert(ServerInstance->Time());
		SendUpdate(user, usertarget, chantarget, keyname, ServerInstance->Time());
		SendNotify(user, usertarget, chantarget, keyname, NULL);
		return DR_OK;
	}

	void ClearAll(User* user, User* usertarget, Channel* chantarget, bool propagate = true)
	{
		ExtData* extdata = GetExtData(usertarget, chantarget);
		if (!extdata)
			return;

		if ((propagate) && (usertarget) && (!IS_LOCAL(usertarget)))
		{
			SendClearAllRequest(user, usertarget, extdata);
			return;
		}

		SyncPayload sync(user);

		for (ExtData::KeyMap::iterator i = extdata->keymap.begin(); i != extdata->keymap.end(); )
		{
			const std::string& keyname = i->first;
			ExtData::TSValue* tsv = extdata->IterToTsv(i);
			if (!tsv)
				continue; // Deleted, expired and removed from container

			if (tsv->IsDeathCert())
				continue;
			tsv->ConvertToDeathCert(ServerInstance->Time());

			if (propagate)
				sync.add(keyname, tsv->ts, NULL);

			SendNotify(user, usertarget, chantarget, keyname, NULL);
		}

		if (!sync.empty())
			SendSync(usertarget, chantarget, sync);
	}

	void GC(User* user)
	{
		GC(userext, user);
	}

	void GC(Channel* chan)
	{
		GC(chanext, chan);
	}

	enum SubscribeResult
	{
		SUB_OK,
		SUB_TOOMANY
	};

	SubscribeResult Subscribe(LocalUserExtData* extdata, const std::string& keyname, unsigned int maxsub)
	{
		if (extdata->IsSubscribed(keyname))
			return SUB_OK;

		if (extdata->GetSubscriptions().size() >= maxsub)
			return SUB_TOOMANY;

		extdata->Subscribe(keyname);
		return SUB_OK;
	}

	void Subscribe(LocalUser* user, const std::string& keyname, unsigned int maxsub)
	{
		Subscribe(userext.getlocal(user, true), keyname, maxsub);
	}

	void Unsubscribe(LocalUserExtData* extdata, const std::string& keyname)
	{
		if (extdata)
			extdata->Unsubscribe(keyname);
	}

	void OnJoin(LocalUser* user, Channel* chan)
	{
		if (!cap.get(user))
			return;

		ExtData* const extdata = chanext.get(chan);
		if (!extdata)
			return;

		SendAllKeys(user, chan->name, extdata);
		AttemptMemberSync(user, chan);
	}

	bool AttemptMemberSync(LocalUser* user, Channel* chan)
	{
		if (last_member_sync + 3 > ServerInstance->Time())
		{
			user->WriteNumeric(ERR_METADATASYNCLATER, chan->name, rand() % 10 + 1);
			return false;
		}

		// TODO: penalize user or disallow entirely if doing this when the initial sync has been done
		DoMemberSync(user, chan);
		return true;
	}
};

void WriteNeighborsWithSubscription::Execute(LocalUser* user)
{
	if ((cap.get(user)) && (manager.IsSubscribed(user, keyname)))
		user->Write(msg);
}

void IRCv3::Metadata::ExtItem::UnserializeKeyMap(irc::commasepstream& ss, Extensible* container)
{
	std::string token;
	ss.GetToken(token);

	User* user = ServerInstance->FindUUID(token);
	if (!user)
		user = ServerInstance->FakeClient;

	User* const usertarget = (this->type == EXT_USER ? static_cast<User*>(container) : NULL);
	Channel* const chantarget = (this->type != EXT_USER ? static_cast<Channel*>(container) : NULL);

	TokenType tt = TT_KEY;
	std::string keyname;
	std::string keyvalue;
	ExtData::TSValue::Timestamp ts;

	while (ss.GetToken(token))
	{
		if (tt == TT_KEY)
		{
			tt = TT_TS;
			keyname.swap(token);
		}
		else if (tt == TT_VALUE)
		{
			tt = TT_KEY;
			keyvalue.clear();
			stdalgo::string::unescape<',', 'c'>(token, keyvalue);
			manager.SetMetadataRemote(user, usertarget, chantarget, keyname, ts, keyvalue);
		}
		else // if (tt == TT_TS)
		{
			tt = TT_VALUE;
			ts = ConvToUInt64(token);
		}
	}
}

void IRCv3::Metadata::UserExtItem::unserialize(SerializeFormat format, Extensible* container, const std::string& value)
{
	irc::commasepstream ss(value, true);

	// Unserialize subscriptions, if applicable
	User* const user = static_cast<User*>(container);
	if ((IS_LOCAL(user)) && (format != FORMAT_NETWORK))
	{
		std::string subscribedkeys;
		ss.GetToken(subscribedkeys);
		irc::spacesepstream subss(subscribedkeys);

		for (std::string token; subss.GetToken(token); )
			manager.Subscribe(static_cast<LocalUser*>(user), token, UINT_MAX);
	}

	// Unserialize keys and their values
	UnserializeKeyMap(ss, container);
}

void IRCv3::Metadata::ChanExtItem::free(Extensible* container, void* item)
{
	ExtData* extdata = static_cast<ExtData*>(item);
	ServerInstance->Logs->Log(MODNAME, LOG_DEBUG, "Free extdata %p", (void*)extdata);
	manager.ClearAll(ServerInstance->FakeClient, NULL, static_cast<Channel*>(container), false);
	delete extdata;
}

class CommandMetadataRequest : public Command
{
 	IRCv3::Metadata::Manager& manager;

 public:
	CommandMetadataRequest(Module* mod, IRCv3::Metadata::Manager& managerref)
		: Command(mod, "MDREQ", 2)
		, manager(managerref)
	{
		// MDREQ <target> <keyname>[,<keyname>] [:<keyvalue>]
		flags_needed = FLAG_SERVERONLY;
	}

	CmdResult Handle(const std::vector<std::string>& parameters, User* user)
	{
		User* target = ServerInstance->FindUUID(parameters[0]);
		if ((!target) || (!IS_LOCAL(target)))
			return CMD_FAILURE;

		if (parameters.size() > 2)
		{
			manager.SetMetadata(user, target, NULL, parameters[1], parameters.back(), UINT_MAX);
		}
		else
		{
			irc::commasepstream ss(parameters[1]);
			for (std::string keyname; ss.GetToken(keyname); )
				manager.DeleteMetadata(user, target, NULL, keyname);
		}
		return CMD_SUCCESS;
	}
};

class CommandMetadata : public SplitCommand
{
	class Subcommand
	{
	 public:
		enum Value
		{
			METADATA_LIST,
			METADATA_GET,
			METADATA_SET,
			METADATA_CLEAR,
			METADATA_SUB,
			METADATA_UNSUB,
			METADATA_SUBS,
			METADATA_SYNC,
			METADATA_INVALID
		};

		Subcommand(const std::string& str)
		{
			if (!strcasecmp(str.c_str(), "LIST"))
				subcmd = METADATA_LIST;
			else if (!strcasecmp(str.c_str(), "GET"))
				subcmd = METADATA_GET;
			else if (!strcasecmp(str.c_str(), "SET"))
				subcmd = METADATA_SET;
			else if (!strcasecmp(str.c_str(), "CLEAR"))
				subcmd = METADATA_CLEAR;
			else if (!strcasecmp(str.c_str(), "SUB"))
				subcmd = METADATA_SUB;
			else if (!strcasecmp(str.c_str(), "UNSUB"))
				subcmd = METADATA_UNSUB;
			else if (!strcasecmp(str.c_str(), "SUBS"))
				subcmd = METADATA_SUBS;
			else if (!strcasecmp(str.c_str(), "SYNC"))
				subcmd = METADATA_SYNC;
			else
				subcmd = METADATA_INVALID;
		}

		bool IsMultiKey() const { return (subcmd != METADATA_SET); }
		bool IsMutating() const { return ((subcmd == METADATA_SET) || (subcmd == METADATA_CLEAR)); }
		bool IsValid() const { return (subcmd != METADATA_INVALID); }
		bool operator==(Value other) const { return (subcmd == other); }
	 private:
 		Value subcmd;
	};

 	IRCv3::Metadata::Manager& manager;

	static void FindTarget(User* user, const std::string& strtarget, User*& usertarget, Channel*& chantarget)
	{
		// An '*' char can be specified to indicate that the target is the client itself
		if (strtarget == "*")
			usertarget = user;
		else if (strtarget[0] == '#')
			chantarget = ServerInstance->FindChan(strtarget);
		else
			usertarget = ServerInstance->FindNickOnly(strtarget);
	}

	void DoList(LocalUser* user, User* usertarget, Channel* chantarget, const std::string& targetname)
	{
		ExtData* extdata = manager.GetExtData(usertarget, chantarget);
		if (extdata)
		{
			for (ExtData::KeyMap::iterator i = extdata->keymap.begin(); i != extdata->keymap.end(); )
			{
				const std::string& keyname = i->first;
				const ExtData::TSValue* tsv = extdata->IterToTsv(i);
				if (!tsv)
					continue;

				user->WriteNumeric(RPL_KEYVALUE, targetname, keyname, '*', tsv->value);
			}
		}
	}

	static const std::string* GetKeyValue(const ExtData* extdata, const std::string& keyname)
	{
		if (!extdata)
			return NULL;
		return extdata->GetValue(keyname);
	}

	bool CheckChannelPermission(LocalUser* user, Channel* chan, Subcommand subcmd)
	{
		// Read: anyone inside the chan and opers with the metadata/auspex priv even when not joined
		// Write: anyone with op rank or higher and opers with the metadata/set priv even when not joined
		if (user->IsOper())
		{
			if ((!subcmd.IsMutating()) && (user->HasPrivPermission("metadata/auspex")))
				return true;
			if (user->HasPrivPermission("metadata/set"))
				return true;
		}
		Membership* const memb = chan->GetUser(user);
		if (!memb)
			return false;
		if (!subcmd.IsMutating())
			return true;
		return (memb->getRank() >= OP_VALUE);
	}

	bool CheckUserPermission(LocalUser* user, User* usertarget, Subcommand subcmd)
	{
		// Read: any user may read the metadata of any user
		// Write: any user may write their own metadata and opers with the metadata/set priv can write the metadata of any user
		if ((!subcmd.IsMutating()) || (user == usertarget))
			return true;
		if (user->HasPrivPermission("metadata/set"))
			return true;
		return false;
	}

	bool CheckPermission(LocalUser* user, User* usertarget, Channel* chantarget, Subcommand subcmd)
	{
		if (usertarget)
			return CheckUserPermission(user, usertarget, subcmd);
		return CheckChannelPermission(user, chantarget, subcmd);
	}

	void HandleSubUnsub(LocalUser* user, const std::vector<std::string>& parameters, bool sub)
	{
		Numeric::Builder<' '> numeric(user, (sub ? RPL_METADATASUBOK : RPL_METADATAUNSUBOK));
		LocalUserExtData* const extdata = static_cast<LocalUserExtData*>(manager.GetExtData(user, NULL, sub));
		for (std::vector<std::string>::const_iterator i = parameters.begin()+2; i != parameters.end(); ++i)
		{
			const std::string& keyname = *i;
			if (!ValidateKeyName(user, keyname))
				continue;

			if (sub)
			{
				IRCv3::Metadata::Manager::SubscribeResult res = manager.Subscribe(extdata, keyname, maxsub);
				if (res == IRCv3::Metadata::Manager::SUB_TOOMANY)
				{
					user->WriteNumeric(ERR_METADATATOOMANYSUBS, keyname);
					break;
				}
			}
			else
				manager.Unsubscribe(extdata, keyname);

			numeric.Add(keyname);
		}

		numeric.Flush();
	}

	static bool ValidateKeyName(LocalUser* user, const std::string& keyname)
	{
		if (IRCv3::Metadata::Manager::IsValidKeyName(keyname))
			return true;

		user->WriteNumeric(ERR_KEYINVALID, keyname, "Invalid metadata key");
		return false;
	}

 public:
	unsigned int maxmetadata;
	unsigned int maxkeylength;
	unsigned int maxvaluelength;
	unsigned int maxsub;

	CommandMetadata(Module* mod, IRCv3::Metadata::Manager& managerref)
		: SplitCommand(mod, "METADATA", 2, 0)
		, manager(managerref)
	{
	}

	CmdResult HandleLocal(const std::vector<std::string>& parameters, LocalUser* user)
	{
		Subcommand const subcmd(parameters[1]);
		if (!subcmd.IsValid())
			return CMD_FAILURE;

		Channel* chantarget = NULL;
		User* usertarget = NULL;
		FindTarget(user, parameters[0], usertarget, chantarget);
		if ((!usertarget) && (!chantarget))
		{
			user->WriteNumeric(ERR_TARGETINVALID, parameters[0], "Invalid metadata target");
			return CMD_FAILURE;
		}

		const std::string& targetname = usertarget ? usertarget->nick : chantarget->name;

		if (!CheckPermission(user, usertarget, chantarget, subcmd))
		{
			user->WriteNumeric(ERR_KEYNOPERMISSION, targetname, (subcmd.IsMultiKey() ? "*" : parameters[1]), "Permission denied");
			return CMD_FAILURE;
		}

		if (subcmd == Subcommand::METADATA_GET)
		{
			// METADATA <Target> GET key1 key2 ...
			if (parameters.size() < 3)
				return CMD_FAILURE;

			const ExtData* extdata = manager.GetExtData(usertarget, chantarget);
			for (std::vector<std::string>::const_iterator i = parameters.begin()+2; i != parameters.end(); ++i)
			{
				const std::string& keyname = *i;
				if (!ValidateKeyName(user, keyname))
					continue;

				// extdata may be NULL, this is handled by GetKeyValue()
				const std::string* keyvalue = GetKeyValue(extdata, keyname);
				if (!keyvalue)
				{
					user->WriteNumeric(ERR_NOMATCHINGKEY, targetname, keyname, "Key not set");
					continue;
				}

				user->WriteNumeric(RPL_KEYVALUE, targetname, keyname, '*', *keyvalue);
			}
		}
		else if (subcmd == Subcommand::METADATA_SET)
		{
			if (parameters.size() < 3)
				return CMD_FAILURE;

			const std::string& keyname = parameters[2];
			if (!ValidateKeyName(user, keyname))
				return CMD_FAILURE;

			// Set or delete?
			if (parameters.size() > 3)
			{
				if ((parameters[3].length() > maxvaluelength) || (keyname.length() > maxkeylength))
				{
					user->WriteNumeric(ERR_KEYNOPERMISSION, targetname, keyname, "Permission denied");
					return CMD_FAILURE;
				}

				IRCv3::Metadata::Manager::SetResult result = manager.SetMetadata(user, usertarget, chantarget, keyname, parameters[3], maxmetadata);
				if (result == IRCv3::Metadata::Manager::SR_TOOMANY)
				{
					user->WriteNumeric(ERR_METADATALIMIT, targetname, "Metadata limit reached");
					return CMD_FAILURE;
				}

				user->WriteNumeric(RPL_KEYVALUE, targetname, keyname, '*', parameters[3]);
			}
			else
			{
				IRCv3::Metadata::Manager::DeleteResult result = manager.DeleteMetadata(user, usertarget, chantarget, keyname);
				if (result == IRCv3::Metadata::Manager::DR_NOSUCHKEY)
				{
					user->WriteNumeric(ERR_KEYNOTSET, targetname, keyname, "Key not set");
					return CMD_FAILURE;
				}

				user->WriteNumeric(RPL_KEYVALUE, targetname, keyname, '*');
			}
		}
		else if (subcmd == Subcommand::METADATA_LIST)
		{
			DoList(user, usertarget, chantarget, targetname);
		}
		else if (subcmd == Subcommand::METADATA_CLEAR)
		{
			DoList(user, usertarget, chantarget, targetname);
			manager.ClearAll(user, usertarget, chantarget);
		}
		else if (subcmd == Subcommand::METADATA_SUB)
		{
			if (parameters.size() < 3)
				return CMD_FAILURE;
			HandleSubUnsub(user, parameters, true);
		}
		else if (subcmd == Subcommand::METADATA_UNSUB)
		{
			if (parameters.size() < 3)
				return CMD_FAILURE;
			HandleSubUnsub(user, parameters, false);
		}
		else if (subcmd == Subcommand::METADATA_SUBS)
		{
			LocalUserExtData* extdata = static_cast<LocalUserExtData*>(manager.GetExtData(user, NULL));
			if (extdata)
			{
				Numeric::Builder<' '> numeric(user, RPL_METADATASUBS);
				const LocalUserExtData::SubscriptionSet& subs = extdata->GetSubscriptions();
				for (LocalUserExtData::SubscriptionSet::const_iterator i = subs.begin(); i != subs.end(); ++i)
					numeric.Add(*i);
				numeric.Flush();
			}
		}
		else if (subcmd == Subcommand::METADATA_SYNC)
		{
			if (!chantarget)
				return CMD_FAILURE;
			manager.AttemptMemberSync(user, chantarget);
			// No RPL_METADATAEND
			return CMD_SUCCESS;
		}

		user->WriteNumeric(RPL_METADATAEND, "End of metadata");
		return CMD_SUCCESS;
	}
};

class ModuleIRCv3Metadata : public Module
{
	IRCv3::Metadata::Manager manager;
	CommandMetadata cmd;
	CommandMetadataRequest cmdreq;

 public:
	ModuleIRCv3Metadata()
		: manager(this)
		, cmd(this, manager)
		, cmdreq(this, manager)
	{
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		ConfigTag* tag = ServerInstance->Config->ConfValue("metadata");
		cmd.maxmetadata = tag->getInt("max", 30, 1);
		cmd.maxvaluelength = tag->getInt("maxvaluelength", UINT_MAX, 1);
		cmd.maxkeylength = tag->getInt("maxkeylength", 32, 1);
		cmd.maxsub = tag->getInt("maxsub", 30, 0);
	}

	void OnPostJoin(Membership* memb) CXX11_OVERRIDE
	{
		LocalUser* const localuser = IS_LOCAL(memb->user);
		if (localuser)
			manager.OnJoin(localuser, memb->chan);
	}

	void On005Numeric(std::map<std::string, std::string>& tokens) CXX11_OVERRIDE
	{
		tokens["METADATA"] = ConvToStr(cmd.maxmetadata);
	}

	void OnGarbageCollect() CXX11_OVERRIDE
	{
		const user_hash& users = ServerInstance->Users.GetUsers();
		for (user_hash::const_iterator i = users.begin(); i != users.end(); ++i)
		{
			User* user = i->second;
			manager.GC(user);
		}

		const chan_hash& chans = ServerInstance->GetChans();
		for (chan_hash::const_iterator i = chans.begin(); i != chans.end(); ++i)
		{
			Channel* chan = i->second;
			manager.GC(chan);
		}
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides IRCv3.2 metadata support", VF_VENDOR | VF_COMMON);
	}
};

MODULE_INIT(ModuleIRCv3Metadata)
