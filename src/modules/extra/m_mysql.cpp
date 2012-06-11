/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2006-2007, 2009 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2006-2009 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2008 Robin Burchell <robin+git@viroteck.net>
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


/* Stop mysql wanting to use long long */
#define NO_CLIENT_LONG_LONG

#include "inspircd.h"
#include <mysql.h>
#include "sql.h"

#ifdef WINDOWS
# pragma comment(lib, "mysqlclient.lib")
# pragma comment(lib, "advapi32.lib")
# pragma comment(linker, "/NODEFAULTLIB:LIBCMT")
#endif

namespace m_mysql {

/* VERSION 3 API: With nonblocking (threaded) requests */

/* $ModDesc: SQL Service Provider module for all other m_sql* modules */
/* $CompileFlags: exec("mysql_config --include") */
/* $LinkerFlags: exec("mysql_config --libs_r") rpath("mysql_config --libs_r") */
/* $ModDep: m_sqlv2.h */

/* THE NONBLOCKING MYSQL API!
 *
 * MySQL provides no nonblocking (asyncronous) API of its own, and its developers recommend
 * that instead, you should thread your program. This is what i've done here to allow for
 * asyncronous SQL requests via mysql. The way this works is as follows:
 *
 * The module spawns a thread via class Thread, and performs its mysql queries in this thread,
 * using a queue with priorities. There is a mutex on either end which prevents two threads
 * adjusting the queue at the same time, and crashing the ircd. Every 50 milliseconds, the
 * worker thread wakes up, and checks if there is a request at the head of its queue.
 * If there is, it processes this request, blocking the worker thread but leaving the ircd
 * thread to go about its business as usual. During this period, the ircd thread is able
 * to insert futher pending requests into the queue.
 *
 * Once the processing of a request is complete, it is removed from the incoming queue to
 * an outgoing queue, and initialized as a 'response'. The worker thread then signals the
 * ircd thread (via a loopback socket) of the fact a result is available, by sending the
 * connection ID through the connection.
 *
 * The ircd thread then mutexes the queue once more, reads the outbound response off the head
 * of the queue, and sends it on its way to the original calling module.
 *
 * XXX: You might be asking "why doesnt he just send the response from within the worker thread?"
 * The answer to this is simple. The majority of InspIRCd, and in fact most ircd's are not
 * threadsafe. This module is designed to be threadsafe and is careful with its use of threads,
 * however, if we were to call a module's OnRequest even from within a thread which was not the
 * one the module was originally instantiated upon, there is a chance of all hell breaking loose
 * if a module is ever put in a re-enterant state (stack corruption could occur, crashes, data
 * corruption, and worse, so DONT think about it until the day comes when InspIRCd is 100%
 * gauranteed threadsafe!)
 *
 * For a diagram of this system please see http://wiki.inspircd.org/Mysql2
 */

class SQLConnection;
class MySQLresult;

typedef std::map<std::string, SQLConnection*> ConnMap;

/** MySQL module
 *  */
class ModuleSQL : public Module
{
 public:
	ConnMap connections; // main thread only

	ModuleSQL();
	void init();
	~ModuleSQL();
	void ReadConfig(ConfigReadStatus&);
	Version GetVersion();
};

#if !defined(MYSQL_VERSION_ID) || MYSQL_VERSION_ID<32224
#define mysql_field_count mysql_num_fields
#endif

/** Represents a mysql result set
 */
class MySQLresult : public SQLResult
{
 public:
	SQLerror err;
	int currentrow;
	int rows;
	std::vector<std::string> colnames;
	std::vector<SQLEntries> fieldlists;

	MySQLresult(MYSQL_RES* res, int affected_rows) : err(SQL_NO_ERROR), currentrow(0), rows(0)
	{
		if (affected_rows >= 1)
		{
			rows = affected_rows;
			fieldlists.resize(rows);
		}
		unsigned int field_count = 0;
		if (res)
		{
			MYSQL_ROW row;
			int n = 0;
			while ((row = mysql_fetch_row(res)))
			{
				if (fieldlists.size() < (unsigned int)rows+1)
				{
					fieldlists.resize(fieldlists.size()+1);
				}
				field_count = 0;
				MYSQL_FIELD *fields = mysql_fetch_fields(res);
				if(mysql_num_fields(res) == 0)
					break;
				if (fields && mysql_num_fields(res))
				{
					colnames.clear();
					while (field_count < mysql_num_fields(res))
					{
						std::string a = (fields[field_count].name ? fields[field_count].name : "");
						if (row[field_count])
							fieldlists[n].push_back(SQLEntry(row[field_count]));
						else
							fieldlists[n].push_back(SQLEntry());
						colnames.push_back(a);
						field_count++;
					}
					n++;
				}
				rows++;
			}
			mysql_free_result(res);
			res = NULL;
		}
	}

	MySQLresult(SQLerror& e) : err(e)
	{

	}

	~MySQLresult()
	{
	}

	virtual int Rows()
	{
		return rows;
	}

	virtual void GetCols(std::vector<std::string>& result)
	{
		result.assign(colnames.begin(), colnames.end());
	}

	virtual SQLEntry GetValue(int row, int column)
	{
		if ((row >= 0) && (row < rows) && (column >= 0) && (column < (int)fieldlists[row].size()))
		{
			return fieldlists[row][column];
		}
		return SQLEntry();
	}

	virtual bool GetRow(SQLEntries& result)
	{
		if (currentrow < rows)
		{
			result.assign(fieldlists[currentrow].begin(), fieldlists[currentrow].end());
			currentrow++;
			return true;
		}
		else
		{
			result.clear();
			return false;
		}
	}
};

/** Represents a connection to a mysql database
 */
class SQLConnection : public SQLProvider
{
 public:
	reference<ConfigTag> config;
	MYSQL *connection;
	Mutex lock;

	// This constructor creates an SQLConnection object with the given credentials, but does not connect yet.
	SQLConnection(Module* p, ConfigTag* tag) : SQLProvider(p, "SQL/" + tag->getString("id")),
		config(tag), connection(NULL)
	{
	}

	~SQLConnection()
	{
		Close();
	}

	// This method connects to the database using the credentials supplied to the constructor, and returns
	// true upon success.
	bool Connect()
	{
		unsigned int timeout = 1;
		connection = mysql_init(connection);
		mysql_options(connection,MYSQL_OPT_CONNECT_TIMEOUT,(char*)&timeout);
		std::string host = config->getString("host");
		std::string user = config->getString("user");
		std::string pass = config->getString("pass");
		std::string dbname = config->getString("name");
		int port = config->getInt("port");
		bool rv = mysql_real_connect(connection, host.c_str(), user.c_str(), pass.c_str(), dbname.c_str(), port, NULL, 0);
		if (!rv)
			return rv;
		std::string initquery;
		if (config->readString("initialquery", initquery))
		{
			mysql_query(connection,initquery.c_str());
		}
		return true;
	}

	ModuleSQL* Parent()
	{
		return (ModuleSQL*)(Module*)creator;
	}

	MySQLresult* DoBlockingQuery(const std::string& query)
	{

		/* Parse the command string and dispatch it to mysql */
		if (CheckConnection() && !mysql_real_query(connection, query.data(), query.length()))
		{
			/* Successfull query */
			MYSQL_RES* res = mysql_use_result(connection);
			unsigned long rows = mysql_affected_rows(connection);
			return new MySQLresult(res, rows);
		}
		else
		{
			/* XXX: See /usr/include/mysql/mysqld_error.h for a list of
			 * possible error numbers and error messages */
			SQLerror e(SQL_QREPLY_FAIL, ConvToStr(mysql_errno(connection)) + std::string(": ") + mysql_error(connection));
			return new MySQLresult(e);
		}
	}

	bool CheckConnection()
	{
		if (!connection || mysql_ping(connection) != 0)
			return Connect();
		return true;
	}

	std::string GetError()
	{
		return mysql_error(connection);
	}

	void Close()
	{
		mysql_close(connection);
	}

	void submit(SQLQuery*, const std::string&);
	void submit(SQLQuery*, const std::string& q, const ParamL& p);
	void submit(SQLQuery*, const std::string& q, const ParamM& p);
};

class QueryJob : public Job
{
 protected:
	SQLQuery* const query;
	SQLConnection* conn;
 private:
	MySQLresult* result;
 public:
	QueryJob(SQLQuery* Q, SQLConnection* C)
		: Job(C->creator), query(Q), conn(C), result(NULL)
	{
	}
	~QueryJob() { }

	virtual MySQLresult* exec() = 0;

	void run()
	{
		Mutex::Lock lock(conn->lock);
		if (!IsCancelled())
			result = exec();
	}

	void finish()
	{
		if (!result)
		{
			SQLerror err(SQL_BAD_DBID, "Query cancelled");
			query->OnError(err);
		}
		else if (result->err.id == SQL_NO_ERROR)
			query->OnResult(*result);
		else
			query->OnError(result->err);
		delete query;
		delete result;
	}

	bool BlocksUnload(Module* m)
	{
		if (m == owner || m == query->creator)
			return true;
		return false;
	}
};

class QueryJobStatic : public QueryJob
{
	const std::string query_str;
 public:
	QueryJobStatic(SQLQuery* Q, SQLConnection* C, const std::string& S)
		: QueryJob(Q, C), query_str(S) {}

	MySQLresult* exec()
	{
		return conn->DoBlockingQuery(query_str);
	}
};

class QueryJobList : public QueryJob
{
 public:
	const std::string format;
	const ParamL p;
	QueryJobList(SQLQuery* Q, SQLConnection* C, const std::string& F, const ParamL& P)
		: QueryJob(Q, C), format(F), p(P) {}
	
	MySQLresult* exec()
	{
		std::string res;
		unsigned int param = 0;
		for(std::string::size_type i = 0; i < format.length(); i++)
		{
			if (format[i] != '?')
				res.push_back(format[i]);
			else
			{
				if (param < p.size())
				{
					std::string parm = p[param++];
					char buffer[MAXBUF];
					mysql_real_escape_string(conn->connection, buffer, parm.data(), parm.length());
					res.append(buffer);
				}
			}
		}
		return conn->DoBlockingQuery(res);
	}
};

class QueryJobMap : public QueryJob
{
 public:
	const std::string format;
	const ParamM p;
	QueryJobMap(SQLQuery* Q, SQLConnection* C, const std::string& F, const ParamM& P)
		: QueryJob(Q, C), format(F), p(P), subst(this) {}

	class FormatSubstFn : public FormatSubstitute
	{
	 public:
		QueryJobMap* me;
		FormatSubstFn(QueryJobMap* Me) : me(Me) {}
		std::string lookup(const std::string& key)
		{
			char buffer[MAXBUF];
			ParamM::const_iterator it = me->p.find(key);
			if (it == me->p.end())
				return "";
			mysql_real_escape_string(me->conn->connection, buffer, it->second.data(), it->second.length());
			return buffer;
		}
	} subst;

	MySQLresult* exec()
	{
		return conn->DoBlockingQuery(subst.format(format));
	}
};

void SQLConnection::submit(SQLQuery* call, const std::string& qs)
{
	ServerInstance->Threads->Submit(new QueryJobStatic(call, this, qs));
}

void SQLConnection::submit(SQLQuery* call, const std::string& format, const ParamL& p)
{
	ServerInstance->Threads->Submit(new QueryJobList(call, this, format, p));
}

void SQLConnection::submit(SQLQuery* call, const std::string& format, const ParamM& p)
{
	ServerInstance->Threads->Submit(new QueryJobMap(call, this, format, p));
}

ModuleSQL::ModuleSQL()
{
}

void ModuleSQL::init()
{
}

ModuleSQL::~ModuleSQL()
{
	for(ConnMap::iterator i = connections.begin(); i != connections.end(); i++)
	{
		delete i->second;
	}
}

class CleanupJob : public Job
{
 public:
	SQLConnection* conn;
	CleanupJob(SQLConnection* c) : Job(c->creator), conn(c) {}
	void run()
	{
		conn->lock.lock();
		// TODO wait for any not-yet-started pending queries to finish
		conn->lock.unlock();
	}
	void finish()
	{
		delete conn;
	}
};

void ModuleSQL::ReadConfig(ConfigReadStatus&)
{
	ConnMap conns;
	ConfigTagList tags = ServerInstance->Config->GetTags("database");
	for(ConfigIter i = tags.first; i != tags.second; i++)
	{
		if (i->second->getString("module", "mysql") != "mysql")
			continue;
		std::string id = i->second->getString("id");
		ConnMap::iterator curr = connections.find(id);
		if (curr == connections.end())
		{
			SQLConnection* conn = new SQLConnection(this, i->second);
			conns.insert(std::make_pair(id, conn));
			ServerInstance->Modules->AddService(*conn);
		}
		else
		{
			conns.insert(*curr);
			connections.erase(curr);
		}
	}

	// now clean up the deleted databases
	for(ConnMap::iterator i = connections.begin(); i != connections.end(); i++)
	{
		ServerInstance->Modules->DelService(*i->second);
		ServerInstance->Threads->Submit(new CleanupJob(i->second));
	}
	connections.swap(conns);
}

Version ModuleSQL::GetVersion()
{
	return Version("MySQL support", VF_VENDOR);
}

}

using m_mysql::ModuleSQL;

MODULE_INIT(ModuleSQL)
