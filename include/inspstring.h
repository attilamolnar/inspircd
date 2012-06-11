/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2007 Craig Edwards <craigedwards@brainbox.cc>
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


#ifndef INSPSTRING_H
#define INSPSTRING_H

// This (inspircd_config) is needed as inspstring doesn't pull in the central header
#include <cstring>
//#include <cstddef>

#ifndef HAS_STRLCPY
/** strlcpy() implementation for systems that don't have it (linux) */
CoreExport size_t strlcpy(char *dst, const char *src, size_t siz);
/** strlcat() implementation for systems that don't have it (linux) */
CoreExport size_t strlcat(char *dst, const char *src, size_t siz);
#endif

/** charlcat() will append one character to a string using the same
 * safety scemantics as strlcat().
 * @param x The string to operate on
 * @param y the character to append to the end of x
 * @param z The maximum allowed length for z including null terminator
 */
CoreExport int charlcat(char* x,char y,int z);
/** charremove() will remove all instances of a character from a string
 * @param mp The string to operate on
 * @param remove The character to remove
 */
CoreExport bool charremove(char* mp, char remove);

/** Binary to hexadecimal conversion */
CoreExport std::string BinToHex(const std::string& data);
/** Base64 encode */
CoreExport std::string BinToBase64(const std::string& data, const char* table = NULL, char pad = 0);
/** Base64 decode */
CoreExport std::string Base64ToBin(const std::string& data, const char* table = NULL);

/** Wrapping class to allow simple replacement of lookup function */
class CoreExport FormatSubstitute : public interfacebase
{
 public:
	/** Substitute $var expressions within the parameter */
	std::string format(const std::string& what);
	/** Variable lookup function: given a name, give the value */
	virtual std::string lookup(const std::string&) = 0;
};

class CoreExport MapFormatSubstitute : public FormatSubstitute
{
 public:
	const SubstMap& map;
	MapFormatSubstitute(const SubstMap& Map) : map(Map) {}
	virtual std::string lookup(const std::string&);
};

/** Given format = "foo $bar $baz!" and Map('bar' => 'one'), returns "foo one !" */
inline std::string MapFormatSubst(const std::string& format, const SubstMap& Map)
{
	MapFormatSubstitute m(Map);
	return m.format(format);
}

#endif

