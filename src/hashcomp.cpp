/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2011 Jackmcbarn <jackmcbarn@jackmcbarn.no-ip.org>
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2005-2009 Craig Edwards <craigedwards@brainbox.cc>
 *   Copyright (C) 2007-2008 Robin Burchell <robin+git@viroteck.net>
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


/* $Core */

#include "inspircd.h"
#include "hashcomp.h"
#include "hash_map.h"

/******************************************************
 *
 * The hash functions of InspIRCd are the centrepoint
 * of the entire system. If these functions are
 * inefficient or wasteful, the whole program suffers
 * as a result. A lot of C programmers in the ircd
 * scene spend a lot of time debating (arguing) about
 * the best way to write hash functions to hash irc
 * nicknames, channels etc.
 * We are lucky as C++ developers as hash_map does
 * a lot of this for us. It does intellegent memory
 * requests, bucketing, search functions, insertion
 * and deletion etc. All we have to do is write some
 * overloaded comparison and hash value operators which
 * cause it to act in an irc-like way. The features we
 * add to the standard hash_map are:
 *
 * Case insensitivity: The hash_map will be case
 * insensitive.
 *
 * Scandanavian Comparisons: The characters [, ], \ will
 * be considered the lowercase of {, } and |.
 *
 ******************************************************/

/** A mapping of uppercase to lowercase, including scandinavian
 * 'oddities' as specified by RFC1459, e.g. { -> [, and | -> \
 */
unsigned const char rfc_case_insensitive_map[256] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,					/* 0-19 */
	20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,				/* 20-39 */
	40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,				/* 40-59 */
	60, 61, 62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,		/* 60-79 */
	112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 94, 95, 96, 97, 98, 99,		/* 80-99 */
	100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,	/* 100-119 */
	120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,	/* 120-139 */
	140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,	/* 140-159 */
	160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,	/* 160-179 */
	180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,	/* 180-199 */
	200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,	/* 200-219 */
	220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,	/* 220-239 */
	240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255				/* 240-255 */
};

/** Case insensitive map, ASCII rules.
 * That is;
 * [ != {, but A == a.
 */
unsigned const char ascii_case_insensitive_map[256] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,                                   /* 0-19 */
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,                         /* 20-39 */
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,                         /* 40-59 */
        60, 61, 62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,             /* 60-79 */
        112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 91, 92, 93, 94, 95, 96, 97, 98, 99,              /* 80-99 */
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,     /* 100-119 */
        120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,     /* 120-139 */
        140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,     /* 140-159 */
        160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179,     /* 160-179 */
        180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,     /* 180-199 */
        200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,     /* 200-219 */
        220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,     /* 220-239 */
        240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255                          /* 240-255 */
};

/** Case sensitive map.
 * Can technically also be used for ASCII case sensitive comparisons, as [ != {, etc.
 */
unsigned const char rfc_case_sensitive_map[256] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
        81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100,
        101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120,
        121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
        141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160,
        161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
        181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200,
        201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220,
        221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240,
        241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
};

/* convert a string to lowercase. Note following special circumstances
 * taken from RFC 1459. Many "official" server branches still hold to this
 * rule so i will too;
 *
 *  Because of IRC's scandanavian origin, the characters {}| are
 *  considered to be the lower case equivalents of the characters []\,
 *  respectively. This is a critical issue when determining the
 *  equivalence of two nicknames.
 */
void nspace::strlower(char *n)
{
	if (n)
	{
		for (char* t = n; *t; t++)
			*t = national_case_insensitive_map[(unsigned char)*t];
	}
}

#if defined(WINDOWS) && !defined(HASHMAP_DEPRECATED)
	size_t nspace::hash_compare<std::string, std::less<std::string> >::operator()(const std::string &s) const
#else
	#ifdef HASHMAP_DEPRECATED
		size_t CoreExport nspace::insensitive::operator()(const std::string &s) const
	#else
		size_t nspace::hash<std::string>::operator()(const std::string &s) const
	#endif
#endif
{
	/* XXX: NO DATA COPIES! :)
	 * The hash function here is practically
	 * a copy of the one in STL's hash_fun.h,
	 * only with *x replaced with national_case_insensitive_map[*x].
	 * This avoids a copy to use hash<const char*>
	 */
	register size_t t = 0;
	for (std::string::const_iterator x = s.begin(); x != s.end(); ++x) /* ++x not x++, as its faster */
		t = 5 * t + national_case_insensitive_map[(unsigned char)*x];
	return t;
}


#if defined(WINDOWS) && !defined(HASHMAP_DEPRECATED)
	size_t nspace::hash_compare<irc::string, std::less<irc::string> >::operator()(const irc::string &s) const
#else
	size_t CoreExport irc::hash::operator()(const irc::string &s) const
#endif
{
	register size_t t = 0;
	for (std::string::const_iterator x = s.value.begin(); x != s.value.end(); ++x) /* ++x not x++, as its faster */
		t = 5 * t + national_case_insensitive_map[(unsigned char)*x];
	return t;
}

bool irc::StrHashComp::operator()(const std::string& s1, const std::string& s2) const
{
	const unsigned char* n1 = (const unsigned char*)s1.c_str();
	const unsigned char* n2 = (const unsigned char*)s2.c_str();
	for (; *n1 && *n2; n1++, n2++)
		if (national_case_insensitive_map[*n1] != national_case_insensitive_map[*n2])
			return false;
	return (national_case_insensitive_map[*n1] == national_case_insensitive_map[*n2]);
}

/******************************************************
 *
 * This is the implementation of our special irc::string
 * class which is a case-insensitive equivalent to
 * std::string which is not only case-insensitive but
 * can also do scandanavian comparisons, e.g. { = [, etc.
 *
 * This class depends on the const array 'national_case_insensitive_map'.
 *
 ******************************************************/

bool irc::irc_char_traits::eq(char c1st, char c2nd)
{
	return national_case_insensitive_map[(unsigned char)c1st] == national_case_insensitive_map[(unsigned char)c2nd];
}

bool irc::irc_char_traits::ne(char c1st, char c2nd)
{
	return national_case_insensitive_map[(unsigned char)c1st] != national_case_insensitive_map[(unsigned char)c2nd];
}

bool irc::irc_char_traits::lt(char c1st, char c2nd)
{
	return national_case_insensitive_map[(unsigned char)c1st] < national_case_insensitive_map[(unsigned char)c2nd];
}

int irc::irc_char_traits::compare(const char* str1, const char* str2, size_t n)
{
	for(unsigned int i = 0; i < n; i++)
	{
		if(national_case_insensitive_map[(unsigned char)*str1] > national_case_insensitive_map[(unsigned char)*str2])
			return 1;

		if(national_case_insensitive_map[(unsigned char)*str1] < national_case_insensitive_map[(unsigned char)*str2])
			return -1;

		if(*str1 == 0 || *str2 == 0)
		   	return 0;

		str1++;
		str2++;
	}
	return 0;
}

const char* irc::irc_char_traits::find(const char* s1, int  n, char c)
{
	while(n-- > 0 && national_case_insensitive_map[(unsigned char)*s1] != national_case_insensitive_map[(unsigned char)c])
		s1++;
	return (n >= 0) ? s1 : NULL;
}

std::string irc::irc_char_traits::remap(const std::string& source)
{
	std::string rv;
	std::string::size_type len = source.length();
	rv.reserve(len);
	for(size_t i=0; i < len; i++)
		rv.push_back(national_case_insensitive_map[(unsigned char)source[i]]);
	return rv;
}

irc::tokenstream::tokenstream(const std::string &source) : tokens(source), last_pushed(false)
{
	/* Record starting position and current position */
	last_starting_position = tokens.begin();
	n = tokens.begin();
}

irc::tokenstream::~tokenstream()
{
}

bool irc::tokenstream::GetToken(std::string &token)
{
	std::string::iterator lsp = last_starting_position;

	while (n != tokens.end())
	{
		/** Skip multi space, converting "  " into " "
		 */
		while ((n+1 != tokens.end()) && (*n == ' ') && (*(n+1) == ' '))
			n++;

		if ((last_pushed) && (*n == ':'))
		{
			/* If we find a token thats not the first and starts with :,
			 * this is the last token on the line
			 */
			std::string::iterator curr = ++n;
			n = tokens.end();
			token = std::string(curr, tokens.end());
			return true;
		}

		last_pushed = false;

		if ((*n == ' ') || (n+1 == tokens.end()))
		{
			/* If we find a space, or end of string, this is the end of a token.
			 */
			last_starting_position = n+1;
			last_pushed = *n == ' ';

			std::string strip(lsp, n+1 == tokens.end() ? n+1  : n++);
			while ((strip.length()) && (strip.find_last_of(' ') == strip.length() - 1))
				strip.erase(strip.end() - 1);

			token = strip;
			return !token.empty();
		}

		n++;
	}
	token.clear();
	return false;
}

bool irc::tokenstream::GetToken(irc::string &token)
{
	std::string stdstring;
	bool returnval = GetToken(stdstring);
	token = stdstring;
	return returnval;
}

bool irc::tokenstream::GetToken(int &token)
{
	std::string tok;
	bool returnval = GetToken(tok);
	token = ConvToInt(tok);
	return returnval;
}

bool irc::tokenstream::GetToken(long &token)
{
	std::string tok;
	bool returnval = GetToken(tok);
	token = ConvToInt(tok);
	return returnval;
}

irc::sepstream::sepstream(const std::string &source, char seperator, bool suppress_empty_items) : tokens(source), suppress_empty(suppress_empty_items), sep(seperator), endreached(false)
{
	n = tokens.begin();
	if(suppress_empty)
	{
		while(n != tokens.end() && *n == sep)
			++n;
		if(n == tokens.end())
			endreached = true;
	}
}

bool irc::sepstream::GetToken(std::string &token)
{
	if(endreached)
	{
		token = "";
		return false;
	}

	std::string::const_iterator lsp = n;

	for(;; ++n)
	{
		if(n == tokens.end())
		{
			endreached = true;
			token = std::string(lsp, n);
			if(suppress_empty)
			{
				std::string::size_type i = token.find_first_of(sep);
				if(i != std::string::npos)
					token.erase(i);
				return !token.empty();
			}
			else
				return true;
		}
		else if(*n == sep)
		{
			if(suppress_empty && (n+1 == tokens.end() || *(n+1) == sep))
				continue;
			token = std::string(lsp, n++);
			if(suppress_empty)
			{
				std::string::size_type i = token.find_first_of(sep);
				if(i != std::string::npos)
					token.erase(i);
				return !token.empty();
			}
			else
				return true;
		}
	}
}

std::string irc::sepstream::GetRemaining() const
{
	return std::string(n, tokens.end());
}

bool irc::sepstream::StreamEnd() const
{
	return endreached;
}

irc::sepstream::~sepstream()
{
}

std::string irc::hex(const unsigned char *raw, size_t rawsz)
{
	if (!rawsz)
		return "";

	/* EWW! This used to be using sprintf, which is WAY inefficient. -Special */

	const char *hex = "0123456789abcdef";
	static char hexbuf[MAXBUF];

	size_t i, j;
	for (i = 0, j = 0; j < rawsz; ++j)
	{
		hexbuf[i++] = hex[raw[j] / 16];
		hexbuf[i++] = hex[raw[j] % 16];
	}
	hexbuf[i] = 0;

	return hexbuf;
}

CoreExport const char* irc::Spacify(const char* n)
{
	static char x[MAXBUF];
	strlcpy(x,n,MAXBUF);
	for (char* y = x; *y; y++)
		if (*y == '_')
			*y = ' ';
	return x;
}

irc::stringjoiner::stringjoiner(const std::string &seperator, const std::vector<std::string> &sequence, int begin, int end)
{
	if (end < begin)
		throw "stringjoiner logic error, this causes problems.";

	for (int v = begin; v < end; v++)
		joined.append(sequence[v]).append(seperator);
	joined.append(sequence[end]);
}

irc::stringjoiner::stringjoiner(const std::string &seperator, const std::deque<std::string> &sequence, int begin, int end)
{
	if (end < begin)
		throw "stringjoiner logic error, this causes problems.";

	for (int v = begin; v < end; v++)
		joined.append(sequence[v]).append(seperator);
	joined.append(sequence[end]);
}

irc::stringjoiner::stringjoiner(const std::string &seperator, const char* const* sequence, int begin, int end)
{
	if (end < begin)
		throw "stringjoiner logic error, this causes problems.";

	for (int v = begin; v < end; v++)
		joined.append(sequence[v]).append(seperator);
	joined.append(sequence[end]);
}

std::string& irc::stringjoiner::GetJoined()
{
	return joined;
}

irc::portparser::portparser(const std::string &source, bool allow_overlapped) : in_range(0), range_begin(0), range_end(0), overlapped(allow_overlapped)
{
	sep = new irc::commasepstream(source);
	overlap_set.clear();
}

irc::portparser::~portparser()
{
	delete sep;
}

bool irc::portparser::Overlaps(long val)
{
	if (!overlapped)
		return false;

	if (overlap_set.find(val) == overlap_set.end())
	{
		overlap_set[val] = true;
		return false;
	}
	else
		return true;
}

long irc::portparser::GetToken()
{
	if (in_range > 0)
	{
		in_range++;
		if (in_range <= range_end)
		{
			if (!Overlaps(in_range))
			{
				return in_range;
			}
			else
			{
				while (((Overlaps(in_range)) && (in_range <= range_end)))
					in_range++;

				if (in_range <= range_end)
					return in_range;
			}
		}
		else
			in_range = 0;
	}

	std::string x;
	if (!sep->GetToken(x))
		return 0;

	while (Overlaps(atoi(x.c_str())))
	{
		if (!sep->GetToken(x))
			return 0;
	}

	std::string::size_type dash = x.rfind('-');
	if (dash != std::string::npos)
	{
		std::string sbegin = x.substr(0, dash);
		std::string send = x.substr(dash+1, x.length());
		range_begin = atoi(sbegin.c_str());
		range_end = atoi(send.c_str());

		if ((range_begin > 0) && (range_end > 0) && (range_begin < 65536) && (range_end < 65536) && (range_begin < range_end))
		{
			in_range = range_begin;
			return in_range;
		}
		else
		{
			/* Assume its just the one port */
			return atoi(sbegin.c_str());
		}
	}
	else
	{
		return atoi(x.c_str());
	}
}

/*const std::basic_string& SearchAndReplace(std::string& text, const std::string& pattern, const std::string& replace)
{
	std::string replacement;
	if ((!pattern.empty()) && (!text.empty()))
	{
		for (std::string::size_type n = 0; n != text.length(); ++n)
		{
			if (text.length() >= pattern.length() && text.substr(n, pattern.length()) == pattern)
			{
				replacement.append(replace);
				n = n + pattern.length() - 1;
			}
			else
			{
				replacement += text[n];
			}
		}
	}
	text = replacement;
	return text;
}*/
