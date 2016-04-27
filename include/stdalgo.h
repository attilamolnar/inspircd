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


#pragma once

namespace stdalgo
{
	namespace vector
	{
		/**
		 * Erase a single element from a vector by overwriting it with a copy of the last element,
		 * which is then removed. This, in contrast to vector::erase(), does not result in all
		 * elements after the erased element being moved.
		 * @param vect Vector to remove the element from
		 * @param it Iterator to the element to remove
		 * @return Nothing, but all iterators, references and pointers to the erased element and the
		 * last element are invalidated
		 */
		template <typename T>
		inline void swaperase(typename std::vector<T>& vect, const typename std::vector<T>::iterator& it)
		{
			*it = vect.back();
			vect.pop_back();
		}

		/**
		 * Find and if exists, erase a single element from a vector by overwriting it with a
		 * copy of the last element, which is then removed. This, in contrast to vector::erase(),
		 * does not result in all elements after the erased element being moved.
		 * If the given value occurs multiple times, the one with the lowest index is removed.
		 * Individual elements are compared to the given value using operator==().
		 * @param vect Vector to remove the element from
		 * @param val Value of the element to look for and remove
		 * @return True if the element was found and removed, false if it wasn't found.
		 * If true, all iterators, references and pointers pointing to either the first element that
		 * is equal to val or to the last element are invalidated.
		 */
		template <typename T>
		inline bool swaperase(typename std::vector<T>& vect, const T& val)
		{
			const typename std::vector<T>::iterator it = std::find(vect.begin(), vect.end(), val);
			if (it != vect.end())
			{
				swaperase(vect, it);
				return true;
			}
			return false;
		}
	}

	/**
	 * Deleter that uses operator delete to delete the item
	 */
	template <typename T>
	struct defaultdeleter
	{
		void operator()(T* o)
		{
			delete o;
		}
	};

	/**
	 * Deleter that adds the item to the cull list, that is, queues it for
	 * deletion at the end of the current mainloop iteration
	 */
	struct culldeleter
	{
		void operator()(classbase* item);
	};

	/**
	 * Deletes all elements in a container using operator delete
	 * @param cont The container containing the elements to delete
	 */
	template <template<typename, typename> class Cont, typename T, typename Alloc>
	inline void delete_all(const Cont<T*, Alloc>& cont)
	{
		std::for_each(cont.begin(), cont.end(), defaultdeleter<T>());
	}

	/**
	 * Remove an element from a container
	 * @param cont Container to remove the element from
	 * @param val Value of the element to look for and remove
	 * @return True if the element was found and removed, false otherwise
	 */
	template <template<typename, typename> class Cont, typename T, typename Alloc>
	inline bool erase(Cont<T, Alloc>& cont, const T& val)
	{
		const typename Cont<T, Alloc>::iterator it = std::find(cont.begin(), cont.end(), val);
		if (it != cont.end())
		{
			cont.erase(it);
			return true;
		}
		return false;
	}

	/**
	 * Check if an element with the given value is in a container. Equivalent to (std::find(cont.begin(), cont.end(), val) != cont.end()).
	 * @param cont Container to find the element in
	 * @param val Value of the element to look for
	 * @return True if the element was found in the container, false otherwise
	 */
	template <template<typename, typename> class Cont, typename T, typename Alloc>
	inline bool isin(const Cont<T, Alloc>& cont, const T& val)
	{
		return (std::find(cont.begin(), cont.end(), val) != cont.end());
	}

	namespace string
	{
		/**
		 * Escape a string
		 * @param str String to escape
		 * @param out Output, must not be the same string as str
		 */
		template <char from, char to, char esc>
		inline void escape(const std::string& str, std::string& out)
		{
			for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
			{
				char c = *i;
				if (c == esc)
					out.append(2, esc);
				else
				{
					if (c == from)
					{
						out.push_back(esc);
						c = to;
					}
					out.push_back(c);
				}
			}
		}

		/**
		 * Escape a string using the backslash character as the escape character
		 * @param str String to escape
		 * @param out Output, must not be the same string as str
		 */
		template <char from, char to>
		inline void escape(const std::string& str, std::string& out)
		{
			escape<from, to, '\\'>(str, out);
		}

		/**
		 * Unescape a string
		 * @param str String to unescape
		 * @param out Output, must not be the same string as str
		 * @return True if the string was unescaped, false if an invalid escape sequence is present in the input in which case out will contain a partially unescaped string
		 */
		template<char from, char to, char esc>
		inline bool unescape(const std::string& str, std::string& out)
		{
			for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
			{
				char c = *i;
				if (c == '\\')
				{
					++i;
					if (i == str.end())
						return false;

					char nextc = *i;
					if (nextc == esc)
						c = esc;
					else if (nextc != to)
						return false; // Invalid escape sequence
					else
						c = from;
				}
				out.push_back(c);
			}
			return true;
		}

		/**
		 * Unescape a string using the backslash character as the escape character
		 * @param str String to unescape
		 * @param out Output, must not be the same string as str
		 * @return True if the string was unescaped, false if an invalid escape sequence is present in the input in which case out will contain a partially unescaped string
		 */
		template <char from, char to>
		inline bool unescape(const std::string& str, std::string& out)
		{
			return unescape<from, to, '\\'>(str, out);
		}
	}
}
