/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
 *   License as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file lua.c
 * @brief Library functions for the lua module.
 *
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#include "config.h"
#include "lua.h"
#include "../../include/libradius.h"
#include "assert.h"


#include <lauxlib.h>
#include <lualib.h>


#define RLM_LUA_STACK_SET()	int _rlm_lua_stack_state = lua_gettop(L)
#define RLM_LUA_STACK_RESET()	lua_settop(L, _rlm_lua_stack_state)

fr_thread_local_setup(REQUEST *, rlm_lua_request);	/* macro */

static int get_attribute(lua_State *L);
static VALUE_PAIR* lua_to_c (REQUEST *request, lua_State *L, DICT_ATTR const *da);
static int lua_next_attr(lua_State *L);

static int rlm_lua_cdefs(lua_State *L)
{
	(void) luaL_dostring(L,"\
		ffi = require(\"ffi\")\
		ffi.cdef [[\
			typedef enum log_type {\
				L_AUTH = 2, L_INFO = 3, L_ERR = 4, L_WARN = 5,\
				L_PROXY	= 6, L_ACCT = 7, L_DBG = 16, L_DBG_WARN = 17,\
				L_DBG_ERR = 18, L_DBG_WARN2 = 19, L_DBG_ERR2 = 20} log_type_t;\
				int radlog(log_type_t lvl, char const *fmt, ...);\
			]]\
		Fr = ffi.load(\"libfreeradius-server.so\")");

	return 0;
}

static bool rlm_lua_isjit(lua_State *L)
{
	int idx;
	bool ret;
	RLM_LUA_STACK_SET();

	lua_getglobal(L, "jit");
	idx = lua_gettop(L);

	if (lua_isnil(L, idx)) {
		ret = false;
		goto done;
	}

	lua_getfield(L, idx, "version");
	idx = lua_gettop(L);

	if (lua_tostring(L, idx)) {
		ret = true;
		goto done;
	}
	ret = false;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

static int rlm_lua_debug(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		DEBUG("%i: %s", idx, message);
		lua_pop(L, 1);
	}

	return 0;
}

static int rlm_lua_info(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		INFO("%i: %s", idx, message);
		lua_pop(L, 1);
	}

	return 0;
}

static int rlm_lua_warn(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		WARN("%i: %s", idx, message);
		lua_pop(L, 1);
	}

	return 0;
}

static int rlm_lua_error(lua_State *L)
{
	int idx;

	while ((idx = lua_gettop(L))) {
		char const *message = lua_tostring(L, idx);
		ERROR("%i: %s", idx, message);
		lua_pop(L, 1);
	}

	return 0;
}

// radlog(L_DBG, "Top is %i, type is %s", lua_gettop(L), lua_typename(L, lua_type(L, lua_gettop(L))));
static void rlm_lua_error_old(REQUEST *request, lua_State *L)
{
	int top;
	char const *errstr;

	top = lua_gettop(L);
	errstr = lua_tostring(L, top);

	if (request) {
		REDEBUG("%s", errstr);
	} else {
		ERROR("%s", errstr);
	}
}

static int lua_check_arg(lua_State *L, char const *name)
{
	static double a = 5, b = 5;
	int ret;
	RLM_LUA_STACK_SET();

	lua_getglobal(L, name);
	lua_pushnumber(L, a);
	lua_pushnumber(L, b);

	if (lua_pcall(L, 2, 1, 0) != 0) {
		rlm_lua_error_old(NULL, L);
		ret = -1;
		goto done;
	}
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}

/** Check if a given function was loaded into an index in the global table
 *
 * Also check what was loaded there is a function and that it accepts the correct arguments.
 *
 * @param inst Current instance of rlm_lua
 * @param name of function to check.
 * @returns 0 on success (function is present and correct), or -1 on failure.
 */
static int lua_check_func(rlm_lua_t *inst, lua_State *L, char const *name)
{
	int top, ret;
	RLM_LUA_STACK_SET();

	if (name == NULL) return 0;

	lua_getglobal(L, name);
	top = lua_gettop(L);

	/*
	 *	Check the global is a function.
	 */
	if (!lua_isfunction(L, top)) {
		int type = lua_type(L, top);

		if (type == LUA_TNIL) {
			ERROR("rlm_lua (%s): Function \"%s\" not found ", inst->xlat_name, name);
		} else {
			ERROR("rlm_lua (%s): Value found at index \"%s\" is not a function (is a %s)",
			      inst->xlat_name, name, lua_typename(L, type));
		}

		ret = -1;
		goto done;
	}

	/*if (lua_check_arg(L, name) < 0) {
		ret = -1;
		goto done;
	}
	*/
	ret = 0;
done:
	RLM_LUA_STACK_RESET();
	return ret;
}



/** Initialise a new LuaJIT interpreter
 *
 * Creates a new lua_State and verifies all required functions have been loaded correctly.
 *
 * @param out Where to write a pointer to the new state.
 * @param instance Current instance of rlm_lua.
 * @return 0 on success else -1.
 */
int lua_init(lua_State **out, rlm_lua_t *instance)
{
	int top;
	rlm_lua_t *inst = instance;
	lua_State *L = luaL_newstate();
	if (!L) {
		ERROR("rlm_lua (%s): Failed initialising Lua state", inst->xlat_name);

		return -1;
	}

	luaL_openlibs(L);
	/*
	 *	Load the Lua file into our environment.
	 *
	 *	When we spawn new connections we copy the compiled functions
	 *	between this L the the slave Ls.
	 */
	if (luaL_loadfile(L, inst->module) != 0) {
		top = lua_gettop(L);

		ERROR("rlm_lua (%s): Failed loading file: %s", inst->xlat_name,
		      top ? lua_tostring(L, top) : "Unknown error");

		goto error;
	}

	if (lua_pcall(L, 0, LUA_MULTRET, 0) != 0) {
		top = lua_gettop(L);

		ERROR("rlm_lua (%s): Failed executing script: %s", inst->xlat_name,
		      top ? lua_tostring(L, top) : "Unknown error");
	}

	lua_pushcfunction(L, rlm_lua_debug);
	lua_setglobal(L, "fr_debug");
	lua_pushcfunction(L, rlm_lua_info);
	lua_setglobal(L, "fr_info");
	lua_pushcfunction(L, rlm_lua_warn);
	lua_setglobal(L, "fr_warn");
	lua_pushcfunction(L, rlm_lua_error);
	lua_setglobal(L, "fr_error");
	lua_pushcfunction(L, rlm_lua_cdefs);
	lua_setglobal(L, "fr_cdefs");
	lua_pushcfunction(L, get_attribute);
	lua_setglobal(L, "get_attribute");

	if (rlm_lua_isjit(L)) {
		INFO("True");
	} else {
		INFO("False");
	}

	/*
	 *	Verify all the functions were provided.
	 */
	if (lua_check_func(inst, L, inst->func_authorize)
	    || lua_check_func(inst, L, inst->func_authenticate)
#ifdef WITH_ACCOUNTING
	    || lua_check_func(inst, L, inst->func_preacct)
	    || lua_check_func(inst, L, inst->func_accounting)
#endif
	    || lua_check_func(inst, L, inst->func_checksimul)
#ifdef WITH_PROXY
	    || lua_check_func(inst, L, inst->func_pre_proxy)
	    || lua_check_func(inst, L, inst->func_post_proxy)
#endif
	    || lua_check_func(inst, L, inst->func_post_auth)
#ifdef WITH_COA
	    || lua_check_func(inst, L, inst->func_recv_coa)
	    || lua_check_func(inst, L, inst->func_send_coa)
#endif
	    || lua_check_func(inst, L, inst->func_detach)
	    || lua_check_func(inst, L, inst->func_xlat)) {
	 	goto error;
	}



	*out = L;
	return 0;

	error:
	*out = NULL;

	lua_close(L);
	return -1;
}


static int c_to_lua(lua_State *L, VALUE_PAIR const *vp)
{
	char	buf[1024];

	if (!vp) return -1;

	switch (vp->da->type) {

		case PW_TYPE_ABINARY:
		case PW_TYPE_DATE:
		case PW_TYPE_ETHERNET:
		case PW_TYPE_IPADDR:
		case PW_TYPE_IPV6ADDR:
		case PW_TYPE_IPV4PREFIX:
		case PW_TYPE_IPV6PREFIX:
		case PW_TYPE_IFID:
		case PW_TYPE_OCTETS:
		case PW_TYPE_TLV:
		case PW_TYPE_STRING:
			vp_prints_value(buf, sizeof(buf), vp, '\0');
			lua_pushstring(L, buf);
			break;

		case PW_TYPE_BYTE:
		case PW_TYPE_SHORT:
		case PW_TYPE_INTEGER:
		case PW_TYPE_SIGNED:
			lua_pushinteger(L, vp->vp_integer);
			break;

		case PW_TYPE_INTEGER64:
			if (sizeof(uint64_t) > sizeof(LUA_NUMBER)) {
				vp_prints_value(buf, sizeof(buf), vp, '\0');
				lua_pushstring(L, buf);
			} else {
				lua_pushinteger(L, vp->vp_integer64);
			}
			break;

		default:
			ERROR("Unknown type, %i", vp->da->type);
			return -1;
	}
	return 0;
}

static int do_lua_value(rlm_lua_t *inst, vp_cursor_t *cursor)
{
	int idx = 1;
	VALUE_PAIR *vp;
	lua_State *L = inst->interpreter;
	vp = fr_cursor_current(cursor);
	DICT_ATTR const *da;
	da = vp->da;

	lua_newtable(L);
	do {
		lua_pushnumber(L, idx);
		if (c_to_lua(L, vp) < 0) {
			return -1;
		}
			lua_settable(L, -3);
		idx++;

	} while ((vp = fr_cursor_next(cursor)) && da == vp->da);

	lua_setfield(L, -2, da->name);

	return 0;
}

static int do_lua_tag(rlm_lua_t *inst, vp_cursor_t *cursor)
{
	int start;
	char tag[7];
	VALUE_PAIR *vp;
	lua_State *L = inst->interpreter;

	vp = fr_cursor_current(cursor);
	start = vp->tag;

	lua_newtable(L);
	do {
		do_lua_value(inst, cursor);
	} while ((vp = fr_cursor_current(cursor)) && (start == vp->tag) && vp->da->flags.has_tag);

	snprintf(tag, sizeof(tag), "tag %i", start);
	lua_setfield(L, -2, tag);

	return 0;
}


static int lua_get_attribute(lua_State *L)
{
	vp_cursor_t cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp = NULL;
	int index;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		REDEBUG("DICT_ATTR not available in upvalues, can't determine target attribute");
		return -1;
	}

	da = lua_touserdata(L, lua_upvalueindex(1));
	if (!da) {
		REDEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}

	/* Packet list should be light user data too at some point... */
	fr_cursor_init(&cursor, &request->packet->vps);

	for (index = (int) lua_tointeger(L, -1); index >= 0; index--) {
		vp = fr_cursor_next_by_da(&cursor, da, TAG_ANY);
		if (!vp) {
			return 0;
		}
	}

	if (c_to_lua(L, vp) < 0) {
		return -1;
	}

	return 1;
}

static int lua_set_attribute(lua_State *L)
{
	vp_cursor_t cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp = NULL, *new;
	int index;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);
	
	if (!lua_islightuserdata(L, lua_upvalueindex(1))) {
		REDEBUG("DICT_ATTR not available in upvalues, can't determine target attribute");
		return -1;
	}
	
	da = lua_touserdata(L, lua_upvalueindex(1));
	if (!da) {
		REDEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}

	if ((new = lua_to_c(request, L, da)) == NULL) {
		return 0;
	}
	
	/* Packet list should be light user data too at some point... */
	fr_cursor_init(&cursor, &request->packet->vps);

	for (index = (int) lua_tointeger(L, -2); index >= 0; index--) {
		INFO("%i, ", index);
		vp = fr_cursor_next_by_da(&cursor, da, TAG_ANY);
		if (!vp) {
			INFO("%i adding new attribute");
			fr_cursor_insert(&cursor, new);
			return 0;
		}
	}
	
	fr_cursor_replace(&cursor, new);
	
	return 0;
}

static int lua_next_attr(lua_State *L)
{
	vp_cursor_t *cursor;
	DICT_ATTR const *da;
	VALUE_PAIR *vp;
	
	if (!(lua_isuserdata(L, lua_upvalueindex(1)))) {
		return -1;
	}
	
	cursor = lua_touserdata(L, lua_upvalueindex(1));
	if (!cursor) {
		DEBUG("Failed retrieving vp_cursor_t from upvalues");
		return -1;
	}

	if (!(lua_isuserdata(L, lua_upvalueindex(2)))) {
		return -1;
	}
	
	da = lua_touserdata(L, lua_upvalueindex(2));
	if (!da) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}
	
	/* Packet list should be light user data too at some point... */
	if((vp = fr_cursor_next_by_da(cursor, da, TAG_ANY)) == NULL) {
		lua_pushnil(L);
		return 1;
	}
	
	
	if (c_to_lua(L, vp) < 0) {
		return -1;
	}

	return 1;
}

static int next_constructor(lua_State *L)
{
	DICT_ATTR const *da;
	VALUE_PAIR *vp;

	da = lua_touserdata(L, lua_upvalueindex(2));
	if (!da) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}
	vp = lua_touserdata(L, lua_upvalueindex(1));
	if (!vp) {
		DEBUG("Failed retrieving DICT_ATTR from upvalues");
		return -1;
	}
	vp_cursor_t* new = (vp_cursor_t*) lua_newuserdata(L, sizeof(vp_cursor_t));
	fr_cursor_init(new, &vp);
	lua_pushlightuserdata(L, da);
	lua_pushcclosure(L, lua_next_attr, 2);
	
	return 1;
}

static int lua_new_attribute_table(lua_State *L)
{
	char const *attr;
	DICT_ATTR const *da;
	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	attr = lua_tostring(L, -1);
	if (!attr) {
		REDEBUG("Invalid attribute \"%s\"", attr);
		return -1;
	}

	da = dict_attrbyname(attr);
	if (!da) {
		REDEBUG("Invalid attribute \"%s\"", attr);
		return -1;
	}

	lua_newtable(L);	/* Attribute value table */
	lua_pushlightuserdata(L, request->packet->vps);
	lua_pushlightuserdata(L, da);
	lua_pushcclosure(L, next_constructor, 2);
	lua_setfield(L, -2, "next_iter");
	lua_newtable(L);	/* Attribute value meta-table */
	lua_pushlightuserdata(L, da);
	lua_pushcclosure(L, lua_get_attribute, 1);
	lua_setfield(L, -2, "__index");
	lua_pushlightuserdata(L, da);
	lua_pushcclosure(L, lua_set_attribute, 1);
	lua_setfield(L, -2, "__newindex");

	lua_setmetatable(L, -2);
	lua_settable(L, -3);
	lua_getfield(L, -1, attr);
	
	return 1;
}

int do_lua(rlm_lua_t *inst, REQUEST *request, char const *funcname)
{
	vp_cursor_t cursor;
	lua_State *L = inst->interpreter;

	fr_thread_local_set(rlm_lua_request, request);

	RLM_LUA_STACK_SET();

	pairsort(&request->packet->vps, true);
	fr_cursor_init(&cursor, &request->packet->vps);


	/*
	 *	Setup the environment
	 */
	lua_newtable(L);	/* Attribute list table */
	lua_newtable(L);	/* Attribute list meta-table */
	lua_pushinteger(L, PAIR_LIST_REQUEST);
	lua_pushcclosure(L, lua_new_attribute_table, 1);
	lua_setfield(L, -2, "__index");

//	lua_pushcfunction(L, new_index);
//	lua_setfield(L, -2, "__newindex");


	lua_setmetatable(L, -2);
	lua_setglobal(L, "request");

	/*
	 *	Get the function were going to be calling
	 */
	lua_getglobal(L, funcname);
	lua_pcall(L, 0, 0, 0);
	RLM_LUA_STACK_RESET();

	return 0;
}

static int get_attribute(lua_State *L)
{
	vp_cursor_t cursor;
	char const *attr;

	REQUEST *request = fr_thread_local_get(rlm_lua_request);

	fr_cursor_init(&cursor, &request->packet->vps);
	int idx = 1, idn, tag;
	VALUE_PAIR *vp;
	vp = fr_cursor_current(&cursor);
	DICT_ATTR const *da;

	idn = lua_gettop(L);
	INFO("%i", idn);

	if (idn > 2) {
		attr = lua_tostring(L, idn -1);
		tag = lua_tointeger(L, idn);
	} else {
		attr = lua_tostring(L, idn);
		tag = TAG_ANY;
	}

	da = dict_attrbyname(attr);
	if (da == NULL) {
		REDEBUG("attr %s not found", attr);
		return -1;
	}
	if (!da->flags.has_tag) {
		tag = TAG_ANY;
	}

	lua_newtable(L);

	while ((vp = fr_cursor_next_by_da(&cursor, da, tag))) {

		lua_pushnumber(L, idx);
		if (c_to_lua(L, vp) < 0) {
			return -1;
		}
		lua_settable(L, -3);
		INFO("%s", attr);
		idx++;
	}

	return 1;

}


static VALUE_PAIR* lua_to_c (REQUEST *request, lua_State *L, DICT_ATTR const *da)

{
	int idx = lua_gettop(L);
	char *p;
	VALUE_PAIR *vp;
	vp = pairalloc(request, da);


	if (lua_isnumber(L, idx) == 1) {

		switch (vp->da->type) {
			case PW_TYPE_STRING:
				p = talloc_asprintf(vp, "%f", lua_tonumber(L, idx));
				pairstrsteal(vp, p);
				break;
			case PW_TYPE_INTEGER:
				vp->vp_integer = (uint32_t) lua_tointeger(L, idx);
				vp->length = 4;
				break;
			case PW_TYPE_IPADDR:
			case PW_TYPE_COMBO_IP:
				vp->vp_ipaddr = (uint32_t) lua_tointeger(L, idx);
				vp->length = 4;
				break;
			case PW_TYPE_DATE:
				vp->vp_date = (uint32_t) lua_tointeger(L, idx);
				vp->length = 4;
				break;
			case PW_TYPE_OCTETS:
			{
				lua_Number number = lua_tonumber(L, idx);
				pairmemcpy(vp, (uint8_t*) &number, sizeof(number));
			}
				break;
			case PW_TYPE_BYTE:
				vp->vp_byte = (uint8_t) lua_tointeger(L, idx);
				vp->length = 1;
				break;
			case PW_TYPE_SHORT:
				vp->vp_short = (uint16_t) lua_tointeger(L, idx);
				vp->length = 2;
				break;
			case PW_TYPE_SIGNED:
				vp->vp_signed = (int32_t) lua_tointeger(L, idx);
				vp->length = 4;
				break;
			case PW_TYPE_INTEGER64:
				vp->vp_integer64 = (uint64_t) lua_tointeger(L, idx);
				vp->length = 8;
				break;
			default:
				ERROR("Unknown type");
				return NULL;
		}

	} else if (lua_isstring(L, idx) == 1) {

		pairparsevalue(vp, lua_tostring(L, idx));
	}

	return vp;
}

