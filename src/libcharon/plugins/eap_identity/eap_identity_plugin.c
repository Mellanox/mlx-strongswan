/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "eap_identity_plugin.h"
#include "eap_identity.h"

#include <daemon.h>

METHOD(plugin_t, get_name, char*,
	eap_identity_plugin_t *this)
{
	return "eap-identity";
}

METHOD(plugin_t, get_features, int,
	eap_identity_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(eap_method_register, eap_identity_create_server),
			PLUGIN_PROVIDE(EAP_SERVER, EAP_IDENTITY),
		PLUGIN_CALLBACK(eap_method_register, eap_identity_create_peer),
			PLUGIN_PROVIDE(EAP_PEER, EAP_IDENTITY),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	eap_identity_plugin_t *this)
{
	free(this);
}

/*
 * see header file
 */
plugin_t *eap_identity_plugin_create()
{
	eap_identity_plugin_t *this;

	INIT(this,
		.plugin = {
			.get_name = _get_name,
			.get_features = _get_features,
			.destroy = _destroy,
		},
	);

	return &this->plugin;
}

