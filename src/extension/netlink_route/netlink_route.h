#ifndef NETLINK_ROUTE_H
#define NETLINK_ROUTE_H

#include "extension/extension.h"

int netlink_route_callback(Extension *extension, ExtensionEvent event, intptr_t data1, intptr_t data2);

#endif /* NETLINK_ROUTE_H */
