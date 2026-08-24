/*
 * The single outbound HTTPS request this library can make: the best-effort
 * AMD AIA EK-certificate fetch. Nothing here talks to Root Herald.
 */

#pragma once

#include <string>

namespace RootHerald {

struct HttpResponse {
    int statusCode = 0;   /* 0 when the request never reached a server */
    std::string body;
};

HttpResponse HttpGet(const std::string& url);

} // namespace RootHerald
