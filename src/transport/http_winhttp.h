/**
 * HTTP transport using WinHTTP.
 */

#ifndef ROOTHERALD_HTTP_WINHTTP_H
#define ROOTHERALD_HTTP_WINHTTP_H

#include <string>

namespace RootHerald {

struct HttpResponse {
    int statusCode = 0;
    std::string body;
};

HttpResponse HttpGet(const std::string& url);

} // namespace RootHerald

#endif /* ROOTHERALD_HTTP_WINHTTP_H */
