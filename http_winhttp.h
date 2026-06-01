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

HttpResponse HttpPost(const std::string& url, const std::string& jsonBody);
HttpResponse HttpPostForm(const std::string& url, const std::string& formBody);
HttpResponse HttpGet(const std::string& url);

} // namespace RootHerald

#endif /* ROOTHERALD_HTTP_WINHTTP_H */
