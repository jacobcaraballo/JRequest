# JRequest

JRequest is a very simple http request library.

---

Usage:

```
JRequest<MyCodableResponseClass>().get(
	endpoint,
	queries: ["param1": param1value, "param2": param2value],
	headers: ["x-api-key": apiKey, "Content-Type", contentType],
	auth: JRequestAuth(key: accessKey, secret: secretKey))
{ (response, error) in
	if let error = error { return handleError(error) }
	doSomething(with: response)
}
```
