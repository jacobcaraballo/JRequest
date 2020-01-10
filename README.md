# JRequest

JRequest is a very simple http request library.

---

Basic Usage:
```swift
JRequest<MyCodableResponseClass>().get(endpoint) { (response, error) in
	if let error = error { return handleError(error) }
	doSomething(with: response)
}
```
```swift
JRequest<MyCodableResponseClass>().post(endpoint, body: jsonBody) 
{ (response, error) in
	if let error = error { return handleError(error) }
	doSomething(with: response)
}
```

---

Extended Usage:

```swift
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
