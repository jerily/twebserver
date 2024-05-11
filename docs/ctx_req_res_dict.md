#### Context Dictionary

The context ```ctx``` dictionary includes the following:
- **server** - the server handle
- **conn** - the connection handle
- **addr** - the address in IPv6 format
- **port** - the port number
- **isSecureProto** - whether the protocol is secure (https)

#### Request Dictionary

The request ```req``` dictionary includes the following:
- **httpMethod** - GET, POST, PUT, DELETE, etc
- **url** - the url
- **version** - HTTP/1.1
- **path** - the path
- **queryString** - the query string
- **queryStringParameters** - a dictionary of query string parameters
- **multiValueQueryStringParameters** - a dictionary of query string parameters (with multiple values)
- **headers** - a dictionary of headers
- **multiValueHeaders** - a dictionary of headers (with multiple values)
- **isBase64Encoded** - whether the body is base64 encoded
- **body** - the body

#### Response Dictionary

The response ```res``` dictionary should include the following:
- **statusCode** - the status code
- **headers** - a dictionary of headers
- **multiValueHeaders** - a dictionary of headers (with multiple values)
- **isBase64Encoded** - whether the body is base64 encoded
- **body** - the body
