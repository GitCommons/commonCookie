# Common-Cookie

A simple cookie scraper written in node.js

> **NOTE:** 
> at the moment this only works for chrome on Mac.
> However, I've listed resources to handle other OS's and browsers.
> It should be pretty easy should one have the time.

<br/>

## Install

```sh
  npm i git+https://github.com/GitCommons/commonCookie.git
```

<br/>

## Usage

```js
  const { CookieStore } = require('common-cookie')

  let store = new CookieStore()
  let query = `SELECT name, encrypted_value, host_key FROM cookies WHERE host_key LIKE '.google.com' OR host_key LIKE 'console.cloud.google.com'`
  let cookies = store.get(query)

  let desiredKeys =  ['SID', 'HSID', 'SSID', 'OSID', 'SAPISID', 'APISID']
  let cookieObj = cookies
    .filter(c=>desiredKeys.includes(c.name))
    .reduce((a,c)=>({...a, [c.name]:c.value}), {})

  console.log(cookieObj)
```