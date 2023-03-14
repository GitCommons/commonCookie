/*
Currently only built for chrome on mac, but below i've listed 
some references on how to expand it to other browsers and OS's 

General:
  • python, decrypt across multiple browsers: https://github.com/borisbabic/browser_cookie3/blob/master/__init__.py
  • JS, chrome all OS's: https://github.com/bertrandom/chrome-cookies-secure/blob/master/index.js
  • JS, chrome (generic, doesn't deal with finding OS specific keys): https://github.com/ebourmalo/cookie-encrypter/blob/master/index.js

Mac:
  • https://stackoverflow.com/questions/57646301/decrypt-chrome-cookies-from-sqlite-db-on-mac-os

Windows:
  • python, chrome & firefox: https://gist.github.com/GitHub30/427b0474008234d449acefb216a4a833
  • python, chrome: https://gist.github.com/GramThanos/ff2c42bb961b68e7cc197d6685e06f10
  • python, chrome: https://stackoverflow.com/questions/60416350/chrome-80-how-to-decode-cookies
  NOTE: windows chrome gets its key from the "Local State" file under the keys ['os_crypt']['encrypted_key']

Linux:
  //const linuxPassword = 'peanuts' // Linux password for all users
  //var derivedKey = crypto.pbkdf2Sync(linuxPassword, 'saltysalt', 1, 16, 'sha1');
*/

const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const exec = promisify(require('child_process').exec)


let db = null
let macKey = null


function decrypt(encryptedData, key) {
  const iv = Buffer.alloc(16, ' ', 'binary')
  let decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);

  // Remove the first 3 bytes (v10) from the encrypted data 
  encryptedData = Buffer.from(encryptedData, 'hex').slice(3);

  // Add PKCS#7 padding to the encrypted data
  const paddingLength = 16 - (encryptedData.length % 16);
  const padding = Buffer.alloc(paddingLength, paddingLength);
  const paddedData = Buffer.concat([encryptedData, padding]);

  // Decrypt the padded data
  let decryptedValue = decipher.update(paddedData);

  // Strip padding junk and return string
  // (PKCS#7 adds \x??, where ?? is the number of bytes added. 2 bytes would be\x02\x02)
  return decryptedValue.slice(0, decryptedValue.length - decryptedValue[decryptedValue.length - 1] ).toString('utf8')
}


async function getCookies(query) {
  return new Promise((resolve , reject) => {
    db.all(query, async (err, rows) => {
      if (err) {
        console.error(err)
        reject(err)
      }

      // get key
      if (!macKey) {
        let tmp = await exec('security find-generic-password -wa "Chrome"')
        if (tmp.stdout) {
          macKey = tmp.stdout.trimEnd('\n')
        } else {
          macKey = 'mock_password'
        }
      }
      let derivedKey = crypto.pbkdf2Sync(macKey, 'saltysalt', 1003, 16, 'sha1')

      // Iterate over the query results and decrypt each cookie value
      let decryptedCookieArr = rows.map( r =>({...r, value: decrypt(r.encrypted_value, derivedKey) }) )

      resolve( decryptedCookieArr )
    })
  })
}


!(()=>{
  // Init cookie DB
  const fs = require("fs");
  const {homedir} = require("os");
  const {join} = require("path")

  //you can get the current profile from 'Local State', a json file located in '/Users/{username}/Library/Application Support/Google/Chrome/'
  const localStatePath = join(homedir(), `/Library/Application Support/Google/Chrome/Local State`)
  const jsonString = fs.readFileSync(localStatePath)
  const localState = JSON.parse(jsonString)

  let profile = localState?.profile?.last_used || 'Default'
  let cookieDBPath = join(homedir(), `/Library/Application Support/Google/Chrome/${profile}/Cookies`)

  db = new sqlite3.Database(cookieDBPath);
})()


!(async ()=>{
  // Execute a SQL query to extract the encrypted cookie values
  let query = `SELECT name, encrypted_value, host_key FROM cookies WHERE host_key LIKE ".google.com" OR  host_key LIKE "console.cloud.google.com"`
  let cookiesArr = await getCookies(query)

  let desiredKeys =  ['SID', 'HSID', 'SSID', 'OSID', 'SAPISID', 'APISID']

  cookiesObj = cookiesArr
    .filter(c=>desiredKeys.includes(c.name))
    .reduce((a,c)=>({...a, [c.name]:c.value}), {})

  console.log(cookiesObj)
})()
