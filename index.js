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
const { execSync } = require('child_process')


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
    db.all(query, (err, rows) => {
      if (err) {
        console.error(err)
        reject(err)
      }

      // get key
      if (!macKey) {
        let tmp = execSync('security find-generic-password -wa "Chrome"').toString()
        if (tmp) {
          macKey = tmp.trimEnd('\n')
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
})//()



/////////////////



const fs = require("fs")
const {homedir} = require("os")
const {join} = require("path")

function getActiveProfile() {
  //you can get the current profile from 'Local State', a json file located in '/Users/{username}/Library/Application Support/Google/Chrome/'
  const localStatePath = join(homedir(), `/Library/Application Support/Google/Chrome/Local State`)
  const jsonString = fs.readFileSync(localStatePath)
  const localState = JSON.parse(jsonString)

  let profile = localState?.profile?.last_used || 'Default'
  return profile
}


function handleProfile(p) {
  let isValid = p instanceof String && /(Profile \d+|Default)/.test(p)

  // catch bad/null input
  if (p === null || isValid === false) return getActiveProfile()
  
  return p // good input
}


let globalKey = null
function initKey() {
  if (!macKey) {
    let tmp = execSync('security find-generic-password -wa "Chrome"').toString()
    if (tmp) {
      macKey = tmp.trimEnd('\n')
    } else {
      macKey = 'mock_password'
    }
  }
  let globalKey = crypto.pbkdf2Sync(macKey, 'saltysalt', 1003, 16, 'sha1')
  return globalKey
}

/* function handleKey(k) {
  // if nothing set, init global
  if (k === null && globalKey === null) return initKey()

  // no param given, default to global
  if (k === null && Buffer.isBuffer(globalKey)) return globalKey

  // If buffer i'm assuming its correct
  if (Buffer.isBuffer(k)) return k

  // Error
  throw new Error(`Failed to resolve key given:\n• key: ${typeof k}\n• globalKey: ${typeof globalKey}`)
} */

function handleKey(k) {
  if (k === null) {
    // if nothing set, init global
    if (globalKey === null) return initKey()

    // no param given, default to global
    if (Buffer.isBuffer(globalKey)) return globalKey

    // Error: globalKey 
    throw new Error(`Failed to resolve globalKey given null argument`)
  }

  // If buffer i'm assuming its correct
  if (Buffer.isBuffer(k)) return k

  // Error: k (aka key)
  throw new Error(`Failed to validate key argument for key of type ${typeof k}`)
}

function initDB(profile) {
  let cookieDBPath = join(homedir(), `/Library/Application Support/Google/Chrome/${profile}/Cookies`)
  let db = new sqlite3.Database(cookieDBPath);
  return db
}

class cookieStore {
  constructor(profile=null, key=null) {
    this.profile = handleProfile(profile)
    this.key = handleKey(key)
    this.db = initDB(this.profile)
  }

  async get(query) {
    return new Promise((resolve , reject) => {
      this.db.all(query, (err, rows) => {
        if (err) {
          console.error(err)
          reject(err)
        }

        // Iterate over the query results and decrypt each cookie value
        let decryptedCookieArr = rows.map( r =>({...r, value: decrypt(r.encrypted_value, this.key) }) )

        resolve( decryptedCookieArr )
      })
    })
  }
}

!(async ()=>{
  let store = new cookieStore()
  let query = `SELECT name, encrypted_value, host_key FROM cookies WHERE host_key LIKE ".google.com" OR  host_key LIKE "console.cloud.google.com"`
  let cookies = await store.get(query)

  let desiredKeys =  ['SID', 'HSID', 'SSID', 'OSID', 'SAPISID', 'APISID']
  cookieObj = cookies
    .filter(c=>desiredKeys.includes(c.name))
    .reduce((a,c)=>({...a, [c.name]:c.value}), {})

  console.log(cookieObj)
})()
