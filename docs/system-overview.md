# System Overview

The user is presented with the login page and given two option to log in.
They can use an existing Apple or Google account. If they have neither, then
currently there are no other options at this time.

When a user logs in with Google, their profile info (name and email) are
requested. In addition, Google sends back a unique ID for them. This
information is saved into a JSON document:

Example Google Login Info:
```json
{
  "refresh_token": null,
  "devices": {
    "<browser-hash>": {
      "session_id": "<session-hash>"
    }
  },
  "google_id": "xxxxxxxx"
}
```

Example Account Info:
```json
{
  "add_id": null,
  "apple_id": null,
  "email": "bearofaction@action.com",
  "fist_name": "Crowbar",
  "last_name": "Jones",
  "google_id": "xxxxxxxx"
}
```

and store is a S3 bucketof these OIDC providers there is an account made
for them.

**First Login with Google Process:**

1. User clicks the login button.
2. User is sent to the OIDC provider consent page.
3. If the user consents, they are directed back to the app through the callback
   URL.
4. Generate a new login object and store it under:
   `s3://<bucket-name>/login/<google-user-id>.json`
5. Generate a new account ID and store info under:
   `s3://<bucket-name>/account/<account-id>.json`
6. Store the <account-id> and <google-user-id> in the active session.
7. Download the apps GPG key and encrypt the account ID and store it in a
   secure HTTP cookie.

**Return Login with Google Process:**

user enter the site, but their previous session has times out.

1. User clicks the login button.
2. On the sign-in page, look for a secure HTTP cookie:
   1. If found,
      1. and contains the encrypted <account-id>,
      2. and you can verify the session was not hijacked,
         1. then refresh the login.
   2. If not,
   3. Send the user  to the OIDC provider consent page, once again.
   4. If the user consents, they are directed back to the app through the
      callback URL.
   5. Now that we have the <google-user-id> we can pull the <account-id> and
      then grab the account info from:
      `s3://<bucket-name>/account/<account-id>.json`.
   6. Update login info, making sure not to delete the refresh token:
      `s3://<bucket-name>/login/<google-user-id>.json`
   7. Store the <account-id> and <google-user-id> in the active session.
   8. Download the apps GPG key and encrypt the account ID and store it in a
      secure HTTP cookie.
