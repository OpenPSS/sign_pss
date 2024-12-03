# sign_pss


Tool to sign PlayStation Mobile applications to run under the retail PlayStation Mobile Runtime Package (PCSI00011) & PlayStation Mobile Runtime Package for Unity (PCSI00010)

this can *technically* even be used to run PSM homebrew on offical firmware 3.74. 
however doing so would require (any) valid PSM license, (you would just sign an app with the same keys & contentid as an offical app)
the issue is of course that you can no longer purchase PSM content from the PS Store, making obtaining a license difficult.
can be used easily under NoPsmDrm however.

This is possible for 2 reasons:
- Sony included the retail Private Key within psm_encryptor32.dll in the PSM SDK.
- The vita version of PSM, never checkde signatures to begin with (only HMAC SHA256) signatures are only checked on the android version.


This also works for the Android version of PlayStation Mobile.


```
usage: sign_pss <game_folder> <output_folder> <content_id> [game_key] [vita_hmac_key] [android_hmac_key]

game_folder - the folder containing the plaintext PSM game files (/Application, /System, etc)
content_id - the content id to use for PSSE signature, eg; UM0000-NPNA99999_00-0000000000000000
game_key - game specific key used to encrypt the data, found in RIF
vita_hmac_key - HMAC key used for verifying psm file integrity on VITA, found in vita psm RIF
android_hmac_key - HMAC key used for verifying psm file integrity on ANDROID, found in android psm RIF

```

The application targets Windows XP, so it should work even really far back

TODO: 
- Create a linux & macos port?

Maybe someday: 
- GUI frontend ??
- encrypt & sign only one single file instead of entire gamee? (would be useful for modding games)
- Read contentid/gamekey/hmackey from existing NoPsmDrm RIF?

Building: 
- depends on openssl1_0_1a, its static linked in the release binaries
- this repository also contains a fairly complete de-compilation of psm_encryptor32.dll,
changes i made to it are #ifdef with _PSM_SIGNER_BUILD 