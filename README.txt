**************************************************************************
Steps to execute the program
**************************************************************************

1. Extract the zip folder
2. Copy the contents to any folder on your system.
3. Open cmd prompt/terminal on your system. Traverse to the location on the system where you copied the files.
4. Run the command - "python password_man.py"
5. Enter the master password and the one time token using Google Authenticator Application
   eg. OnionRing,123456
6. Enter the choice:
    a. Read Password - Enter a username you already saved in the DB
    b. Write & Save password - Enter a username and
    select the option to enter your own password or generate random password by application (Minimum 9 characters)
    c. Show DB - To view the encrypted contents of the DB.
    d. Exit


Please follow the below link to set up Google Authenticator:
https://support.google.com/accounts/answer/1066447?hl=en
Set up using Secret Key: 'masterofpuppetss' and Time based

Download Link:
Android : https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en
IOS: https://itunes.apple.com/us/app/google-authenticator/id388497605?mt=8

Python Dependencies:
Install the following Python Libraries:
- pyCrypto
- sqlalchemy
- hashlib
- passwordmeter
- pyotp

**************************************************************************
