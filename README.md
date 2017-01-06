# Disclamer
I created this tool to decrypt my own chat logs beause I’m too lazy
to copy and paste them one by one from Kakaotalk. If you want to
decrypt messages that were not intended to you, think about how
you’d feel if someone would do that to you. You don’t want anybody
to read your private conversations with your boyfriend, girlfriend,
close friends, family… so **don’t do it**.

It is your responsability to respect people’s privacy.

# kakaodecrypt.py
Decrypt chat history from the local database of Kakaotalk’s Android app.

## Usage
Print decrypted chat history:
```shell
$ ./kakaodecrypt.py -p KakaoTalk.db
...
```
Decrypt the `chat_logs` table into a new `chat_logs_dec` table:
```shell
$ ./kakaodecrypt.py KakaoTalk.db # This creates a new chat_logs_dec table
$ sqlite3 KakaoTalk.db "select user_id, message, attachment \
  from chat_logs_dec where chat_id = 123456789 order by created_at"
...
```
