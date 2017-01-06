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
