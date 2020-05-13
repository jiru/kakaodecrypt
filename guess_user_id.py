#!/usr/bin/python3

import sys
import argparse
import sqlite3
import json
from collections import Counter

class KakaoDbGuessUserId:
  @staticmethod
  def run(db_file):
    con = sqlite3.connect(db_file)
    cur = con.cursor()
    cur.execute('SELECT id, members FROM chat_rooms')
    chat_members = { row[0]: [] if row[1] is None else json.loads(row[1]) for row in cur.fetchall()}

    found = []
    for chat_id in chat_members:
      if len(chat_members[chat_id]) > 0:
        exclude = ','.join(list(map(str, chat_members[chat_id])))
        cur.execute('SELECT DISTINCT user_id FROM chat_logs WHERE chat_id = %d AND user_id NOT IN (%s)' % (chat_id, exclude))
        for row in cur.fetchall():
          found.append(row[0])

    total = len(found)
    if total > 0:
      print('Possible value(s) for user_id:')
      found = Counter(found)
      for user_id in found:
        prob = found[user_id]*100/total
        print('  %20d (prob %5.2f%%)' % (user_id, prob))
    else:
      print('Unable to find user_id.')

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description="Guess the account's user_id value by analysing chat logs and chatrooms membership.")
  parser.add_argument('db_file', metavar='KakaoTalk.db')
  args = parser.parse_args()

  KakaoDbGuessUserId.run(args.db_file)
